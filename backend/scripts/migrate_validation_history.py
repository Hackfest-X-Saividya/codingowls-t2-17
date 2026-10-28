"""Copy validation history from the earlier SQLite store into MongoDB, then verify it.

Earlier versions kept investigations and attempts in the scan database
(DB_PATH, default backend/data/scans.db). This copies them into MONGODB_URI /
MONGODB_DATABASE, keeping IDs, attempt numbers, parent links, code hashes,
statuses and timestamps. The best code of each investigation is taken from the
validation runs stored in the scan states, so resumed runs continue from it.

  - SQLite is opened read-only and never changed or deleted.
  - Documents that already exist in MongoDB are left alone (re-running is safe);
    a conflicting document is reported, not overwritten.
  - Every SQLite record is then read back from MongoDB and compared field by field.
    Exit code 0 only when every record matches.

    cd backend
    python scripts/migrate_validation_history.py --dry-run
    python scripts/migrate_validation_history.py [--sqlite path/to/scans.db]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import validation_history  # noqa: E402
from utils.config import settings  # noqa: E402

ATTEMPT_FIELDS = ("investigation_id", "validation_id", "attempt_number", "parent_attempt_id", "code_hash", "finding_id",
                  "chain_id", "rule_id", "vuln_class", "fix_origin", "strategy", "status", "outcome", "failure_reason",
                  "created_at", "finished_at")
INVESTIGATION_FIELDS = ("scan_id", "target_key", "finding_id", "chain_id", "rule_id", "vuln_class", "repo_url", "file",
                        "status", "max_attempts", "created_at", "updated_at")


def read_sqlite(path: Path) -> tuple[list[dict], list[dict], dict[str, dict]]:
    """(investigations, attempts, best code per investigation) from the SQLite file, opened read-only."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not {"investigations", "validation_attempts"} <= tables:
        return [], [], {}
    investigations = [dict(r) for r in db.execute("SELECT * FROM investigations ORDER BY created_at")]
    attempts = [dict(r) for r in db.execute(
        "SELECT * FROM validation_attempts ORDER BY investigation_id, attempt_number")]
    best: dict[str, dict] = {}
    if "scans" in tables:
        for (state_json,) in db.execute("SELECT state_json FROM scans"):
            for run in (json.loads(state_json).get("validations") or {}).values():
                inv = run.get("investigation_id")
                if inv and run.get("final_fix") and run.get("best_attempt"):
                    if inv not in best or run.get("started_at", "") > best[inv]["started_at"]:
                        best[inv] = {"started_at": run.get("started_at", ""), "fix": run["final_fix"],
                                     "attempt": run["best_attempt"]}
    db.close()
    return investigations, attempts, best


def to_documents(investigations: list[dict], attempts: list[dict], best: dict[str, dict]) -> tuple[list, list]:
    inv_docs = []
    for r in investigations:
        doc = {"_id": r["investigation_id"], **{k: r.get(k) for k in INVESTIGATION_FIELDS},
               "active_validation_id": None,  # no run of the old process is still alive
               "best_fix": best.get(r["investigation_id"], {}).get("fix"),
               "best_attempt": best.get(r["investigation_id"], {}).get("attempt")}
        if r["status"] != "closed":
            doc["current_key"] = f"{r['scan_id']}|{r['target_key']}"
        inv_docs.append(doc)
    by_inv = {r["investigation_id"]: r for r in investigations}
    attempt_docs = []
    for r in attempts:
        result = json.loads(r["result_json"]) if r.get("result_json") else None
        inv = by_inv.get(r["investigation_id"], {})
        status = r["status"]
        attempt_docs.append({
            "_id": r["attempt_id"], **{k: r.get(k) for k in ATTEMPT_FIELDS},
            # A RUNNING row was interrupted when the old process stopped
            "status": "ERROR" if status == "RUNNING" else status,
            "failure_reason": (r.get("failure_reason") or "Interrupted: the backend stopped while this attempt was "
                               "running (migrated from SQLite).") if status == "RUNNING" else r.get("failure_reason"),
            "repo_url": inv.get("repo_url"), "file": inv.get("file"),
            "phase": "validating" if r.get("code_hash") else "generating",
            "patch": json.loads(r["patch_json"]) if r.get("patch_json") else [], "diff": r.get("diff") or "",
            "evaluated": bool(result) and not any(c.get("name") == "apply_patch" for c in result.get("checks", [])),
            "result": result, "updated_at": r.get("finished_at") or r["created_at"],
        })
    return inv_docs, attempt_docs


def insert(collection, docs: list[dict]) -> tuple[int, int, list[str]]:
    """Insert documents that are not in MongoDB yet. Returns (inserted, already present, conflicts)."""
    from pymongo.errors import DuplicateKeyError

    inserted = present = 0
    conflicts = []
    for doc in docs:
        try:
            res = collection.update_one({"_id": doc["_id"]}, {"$setOnInsert": doc}, upsert=True)
        except DuplicateKeyError as e:  # same attempt number or current investigation under another id
            conflicts.append(f"{doc['_id']}: {e.details.get('errmsg', e) if e.details else e}")
            continue
        if res.upserted_id is not None:
            inserted += 1
        else:
            present += 1
    return inserted, present, conflicts


def verify(db, inv_docs: list[dict], attempt_docs: list[dict]) -> list[str]:
    """Every migrated record, read back and compared."""
    problems = []
    for coll, docs, fields in ((db.investigations, inv_docs, INVESTIGATION_FIELDS + ("best_attempt",)),
                               (db.validation_attempts, attempt_docs, ATTEMPT_FIELDS + ("evaluated",))):
        for doc in docs:
            stored = coll.find_one({"_id": doc["_id"]})
            if stored is None:
                problems.append(f"{coll.name} {doc['_id']} is missing")
                continue
            for f in fields:
                if stored.get(f) != doc.get(f):
                    problems.append(f"{coll.name} {doc['_id']}.{f}: MongoDB {stored.get(f)!r} != SQLite {doc.get(f)!r}")
    # Lineage: each parent is the previous attempt of the same investigation
    ids = {d["_id"]: d for d in attempt_docs}
    for d in attempt_docs:
        parent = ids.get(d["parent_attempt_id"]) if d["parent_attempt_id"] else None
        if d["attempt_number"] > 1 and (parent is None or parent["investigation_id"] != d["investigation_id"]
                                        or parent["attempt_number"] != d["attempt_number"] - 1):
            problems.append(f"attempt {d['_id']}: parent link does not point at attempt {d['attempt_number'] - 1}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sqlite", type=Path, default=settings.DB_PATH, help="SQLite file (default: DB_PATH)")
    parser.add_argument("--dry-run", action="store_true", help="show what would be copied; write nothing")
    args = parser.parse_args()

    if not args.sqlite.is_file():
        print(f"No SQLite database at {args.sqlite}: nothing to migrate.")
        return 0
    investigations, attempts, best = read_sqlite(args.sqlite)
    inv_docs, attempt_docs = to_documents(investigations, attempts, best)
    print(f"SQLite {args.sqlite}: {len(inv_docs)} investigation(s), {len(attempt_docs)} attempt(s), "
          f"best code for {len(best)} investigation(s)")
    if not inv_docs and not attempt_docs:
        print("No validation history in SQLite: nothing to migrate.")
        return 0
    if args.dry_run:
        print("Dry run: nothing written.")
        return 0

    db = validation_history._db()  # fails with setup instructions if MongoDB is not configured
    print(f"MongoDB database {settings.MONGODB_DATABASE!r}")
    for name, coll, docs in (("investigations", db.investigations, inv_docs),
                             ("attempts", db.validation_attempts, attempt_docs)):
        inserted, present, conflicts = insert(coll, docs)
        print(f"  {name}: {inserted} inserted, {present} already present, {len(conflicts)} conflict(s)")
        for c in conflicts:
            print(f"    conflict {c}")
    problems = verify(db, inv_docs, attempt_docs)
    if problems:
        print(f"Verification FAILED ({len(problems)} problem(s)); SQLite was not changed:")
        for p in problems[:50]:
            print("  " + p)
        return 1
    print(f"Verified: all {len(inv_docs)} investigation(s) and {len(attempt_docs)} attempt(s) match. "
          "SQLite was not changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
