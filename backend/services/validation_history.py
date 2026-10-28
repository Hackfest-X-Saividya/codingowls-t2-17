"""Persistent validation history in MongoDB: every fix attempt, kept forever.

An investigation is the effort to fix one problem (an attack chain or a finding of
one scan). Each Validate Fix click is a run inside the problem's current
investigation; every attempt of every run is a document in `validation_attempts`:

  - created as RUNNING *before* its fix is generated (phase: generating ->
    applying -> validating), then finished exactly once as PASSED / FAILED /
    INCONCLUSIVE / ERROR / SKIPPED. Only RUNNING documents are ever updated and
    nothing is deleted (enforced here: every write filters on status RUNNING)
  - numbered 1, 2, 3... per investigation (unique index on investigation_id +
    attempt_number), each linked to the attempt before it (parent_attempt_id)
  - identified by one SHA-256 code_hash of the snapshot it validated; code an
    earlier attempt already validated is not run again but recorded as SKIPPED

A crash marks the run's RUNNING attempts ERROR; the first connection of a new
backend process does the same for attempts a stopped process left RUNNING. Only
one run per investigation at a time (atomic claim on active_validation_id).

A problem has one current investigation (unique current_key). Once it passed or
used its INVESTIGATION_MAX_ATTEMPTS, further runs are refused until the developer
explicitly starts a new investigation; nothing silently starts a fresh one.

Configured with MONGODB_URI / MONGODB_DATABASE. There is no fallback store: without
MongoDB, fix validation is unavailable (HistoryUnavailable) and scanning still works.
One backend process per database is assumed (as for the in-memory scan state).
"""
from __future__ import annotations

import logging
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError, PyMongoError

from models.schemas import (
    AttemptRecord, AttemptStatus, ChainFix, FixEdit, Investigation, ValidationAttempt, ValidationCheck,
)
from utils.config import settings

logger = logging.getLogger(__name__)

SETUP_HINT = ("Set MONGODB_URI (for example mongodb://localhost:27017, or your MongoDB Atlas "
              "mongodb+srv://<user>:<password>@<cluster>/ connection string) and MONGODB_DATABASE in backend/.env, "
              "then restart the backend.")
EVALUATED = [AttemptStatus.PASSED.value, AttemptStatus.FAILED.value, AttemptStatus.INCONCLUSIVE.value]


class HistoryUnavailable(RuntimeError):
    """MongoDB is not configured or not reachable."""


class DuplicateAttempt(Exception):
    """The attempt number already exists in the investigation."""


class ImmutableAttempt(Exception):
    """A finished attempt was about to be changed."""


_lock = threading.Lock()
_client: Optional[MongoClient] = None
_database: Optional[Database] = None


def _redact(text: str) -> str:
    return re.sub(r"(mongodb(?:\+srv)?://)[^@/\s]+@", r"\1***@", text)


def _db() -> Database:
    """The history database. The first connection of a process creates indexes and recovers interrupted attempts."""
    global _client, _database
    with _lock:
        if _database is not None:
            return _database
        if not settings.MONGODB_URI:
            raise HistoryUnavailable("Fix validation stores its history in MongoDB, but MONGODB_URI is not set. "
                                     + SETUP_HINT)
        try:
            client: MongoClient = MongoClient(settings.MONGODB_URI, appname="ai-security-scanner",
                                              serverSelectionTimeoutMS=settings.MONGODB_TIMEOUT_MS)
            client.admin.command("ping")
            db = client[settings.MONGODB_DATABASE]
            _ensure_indexes(db)
            _recover(db)
        except PyMongoError as e:
            logger.error("MongoDB connection failed: %s", _redact(str(e)))
            raise HistoryUnavailable(f"MongoDB is not reachable ({type(e).__name__}). Check MONGODB_URI, the "
                                     "network access list and the credentials. " + SETUP_HINT) from e
        _client, _database = client, db
        logger.info("Validation history: MongoDB database %r", settings.MONGODB_DATABASE)
        return db


def connect() -> None:
    """Connect now (at startup), so interrupted attempts are recovered before new ones start."""
    _db()


def reset() -> None:
    """Forget the connection, as a backend restart would (tests)."""
    global _client, _database
    with _lock:
        if _client is not None:
            _client.close()
        _client = _database = None


def _ensure_indexes(db: Database) -> None:
    a, i = db.validation_attempts, db.investigations
    a.create_index([("investigation_id", ASCENDING), ("attempt_number", ASCENDING)], unique=True,
                   name="attempt_number_unique")
    a.create_index([("investigation_id", ASCENDING), ("code_hash", ASCENDING)], name="snapshot")
    a.create_index([("validation_id", ASCENDING), ("status", ASCENDING)], name="run_status")
    a.create_index([("status", ASCENDING)], name="status")
    a.create_index([("rule_id", ASCENDING), ("status", ASCENDING), ("created_at", DESCENDING)], name="similar_rule")
    a.create_index([("vuln_class", ASCENDING), ("status", ASCENDING), ("created_at", DESCENDING)], name="similar_class")
    a.create_index([("strategy_id", ASCENDING), ("rule_id", ASCENDING), ("vuln_class", ASCENDING)], name="strategy")
    # One current investigation per problem; closed ones drop the key
    i.create_index("current_key", unique=True, partialFilterExpression={"current_key": {"$exists": True}},
                   name="current_investigation_unique")
    i.create_index([("scan_id", ASCENDING), ("target_key", ASCENDING), ("created_at", DESCENDING)], name="problem")


def _recover(db: Database) -> int:
    """Attempts left RUNNING by a stopped backend become ERROR; their runs' claims are released."""
    now = _now()
    n = db.validation_attempts.update_many({"status": AttemptStatus.RUNNING.value}, [{"$set": {
        "status": AttemptStatus.ERROR.value, "finished_at": now, "updated_at": now,
        "failure_reason": {"$concat": ["Interrupted: the backend stopped while this attempt was running (during ",
                                       {"$ifNull": ["$phase", "setup"]}, ")."]},
    }}]).modified_count
    db.investigations.update_many({"active_validation_id": {"$ne": None}},
                                  {"$set": {"active_validation_id": None, "updated_at": now}})
    if n:
        logger.warning("Marked %d interrupted validation attempt(s) as ERROR", n)
    return n


def recover_interrupted() -> int:
    return _recover(_db())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- investigations ----------

def target_key(chain_id: Optional[str], finding_id: Optional[str]) -> str:
    return f"chain:{chain_id}" if chain_id else f"finding:{finding_id}"


def _inv(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    out["investigation_id"] = out.pop("_id")
    return out


def open_investigation(
    scan_id: str, key: str, *, max_attempts: int, finding_id: Optional[str] = None, chain_id: Optional[str] = None,
    rule_id: Optional[str] = None, vuln_class: Optional[str] = None, repo_url: Optional[str] = None,
    file: Optional[str] = None, new: bool = False,
) -> dict[str, Any]:
    """The problem's current investigation (open, passed or exhausted), created if there is none.

    new=True closes the current one (unless a run holds it) and creates another;
    this is the only way a problem gets a fresh investigation.
    """
    db = _db()
    current_key = f"{scan_id}|{key}"
    for _ in range(3):  # retried only if another request created one at the same moment
        doc = db.investigations.find_one({"current_key": current_key})
        if doc is not None and new:
            closed = db.investigations.update_one(
                {"_id": doc["_id"], "active_validation_id": None},
                {"$set": {"status": "closed", "updated_at": _now()}, "$unset": {"current_key": ""}})
            if closed.modified_count:
                doc, new = None, False
        if doc is not None:
            return _inv(doc)
        now = _now()
        doc = {"_id": uuid.uuid4().hex[:12], "current_key": current_key, "scan_id": scan_id, "target_key": key,
               "finding_id": finding_id, "chain_id": chain_id, "rule_id": rule_id, "vuln_class": vuln_class,
               "repo_url": repo_url, "file": file, "status": "open", "max_attempts": max_attempts,
               "active_validation_id": None, "best_fix": None, "best_attempt": None,
               "created_at": now, "updated_at": now}
        try:
            db.investigations.insert_one(doc)
            return _inv(doc)
        except DuplicateKeyError:
            continue
    raise HistoryUnavailable("Could not open an investigation; try again.")


def claim(investigation_id: str, validation_id: str) -> Optional[int]:
    """Reserve the open investigation for one run. Returns its next attempt number, or None if it is not available."""
    db = _db()
    doc = db.investigations.find_one_and_update(
        {"_id": investigation_id, "status": "open", "active_validation_id": None},
        {"$set": {"active_validation_id": validation_id, "updated_at": _now()}}, return_document=ReturnDocument.AFTER)
    if doc is None:
        return None
    top = db.validation_attempts.find_one({"investigation_id": investigation_id}, sort=[("attempt_number", DESCENDING)])
    return (top["attempt_number"] + 1) if top else 1


def release(investigation_id: str, validation_id: str) -> str:
    """End a run's claim; the investigation becomes passed / exhausted when that is now true. Returns its status."""
    db = _db()
    inv = db.investigations.find_one({"_id": investigation_id})
    if inv is None:
        return "missing"
    status = inv["status"]
    if status == "open":
        passed = db.validation_attempts.find_one({"investigation_id": investigation_id,
                                                  "status": AttemptStatus.PASSED.value})
        used = attempts_used(investigation_id)
        status = "passed" if passed else "exhausted" if used >= inv["max_attempts"] else "open"
    db.investigations.update_one({"_id": investigation_id, "active_validation_id": validation_id},
                                 {"$set": {"status": status, "active_validation_id": None, "updated_at": _now()}})
    return status


def record_best(investigation_id: str, fix: ChainFix, best_attempt: int) -> None:
    """The best code so far (edits against the original), where the next run resumes."""
    _db().investigations.update_one({"_id": investigation_id}, {"$set": {
        "best_fix": fix.model_dump(mode="json"), "best_attempt": best_attempt, "updated_at": _now()}})


def best(investigation_id: str) -> tuple[Optional[ChainFix], Optional[int]]:
    doc = _db().investigations.find_one({"_id": investigation_id}, {"best_fix": 1, "best_attempt": 1}) or {}
    fix = ChainFix.model_validate(doc["best_fix"]) if doc.get("best_fix") else None
    return fix, doc.get("best_attempt")


def attempts_used(investigation_id: str) -> int:
    return _db().validation_attempts.count_documents({"investigation_id": investigation_id})


def mark_exhausted(investigation_id: str) -> None:
    _db().investigations.update_one({"_id": investigation_id, "status": "open"},
                                    {"$set": {"status": "exhausted", "updated_at": _now()}})


def get_investigation(investigation_id: str) -> Optional[Investigation]:
    doc = _db().investigations.find_one({"_id": investigation_id})
    if doc is None:
        return None
    inv = _inv(doc)
    return Investigation(**{k: inv[k] for k in Investigation.model_fields if k in inv},
                         attempts=attempts(investigation_id))


# ---------- attempts ----------

def begin_attempt(investigation_id: str, validation_id: str, attempt_number: int, phase: str = "generating") -> str:
    """Create attempt `attempt_number` as RUNNING, before its fix is generated, linked to the previous attempt.

    The number must be exactly the next one: a repeat raises DuplicateAttempt (also
    when two writers race, via the unique index) and a gap raises ValueError.
    """
    db = _db()
    inv = db.investigations.find_one({"_id": investigation_id})
    if inv is None:
        raise ValueError(f"Unknown investigation {investigation_id}")
    prev = db.validation_attempts.find_one({"investigation_id": investigation_id}, sort=[("attempt_number", DESCENDING)])
    expected = (prev["attempt_number"] + 1) if prev else 1
    if attempt_number < expected:
        raise DuplicateAttempt(f"Attempt {attempt_number} already exists in investigation {investigation_id}")
    if attempt_number != expected:
        raise ValueError(f"Attempt {attempt_number} would leave a gap; the next attempt is {expected}")
    now = _now()
    doc = {"_id": uuid.uuid4().hex, "investigation_id": investigation_id, "validation_id": validation_id,
           "attempt_number": attempt_number, "parent_attempt_id": prev["_id"] if prev else None,
           "code_hash": None, "finding_id": inv.get("finding_id"), "chain_id": inv.get("chain_id"),
           "rule_id": inv.get("rule_id"), "vuln_class": inv.get("vuln_class"), "repo_url": inv.get("repo_url"),
           "file": inv.get("file"), "phase": phase, "fix_origin": None, "strategy": None, "patch": [],
           "diff": "", "status": AttemptStatus.RUNNING.value, "outcome": None, "failure_reason": None,
           "evaluated": False, "result": None, "created_at": now, "updated_at": now, "finished_at": None}
    try:
        db.validation_attempts.insert_one(doc)
    except DuplicateKeyError as e:
        raise DuplicateAttempt(f"Attempt {attempt_number} already exists in investigation {investigation_id}") from e
    return doc["_id"]


def _update_running(attempt_id: str, fields: dict[str, Any]) -> None:
    fields["updated_at"] = _now()
    res = _db().validation_attempts.update_one({"_id": attempt_id, "status": AttemptStatus.RUNNING.value},
                                               {"$set": fields})
    if res.matched_count != 1:
        raise ImmutableAttempt(f"Attempt {attempt_id} is not running; finished attempts are never changed")


def set_fix(attempt_id: str, fix: ChainFix) -> None:
    """The generated fix (patch) and the strategy chosen for it, before it is applied."""
    _update_running(attempt_id, {"phase": "applying", "fix_origin": fix.origin, "strategy": fix.strategy,
                                 "strategy_id": fix.strategy_id, "selection_note": fix.history_note,
                                 "patch": [e.model_dump() for e in fix.edits]})


def set_code_hash(attempt_id: str, code_hash: str) -> None:
    """The snapshot this attempt validates; set once the patch is applied, before the checks run."""
    _update_running(attempt_id, {"phase": "validating", "code_hash": code_hash})


def finish_attempt(attempt_id: str, attempt: ValidationAttempt) -> None:
    """Record an evaluated attempt's results; only a RUNNING attempt can be finished."""
    status = attempt.record_status or AttemptStatus.INCONCLUSIVE
    applied = not any(c.name == "apply_patch" for c in attempt.checks)
    _update_running(attempt_id, {
        "status": status.value, "outcome": attempt.status.value,
        "failure_reason": None if status == AttemptStatus.PASSED else attempt.summary,
        "code_hash": attempt.code_hash, "diff": attempt.diff, "evaluated": applied,
        "result": attempt.model_dump(mode="json"), "finished_at": _now()})


def close_attempt(attempt_id: str, status: AttemptStatus, reason: str) -> None:
    """End an attempt without an evaluation: no fix could be generated (INCONCLUSIVE) or the code was already validated (SKIPPED)."""
    _update_running(attempt_id, {"status": status.value, "failure_reason": reason, "finished_at": _now()})


def fail_running(validation_id: str, reason: str) -> int:
    """A run crashed: its RUNNING attempts become ERROR (kept, with the reason and the phase it reached)."""
    now = _now()
    return _db().validation_attempts.update_many(
        {"validation_id": validation_id, "status": AttemptStatus.RUNNING.value},
        [{"$set": {"status": AttemptStatus.ERROR.value, "finished_at": now, "updated_at": now,
                   "failure_reason": {"$concat": [reason[:2000], " (during ", {"$ifNull": ["$phase", "setup"]}, ")"]}}}],
    ).modified_count


def _record(doc: dict[str, Any]) -> AttemptRecord:
    result = doc.get("result") or {}
    return AttemptRecord(
        attempt_id=doc["_id"], investigation_id=doc["investigation_id"], validation_id=doc["validation_id"],
        attempt_number=doc["attempt_number"], parent_attempt_id=doc.get("parent_attempt_id"),
        code_hash=doc.get("code_hash"), finding_id=doc.get("finding_id"), chain_id=doc.get("chain_id"),
        rule_id=doc.get("rule_id"), vuln_class=doc.get("vuln_class"), phase=doc.get("phase"), status=doc["status"],
        outcome=doc.get("outcome"), failure_reason=doc.get("failure_reason"), strategy=doc.get("strategy") or "",
        strategy_id=doc.get("strategy_id") or "", selection_note=doc.get("selection_note") or "",
        fix_origin=doc.get("fix_origin") or "", patch=[FixEdit.model_validate(e) for e in doc.get("patch") or []],
        diff=doc.get("diff") or "", checks=[ValidationCheck.model_validate(c) for c in result.get("checks", [])],
        created_at=doc["created_at"], finished_at=doc.get("finished_at"),
    )


def attempts(investigation_id: str) -> list[AttemptRecord]:
    docs = _db().validation_attempts.find({"investigation_id": investigation_id}).sort("attempt_number", ASCENDING)
    return [_record(d) for d in docs]


def history(investigation_id: str) -> list[ValidationAttempt]:
    """Evaluated attempts of an investigation, oldest first, as the fix generators take them."""
    docs = _db().validation_attempts.find({"investigation_id": investigation_id, "result": {"$ne": None}},
                                          {"result": 1}).sort("attempt_number", ASCENDING)
    return [ValidationAttempt.model_validate(d["result"]) for d in docs]


def known_snapshot(investigation_id: str, code_hash: str) -> Optional[str]:
    """An earlier attempt that already validated exactly this code (ERROR/SKIPPED don't count: nothing was learned)."""
    doc = _db().validation_attempts.find_one(
        {"investigation_id": investigation_id, "code_hash": code_hash, "status": {"$in": EVALUATED}, "evaluated": True},
        sort=[("attempt_number", ASCENDING)])
    return f"attempt {doc['attempt_number']} ({doc['status']})" if doc else None


# ---------- learning from other investigations ----------

def similar(
    *, rule_id: Optional[str], vuln_class: Optional[str], repo_url: Optional[str] = None, file: Optional[str] = None,
    exclude_investigation: Optional[str] = None, limit: int = 6,
) -> list[dict[str, Any]]:
    """Evaluated attempts on the same rule or vulnerability class in other investigations, most relevant first.

    Relevance: same repository and file, then same rule, then same class; passes before
    failures at equal relevance; newest first. ERROR / SKIPPED attempts carry no evidence.
    """
    match = [{f: v} for f, v in (("rule_id", rule_id), ("vuln_class", vuln_class)) if v]
    if not match:
        return []
    docs = list(_db().validation_attempts.find(
        {"status": {"$in": EVALUATED}, "evaluated": True, "investigation_id": {"$ne": exclude_investigation},
         "$or": match},
        {"result": 0}).sort("created_at", DESCENDING).limit(200))

    def relevance(d: dict[str, Any]) -> tuple:
        return (4 * (bool(repo_url) and d.get("repo_url") == repo_url and d.get("file") == file)
                + 2 * (bool(rule_id) and d.get("rule_id") == rule_id)
                + (bool(vuln_class) and d.get("vuln_class") == vuln_class),
                d["status"] == AttemptStatus.PASSED.value)

    return sorted(docs, key=relevance, reverse=True)[:limit]  # stable: newest first within a rank


def strategy_stats(
    *, rule_id: Optional[str], vuln_class: Optional[str], exclude_investigation: Optional[str] = None,
) -> dict[str, tuple[int, int]]:
    """(passed, failed) per fix strategy over evaluated attempts on the same rule or vulnerability class,
    in other investigations (fix_planner.choose adds the current investigation's own attempts).

    INCONCLUSIVE counts as a failure of the strategy (e.g. the scanner still flags it); ERROR, SKIPPED
    and patches that did not apply count as nothing.
    """
    match = [{f: v} for f, v in (("rule_id", rule_id), ("vuln_class", vuln_class)) if v]
    if not match:
        return {}
    rows = _db().validation_attempts.aggregate([
        {"$match": {"status": {"$in": EVALUATED}, "evaluated": True, "strategy_id": {"$nin": [None, ""]},
                    "investigation_id": {"$ne": exclude_investigation}, "$or": match}},
        {"$group": {"_id": "$strategy_id",
                    "passed": {"$sum": {"$cond": [{"$eq": ["$status", AttemptStatus.PASSED.value]}, 1, 0]}},
                    "failed": {"$sum": {"$cond": [{"$eq": ["$status", AttemptStatus.PASSED.value]}, 0, 1]}}}},
    ])
    return {r["_id"]: (r["passed"], r["failed"]) for r in rows}


def lessons(rows: list[dict[str, Any]], stats: Optional[dict[str, tuple[int, int]]] = None,
            max_diff: int = 600) -> str:
    """Similar attempts as prompt text: each strategy's record, what passed, what failed and why.
    Empty when there is nothing."""
    out = [f"- strategy {sid}: passed {p}, failed {f} in comparable cases"
           for sid, (p, f) in sorted((stats or {}).items())]
    for r in rows:
        label = "PASSED" if r["status"] == "PASSED" else f"{r['status']} — {(r.get('failure_reason') or '')[:300]}"
        out.append(f"- [{r.get('rule_id') or r.get('vuln_class')}] {r.get('strategy') or 'fix'} "
                   f"({r.get('strategy_id') or r.get('fix_origin')}): {label}")
        if r.get("diff"):
            out.append("  change:\n" + "\n".join("    " + line for line in r["diff"][:max_diff].splitlines()))
    return "\n".join(out)
