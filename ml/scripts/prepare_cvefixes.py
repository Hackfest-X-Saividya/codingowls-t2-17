"""Extract Python / JavaScript / TypeScript functions from the CVEfixes dataset.

Streams the SQL dump straight out of CVEfixes_vX.zip (no need to unpack the
~20 GB SQL text or build the full database) and writes one JSON line per
function version:

    label 1 = vulnerable version (method_change.before_change == 'True')
    label 0 = fixed version      (method_change.before_change == 'False')

Usage:
    python ml/scripts/prepare_cvefixes.py \
        --zip datasets/raw/CVEfixes_v1.0.7.zip \
        --out ml/data/interim/functions.jsonl
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import sqlite3
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
}
WANTED_TABLES = {"fixes", "commits", "file_change", "method_change", "cwe_classification"}

# Some JS "functions" in CVEfixes are whole minified bundles (~1M chars on one
# line). They are useless for training (the model reads 512 tokens) and, kept
# in memory, they exhausted RAM and filled the disk via the page file.
MAX_LINES = 400
MAX_CHARS = 20_000
MAX_LINE_CHARS = 1_000
INSERT_RE = re.compile(r'^INSERT INTO "?(\w+)"?\s')
CREATE_RE = re.compile(r'^CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?', re.I)


def lang_of(filename: str | None) -> str | None:
    if not filename:
        return None
    return EXT_TO_LANG.get(Path(filename).suffix.lower())


def too_big(code: str) -> bool:
    if len(code) > MAX_CHARS or code.count("\n") + 1 > MAX_LINES:
        return True
    return any(len(line) > MAX_LINE_CHARS for line in code.splitlines())


def iter_statements(stream: io.TextIOBase):
    """Yield complete SQL statements from a sqlite3 .dump stream.

    A statement may span many lines (code with newlines inside string literals).
    sqlite escapes quotes as '', so quote parity tells us whether we're inside a
    string; a statement ends at a ';' line-end with even parity.
    """
    buf: list[str] = []
    parity = 0
    for line in stream:
        buf.append(line)
        parity = (parity + line.count("'")) % 2
        if parity == 0 and line.rstrip().endswith(";"):
            yield "".join(buf)
            buf.clear()
    if buf:
        yield "".join(buf)


def open_sql_stream(zip_path: Path) -> io.TextIOBase:
    zf = zipfile.ZipFile(zip_path)
    member = next(n for n in zf.namelist() if n.endswith(".sql.gz"))
    print(f"Reading {member} from {zip_path.name}", file=sys.stderr)
    raw = zf.open(member)
    return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="replace")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    # Scratch DB holds the parsed rows we keep; each INSERT is first executed
    # into an in-memory table that mirrors the dump's schema, then read back.
    mem = sqlite3.connect(":memory:")
    columns: dict[str, list[str]] = {}

    fixes: dict[str, list[tuple[str, str]]] = defaultdict(list)  # hash -> [(cve_id, repo_url)]
    commit_date: dict[str, str] = {}                            # hash -> author_date
    cwes: dict[str, list[str]] = defaultdict(list)              # cve_id -> [cwe_id]
    file_info: dict[int, tuple[str, str, str]] = {}             # file_change_id -> (hash, path, lang)
    file_change_done = False
    pending_methods: list[dict] = []   # only used if method_change precedes file_change
    skipped_big = 0

    # Functions are streamed to a temp file as they arrive (memory stays flat);
    # CWE labels appear later in the dump, so a second pass adds them.
    tmp_path = args.out.with_suffix(".partial.jsonl")
    tmp = tmp_path.open("w", encoding="utf-8")

    def emit(mrec: dict) -> None:
        commit_hash, path, lang = file_info[mrec["file_change_id"]]
        fx = fixes.get(commit_hash, [])
        tmp.write(json.dumps({
            "id": f"{mrec['method_change_id']}",
            "lang": lang,
            "label": 1 if mrec["before_change"] else 0,
            "code": mrec["code"],
            "name": mrec["name"],
            "path": path,
            "start_line": mrec["start_line"],
            "end_line": mrec["end_line"],
            "repo_url": fx[0][1] if fx else "",
            "commit": commit_hash,
            "date": commit_date.get(commit_hash, ""),
            "cve_ids": sorted({c for c, _ in fx}),
        }, ensure_ascii=False) + "\n")

    counts: Counter[str] = Counter()
    lang_counts: Counter[str] = Counter()
    started = time.time()
    current_table = None

    for stmt in iter_statements(open_sql_stream(args.zip)):
        m = INSERT_RE.match(stmt)
        if not m:
            c = CREATE_RE.match(stmt)
            if c:
                mem.execute(stmt)
                table = c.group(1)
                columns[table] = [r[1] for r in mem.execute(f'PRAGMA table_info("{table}")')]
            continue

        table = m.group(1)
        counts[table] += 1
        if table != current_table:
            if current_table == "file_change":
                file_change_done = True
            current_table = table
            print(f"[{time.time() - started:6.0f}s] table {table}", file=sys.stderr)
        if table not in WANTED_TABLES:
            continue
        if sum(counts.values()) % 200_000 == 0:
            print(f"[{time.time() - started:6.0f}s] {dict(counts)}", file=sys.stderr)

        mem.execute(stmt)
        rows = mem.execute(f'SELECT * FROM "{table}"').fetchall()
        mem.execute(f'DELETE FROM "{table}"')
        cols = columns[table]

        for row in rows:
            r = dict(zip(cols, row))
            if table == "fixes":
                fixes[r["hash"]].append((r["cve_id"], r["repo_url"]))
            elif table == "commits":
                commit_date[r["hash"]] = r.get("author_date") or ""
            elif table == "cwe_classification":
                cwes[r["cve_id"]].append(r["cwe_id"])
            elif table == "file_change":
                path = r.get("new_path") if r.get("new_path") not in (None, "None") else r.get("old_path")
                lang = lang_of(r.get("filename"))
                lang_counts[r.get("programming_language") or "?"] += 1
                if lang:
                    file_info[int(r["file_change_id"])] = (r["hash"], path or r["filename"], lang)
            elif table == "method_change":
                fcid = int(r["file_change_id"])
                if file_change_done and fcid not in file_info:
                    continue  # not Python / JS / TS
                code = r.get("code") or ""
                if too_big(code):
                    skipped_big += 1
                    continue
                rec = {
                    "file_change_id": fcid,
                    "method_change_id": r["method_change_id"],
                    "name": r.get("name"),
                    "start_line": r.get("start_line"),
                    "end_line": r.get("end_line"),
                    "code": code,
                    "before_change": str(r.get("before_change")) == "True",
                }
                if file_change_done:
                    emit(rec)
                else:
                    pending_methods.append(rec)

    for mrec in pending_methods:
        if mrec["file_change_id"] in file_info:
            emit(mrec)
    tmp.close()
    print(f"Rows seen: {dict(counts)}", file=sys.stderr)
    print(f"Top file languages in CVEfixes: {lang_counts.most_common(12)}", file=sys.stderr)
    print(f"Skipped {skipped_big} oversized / minified functions", file=sys.stderr)

    # Second pass: add CWE labels (cwe_classification comes after method_change)
    written = Counter()
    with tmp_path.open(encoding="utf-8") as src, args.out.open("w", encoding="utf-8") as f:
        for line in src:
            rec = json.loads(line)
            rec["cwe_ids"] = sorted({w for c in rec["cve_ids"] for w in cwes.get(c, [])})
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written[(rec["lang"], rec["label"])] += 1
    tmp_path.unlink()

    print(f"Wrote {sum(written.values())} functions to {args.out}", file=sys.stderr)
    for (lang, label), n in sorted(written.items()):
        print(f"  {lang:10s} label={label}: {n}", file=sys.stderr)
    print(f"Done in {time.time() - started:.0f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
