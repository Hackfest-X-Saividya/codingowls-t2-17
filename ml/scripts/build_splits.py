"""Clean, deduplicate and split the extracted functions into train/val/test.

- Strips comments (so the model can't learn from "// fix CVE-..." notes)
- Drops very short / very long functions
- Deduplicates on normalised code; code that appears with BOTH labels is
  ambiguous and removed entirely
- Splits by repository (never by function) so test projects are unseen
- Picks the most frequent CWEs as classes; the rest become "other"

Usage:
    python ml/scripts/build_splits.py \
        --inp ml/data/interim/functions.jsonl \
        --out ml/data/processed
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

PY_COMMENT = re.compile(r"^\s*#.*$", re.M)
JS_LINE_COMMENT = re.compile(r"^\s*//.*$", re.M)
JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
DOCSTRING = re.compile(r'^\s*(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')\s*$', re.M)
WS = re.compile(r"\s+")


def strip_comments(code: str, lang: str) -> str:
    if lang == "python":
        code = DOCSTRING.sub("", PY_COMMENT.sub("", code))
    else:
        code = JS_LINE_COMMENT.sub("", JS_BLOCK_COMMENT.sub("", code))
    return "\n".join(line for line in code.splitlines() if line.strip())


def norm_hash(code: str) -> str:
    return hashlib.sha1(WS.sub(" ", code).strip().encode()).hexdigest()


def split_of(repo_url: str, val: float, test: float) -> str:
    bucket = int(hashlib.md5(repo_url.encode()).hexdigest(), 16) % 10_000 / 10_000
    if bucket < test:
        return "test"
    if bucket < test + val:
        return "val"
    return "train"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inp", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--min-lines", type=int, default=3)
    ap.add_argument("--max-lines", type=int, default=400)
    ap.add_argument("--val", type=float, default=0.1)
    ap.add_argument("--test", type=float, default=0.1)
    ap.add_argument("--top-cwes", type=int, default=10)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    dropped: Counter[str] = Counter()
    by_hash: dict[str, list[dict]] = defaultdict(list)
    with args.inp.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if not r["repo_url"]:
                dropped["no_repo"] += 1
                continue
            code = strip_comments(r["code"], r["lang"])
            n = code.count("\n") + 1
            if n < args.min_lines or n > args.max_lines:
                dropped["length"] += 1
                continue
            r["code"] = code
            by_hash[norm_hash(code)].append(r)

    records: list[dict] = []
    for group in by_hash.values():
        if len({r["label"] for r in group}) > 1:
            dropped["ambiguous_label"] += len(group)
            continue
        dropped["duplicate"] += len(group) - 1
        records.append(group[0])

    # CWE classes, chosen from training positives only
    for r in records:
        r["split"] = split_of(r["repo_url"], args.val, args.test)
        real = [c for c in r["cwe_ids"] if c.startswith("CWE-")]
        r["cwe"] = real[0] if real else "other"
    train_cwes = Counter(r["cwe"] for r in records if r["split"] == "train" and r["label"] == 1)
    classes = [c for c, _ in train_cwes.most_common() if c != "other"][: args.top_cwes] + ["other"]
    for r in records:
        if r["cwe"] not in classes:
            r["cwe"] = "other"

    stats = Counter((r["split"], r["lang"], r["label"]) for r in records)
    for split in ("train", "val", "test"):
        with (args.out / f"{split}.jsonl").open("w", encoding="utf-8") as f:
            for r in records:
                if r["split"] == split:
                    f.write(json.dumps({k: r[k] for k in (
                        "id", "lang", "label", "cwe", "code", "name", "path",
                        "repo_url", "commit", "date", "cve_ids")}, ensure_ascii=False) + "\n")

    (args.out / "labels.json").write_text(json.dumps({"cwe_classes": classes}, indent=2))

    lines = ["# Dataset stats", "", f"Dropped: {dict(dropped)}", "",
             "| split | lang | vulnerable (1) | fixed (0) |", "|---|---|---|---|"]
    for split in ("train", "val", "test"):
        for lang in sorted({r["lang"] for r in records}):
            lines.append(f"| {split} | {lang} | {stats[(split, lang, 1)]} | {stats[(split, lang, 0)]} |")
    repos = Counter(r["split"] for r in {r["repo_url"]: r for r in records}.values())
    lines += ["", f"Repositories per split: {dict(repos)}", "",
              "CWE classes (train positives):", ""]
    lines += [f"- {c}: {train_cwes.get(c, sum(n for k, n in train_cwes.items() if k not in classes))}" for c in classes]
    (args.out / "stats.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
