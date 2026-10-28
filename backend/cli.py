"""Command-line scanner for CI pipelines (GitHub Actions, GitLab CI, local use).

Scans a local directory with the same pipeline as the web app, writes SARIF
for GitHub code scanning, and exits non-zero when findings at or above
--fail-on exist, so a workflow can block a pull request.

Examples:
    python backend/cli.py scan .                                   # summary only
    python backend/cli.py scan . --sarif results.sarif --fail-on high
    python backend/cli.py scan ../other-repo --no-ai --json report.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from services import pipeline, repo_manager, sarif_export  # noqa: E402

SEVERITIES = ["low", "medium", "high", "critical"]


def _print_summary(result: pipeline.PipelineResult) -> None:
    by_sev = Counter(v.severity for v in result.findings)
    by_cat = Counter(v.category.value for v in result.findings)
    print(f"\nLanguages: {', '.join(result.languages) or 'none detected'}")
    print(f"Findings:  {len(result.findings)} total | " + " | ".join(
        f"{s}: {by_sev.get(s, 0)}" for s in reversed(SEVERITIES)))
    print(f"By type:   code: {by_cat.get('code', 0)} | dependency: {by_cat.get('dependency', 0)} | "
          f"secret: {by_cat.get('secret', 0)}")
    for w in result.warnings:
        print(f"Warning:   {w}")
    if result.findings:
        print()
    for v in result.findings[:50]:
        print(f"  [{v.severity.upper():8s}] {v.category.value:10s} {v.file}:{v.line}  {v.title[:100]}")
    if len(result.findings) > 50:
        print(f"  ... and {len(result.findings) - 50} more (see SARIF / JSON output)")


async def _scan(args: argparse.Namespace) -> int:
    repo_path = Path(args.path).resolve()
    if not repo_path.is_dir():
        print(f"Not a directory: {repo_path}", file=sys.stderr)
        return 2

    scan_id = f"cli-{uuid.uuid4().hex[:8]}"
    try:
        result = await pipeline.analyze(repo_path, scan_id, use_ai=not args.no_ai)
    finally:
        repo_manager.cleanup_scan(scan_id)  # removes only the temp SARIF dir, never the repo

    _print_summary(result)

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(sarif_export.to_sarif(result.findings), indent=2), encoding="utf-8")
        print(f"\nSARIF written to {args.sarif}")
    if args.pdf:
        from datetime import datetime, timezone
        from services import pdf_report

        Path(args.pdf).write_bytes(pdf_report.render_pdf(
            repo_name=repo_path.name,
            repo_url=str(repo_path),
            scanned_at=datetime.now(timezone.utc).isoformat(),
            languages=result.languages,
            findings=result.findings,
            warnings=result.warnings,
        ))
        print(f"PDF written to {args.pdf}")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "languages": result.languages,
            "warnings": result.warnings,
            "vulnerabilities": [v.model_dump(mode="json") for v in result.findings],
        }, indent=2), encoding="utf-8")
        print(f"JSON written to {args.json}")

    if args.fail_on != "none":
        threshold = SEVERITIES.index(args.fail_on)
        blocking = [v for v in result.findings if SEVERITIES.index(v.severity) >= threshold]
        if blocking:
            print(f"\nFAILED: {len(blocking)} finding(s) at or above '{args.fail_on}'.")
            return 1
        print(f"\nPASSED: no findings at or above '{args.fail_on}'.")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="ai-security-scanner", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a local directory")
    scan.add_argument("path", help="Directory to scan (e.g. '.' in CI)")
    scan.add_argument("--sarif", help="Write SARIF 2.1.0 to this file")
    scan.add_argument("--json", help="Write full JSON results to this file")
    scan.add_argument("--pdf", help="Write a PDF report with every finding to this file")
    scan.add_argument("--fail-on", choices=["none", *SEVERITIES], default="none",
                      help="Exit 1 if any finding has this severity or higher (default: none)")
    scan.add_argument("--no-ai", action="store_true", help="Skip LLM enhancement (faster, no API key)")
    scan.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    sys.exit(asyncio.run(_scan(args)))


if __name__ == "__main__":
    main()
