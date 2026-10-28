"""Demo: a fix that needs three attempts, each building on the previous one's code.

Scenario: requirements.txt pins flask==0.12. The advisory for 0.12 is fixed in 1.0,
but 1.0 has its own advisory (fixed in 2.0), and 2.0 has another (fixed in 2.2.5).

Everything here is the real validation loop: fix generation, applying the change
to a copy, carrying the code forward, re-checking, deciding, stopping. Only the
vulnerability database (OSV.dev) answers are SIMULATED, so the run is repeatable.

    cd backend
    python scripts/demo_three_attempts.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.schemas import FindingCategory, Vulnerability  # noqa: E402
from services import dependency_scanner, finding_validation, fix_validation  # noqa: E402

# Simulated advisory database: version -> (advisory id, first fixed version)
SIMULATED_OSV = {
    "0.12": ("GHSA-0001 (DoS in JSON parsing)", "1.0"),
    "1.0": ("GHSA-0002 (session cookie leak)", "2.0"),
    "2.0": ("GHSA-0003 (missing Vary header)", "2.2.5"),
}


async def simulated_scan(repo: Path):
    line = next(l for l in (repo / "requirements.txt").read_text().splitlines() if l.startswith("flask=="))
    version = line.split("==")[1]
    if version not in SIMULATED_OSV:
        return [], []
    advisory, fixed = SIMULATED_OSV[version]
    return [Vulnerability(
        id="dep_001", title=f"flask {version}: {advisory}", severity="high", scanner_severity="high",
        file="requirements.txt", line=2, rule_id=advisory, category=FindingCategory.DEPENDENCY,
        package="flask", installed_version=version, fixed_version=fixed)], []


async def main() -> None:
    dependency_scanner.scan_dependencies = simulated_scan  # only the database is simulated
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        (root / "requirements.txt").write_text("requests==2.32.4\nflask==0.12\ngunicorn==22.0.0\n")

        [finding] = (await simulated_scan(root))[0]
        print(f"Finding: {finding.title}  (suggested upgrade: {finding.fixed_version})\n")

        target = finding_validation.FindingTarget(finding, root, ["python"], scanner=None, all_findings=[finding])
        result = await fix_validation.run_loop(target, Path(tmp) / "work", max_attempts=5)

        for a in result.attempts:
            edit = a.fix.edits[0]
            print(f"Attempt {a.attempt}: {edit.original!r} -> {edit.replacement!r}")
            print(f"  result:   {a.status.value.upper()}  (progress score {a.progress_score}, "
                  f"{'improved' if a.improved else 'no progress'})")
            print(f"  why:      {a.summary}")
            if a.new_issues:
                print(f"  evidence: {a.new_issues[0].description}  -> next attempt builds on this version")
            print()

        print(f"Final status: {result.status.value.upper()} after {len(result.attempts)} attempts "
              f"(stopped because: {result.stop_reason})")
        final = result.final_fix.edits[0]
        print(f"Final code:   {final.original!r} -> {final.replacement!r}   (vs the original file)")
        print("\nFinal diff:\n" + result.final_diff)


if __name__ == "__main__":
    asyncio.run(main())
