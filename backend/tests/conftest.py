"""Shared helpers for the chain-analysis and fix-validation tests.

The tests never call Semgrep or Groq: `FakeScanner` stands in for the targeted
Semgrep re-check with a few deterministic regex rules, and AI suggestions are
disabled, so every run gives the same result.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.schemas import Vulnerability  # noqa: E402
from services import chain_analysis, fix_validation, flow_analyzer  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

FAKE_RULES = [
    ("fake.python.sql-injection", re.compile(r"execute\((f[\"']|query\)|sql\))"), "SQL query built from user input"),
    ("fake.python.subprocess-shell-true", re.compile(r"shell=True"), "subprocess call with shell=True"),
    ("fake.python.os-system", re.compile(r"os\.system\("), "os.system call"),
    ("fake.python.debug-enabled", re.compile(r"debug=True"), "Flask debug mode enabled"),
    ("fake.js.sql-concat", re.compile(r"query\(\s*[\"'][^\"']*[\"']\s*\+"), "SQL query built by string concatenation"),
    # Pattern rule like Semgrep's: flags any returned f-string, escaped or not
    ("fake.python.directly-returned-format-string", re.compile(r"return f[\"']"), "Route returns a formatted string"),
]


def fake_findings(root: Path, files: Optional[list[str]] = None) -> list[Vulnerability]:
    out = []
    for rel in files or [p.relative_to(root).as_posix() for p in root.rglob("*") if p.suffix in (".py", ".js")]:
        for i, line in enumerate((root / rel).read_text(encoding="utf-8").split("\n"), 1):
            for rule_id, pattern, title in FAKE_RULES:
                if pattern.search(line):
                    out.append(Vulnerability(
                        id=f"vuln_{len(out) + 1:03d}", title=title, severity="high", scanner_severity="high",
                        file=rel, line=i, rule_id=rule_id, vulnerable_code=line.strip(),
                    ))
    return out


class FakeScanner:
    """Scanner protocol of fix_validation; can be told to fail."""

    def __init__(self, error: Optional[str] = None) -> None:
        self.error = error
        self.calls: list[tuple[Path, list[str]]] = []

    async def __call__(self, root: Path, files: list[str], languages: list[str]):
        self.calls.append((root, files))
        if self.error:
            return [], self.error
        return fake_findings(root, files), None


@pytest.fixture
def make_repo(tmp_path):
    """Copy a fixture app into a fresh directory and return its path."""
    def make(name: str) -> Path:
        dest = tmp_path / name / "original"
        shutil.copytree(FIXTURES / name, dest)
        return dest
    return make


def baseline_for(root: Path, findings: Optional[list[Vulnerability]] = None) -> fix_validation.Baseline:
    """What the API does before validating: analyse the scanned revision and rebuild its chains."""
    findings = fake_findings(root) if findings is None else findings
    analysis = flow_analyzer.analyze_repository(root)
    chains = chain_analysis.build_chains(analysis, findings, root)
    return fix_validation.Baseline(root, analysis, chains, ["python"])


def chain_at(baseline: fix_validation.Baseline, function: str, occurrence: int = 0, kind: str = "sql_injection"):
    for c in baseline.chains:
        if c.function == function and c.kind == kind and c.signature["occurrence"] == str(occurrence):
            return c
    raise AssertionError(f"no {kind} chain in {function}() #{occurrence}: {[c.title for c in baseline.chains]}")
