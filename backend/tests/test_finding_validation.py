"""Fix validation for single findings: code in any language, dependencies and secrets."""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from models.schemas import ChainFix, FindingCategory, FixEdit, ValidationStatus, Vulnerability
from services import dependency_scanner, finding_validation, fix_validation, secret_scanner

from conftest import FakeScanner, fake_findings

JS_APP = """const express = require("express");
const app = express();

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});
"""


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for rel, text in files.items():
        (root / rel).write_text(text, encoding="utf-8")
    return root


def _run(target, work: Path, max_attempts=3):
    return asyncio.run(fix_validation.run_loop(target, work, max_attempts))


def _js_finding(root: Path, fixed_code: str) -> Vulnerability:
    [f] = [v for v in fake_findings(root) if v.rule_id == "fake.js.sql-concat"]
    return f.model_copy(update={"fixed_code": fixed_code})


def test_code_finding_in_javascript_is_fixed_and_verified(tmp_path):
    root = _repo(tmp_path, {"app.js": JS_APP})
    finding = _js_finding(root, '```js\ndb.query("SELECT * FROM users WHERE id = ?", [req.query.id], (err, rows) => res.json(rows));\n```')
    target = finding_validation.FindingTarget(finding, root, ["javascript"], FakeScanner())

    result = _run(target, tmp_path / "work")

    assert result.status == ValidationStatus.PASS and result.stop_reason == "passed"
    [a] = result.attempts
    assert {c.name: c.status for c in a.checks}["reproduce_original"] == "passed"
    assert "?\", [req.query.id]" in result.final_fix.edits[0].replacement
    assert result.final_fix.edits[0].replacement.startswith("  db.query"), "indentation of the flagged line kept"
    if shutil.which("node"):
        assert {c.name: c.status for c in a.checks}["syntax"] == "passed"


def test_each_attempt_builds_on_the_previous_code(tmp_path, monkeypatch):
    """Attempt 1's suggestion is faulty; attempt 2 edits attempt 1's code, and the final code is attempt 2's."""
    root = _repo(tmp_path, {"app.js": JS_APP})
    faulty = 'const id = req.query.id;\ndb.query("SELECT * FROM users WHERE id = " + id, (err, rows) => res.json(rows));'
    finding = _js_finding(root, faulty)
    seen_code = []

    async def ai_fix(self, current, history):
        text = (current / "app.js").read_text(encoding="utf-8")
        seen_code.append(text)
        lines = text.split("\n")
        n = next(i for i, l in enumerate(lines, 1) if "+ id" in l)
        return ChainFix(strategy="Use a placeholder", break_point=finding.id, origin="ai", edits=[FixEdit(
            file="app.js", start_line=n, end_line=n, original=lines[n - 1],
            replacement='  db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => res.json(rows));')])

    monkeypatch.setattr(finding_validation.FindingTarget, "_ai_fix", ai_fix)
    target = finding_validation.FindingTarget(finding, root, ["javascript"], FakeScanner(), use_ai=True)
    result = _run(target, tmp_path / "work")

    first, second = result.attempts
    assert first.status == ValidationStatus.FAIL, "the faulty suggestion still concatenates"
    assert "const id = req.query.id;" in seen_code[0], "attempt 2 was planned on attempt 1's code"
    assert second.status == ValidationStatus.PASS
    final = "\n".join(e.replacement for e in result.final_fix.edits)
    assert "const id = req.query.id;" in final and "[id]" in final, "final code = attempt 1 + attempt 2"
    assert final != first.fix.edits[0].replacement
    assert (tmp_path / "work" / "attempt-2" / "app.js").read_text(encoding="utf-8").count("const id") == 1


def test_dependency_upgrade_moves_past_new_advisories(tmp_path, monkeypatch):
    root = _repo(tmp_path, {"requirements.txt": "requests==2.31.0\nflask==0.12\n"})
    advisories = {"0.12": ("GHSA-old", "1.0"), "1.0": ("GHSA-new", "2.2.5")}

    async def fake_osv(repo: Path):
        version = next(l.split("==")[1] for l in (repo / "requirements.txt").read_text().splitlines() if l.startswith("flask"))
        if version not in advisories:
            return [], []
        vid, fixed = advisories[version]
        return [Vulnerability(id="dep_001", title=f"flask {version}", severity="high", scanner_severity="high",
                              file="requirements.txt", line=2, rule_id=vid, category=FindingCategory.DEPENDENCY,
                              package="flask", installed_version=version, fixed_version=fixed)], []

    monkeypatch.setattr(dependency_scanner, "scan_dependencies", fake_osv)
    [finding] = asyncio.run(fake_osv(root))[0]
    target = finding_validation.FindingTarget(finding, root, ["python"], None, all_findings=[finding])
    result = _run(target, tmp_path / "work")

    first, second = result.attempts
    assert first.status == ValidationStatus.NEW_VULNERABILITY, "1.0 fixes GHSA-old but has GHSA-new"
    assert second.status == ValidationStatus.PASS
    assert second.fix.edits[0].original == "flask==1.0", "the second upgrade starts from the first one"
    assert result.final_fix.edits[0].original == "flask==0.12"
    assert result.final_fix.edits[0].replacement == "flask==2.2.5"


def test_three_attempts_each_building_on_the_last(tmp_path, monkeypatch):
    """Same score but a *different* remaining problem is progress, not a stall."""
    root = _repo(tmp_path, {"requirements.txt": "flask==0.12\n"})
    chain = {"0.12": ("GHSA-1", "1.0"), "1.0": ("GHSA-2", "2.0"), "2.0": ("GHSA-3", "2.2.5")}

    async def fake_osv(repo: Path):
        version = (repo / "requirements.txt").read_text().strip().split("==")[1]
        if version not in chain:
            return [], []
        vid, fixed = chain[version]
        return [Vulnerability(id="dep_001", title=vid, severity="high", scanner_severity="high", file="requirements.txt",
                              line=1, rule_id=vid, category=FindingCategory.DEPENDENCY, package="flask",
                              installed_version=version, fixed_version=fixed)], []

    monkeypatch.setattr(dependency_scanner, "scan_dependencies", fake_osv)
    [finding] = asyncio.run(fake_osv(root))[0]
    result = _run(finding_validation.FindingTarget(finding, root, ["python"], None, all_findings=[finding]),
                  tmp_path / "work", max_attempts=5)

    assert [a.status for a in result.attempts] == [
        ValidationStatus.NEW_VULNERABILITY, ValidationStatus.NEW_VULNERABILITY, ValidationStatus.PASS]
    assert all(a.improved for a in result.attempts)
    assert [a.fix.edits[0].original for a in result.attempts] == ["flask==0.12", "flask==1.0", "flask==2.0"]
    assert result.final_fix.edits[0].replacement == "flask==2.2.5" and result.stop_reason == "passed"


def test_secret_moves_to_an_environment_variable(tmp_path):
    secret = "Zx9fQ2pL7vR4tY8wK3mN"
    root = _repo(tmp_path, {"config.py": f'"""Settings."""\nDEBUG = False\nAPI_KEY = "{secret}"\n'})
    [finding] = secret_scanner.scan_secrets(root)[0]
    target = finding_validation.FindingTarget(finding, root, ["python"], None)

    result = _run(target, tmp_path / "work")

    assert result.status == ValidationStatus.PASS
    final = "\n".join(e.replacement for e in result.final_fix.edits)
    assert 'API_KEY = os.environ.get("API_KEY", "")' in final and "import os" in final
    assert secret not in (tmp_path / "work" / "attempt-1" / "config.py").read_text(encoding="utf-8")
    assert secret not in secret_scanner.mask_secrets(f'API_KEY = "{secret}"')


def test_no_fix_available_is_inconclusive(tmp_path):
    root = _repo(tmp_path, {"app.js": JS_APP})
    finding = _js_finding(root, "(AI enhancement unavailable — set GROQ_API_KEY for detailed fixes)")
    result = _run(finding_validation.FindingTarget(finding, root, ["javascript"], FakeScanner()), tmp_path / "work")
    assert result.status == ValidationStatus.INCONCLUSIVE and result.stop_reason == "no_fix" and not result.attempts


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_javascript_syntax_errors_are_caught(tmp_path):
    root = _repo(tmp_path, {"app.js": JS_APP})
    finding = _js_finding(root, 'db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (err, rows) => res.json(rows);')
    [a] = _run(finding_validation.FindingTarget(finding, root, ["javascript"], FakeScanner()), tmp_path / "work").attempts
    assert a.status == ValidationStatus.FAIL
    assert {c.name: c.status for c in a.checks}["syntax"] == "failed"
