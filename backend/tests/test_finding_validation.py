"""Fix validation for single findings: code in any language, dependencies and secrets."""
from __future__ import annotations

import asyncio
import json
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


def _npm_project(tmp_path: Path, copies: dict[str, str]) -> Path:
    """An npm project in web/ whose lockfile holds `copies` (lockfile key -> version)."""
    deps = {"lodash": "^4.17.0", "express": "^4.18.0"}
    lock = {"name": "web", "lockfileVersion": 3,
            "packages": {"": {"name": "web", "dependencies": deps}, **{k: {"version": v} for k, v in copies.items()}}}
    root = tmp_path / "repo"
    (root / "web").mkdir(parents=True)
    (root / "README.md").write_text("demo\n")
    (root / "web/package.json").write_text(json.dumps({"name": "web", "dependencies": deps}, indent=2) + "\n")
    (root / "web/package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
    return root


def _name(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def _fake_npm(work: Path) -> bool:
    """Stands in for `npm install --package-lock-only`: every range resolves to its minimum version.
    Overrides keyed "name@^M" apply only to copies of major version M, as npm's do."""
    pkg = json.loads((work / "package.json").read_text())
    lock = json.loads((work / "package-lock.json").read_text())
    lock["packages"][""]["dependencies"] = pkg["dependencies"]
    for key, entry in lock["packages"].items():
        name, major = _name(key), entry.get("version", "").split(".")[0]
        if key == f"node_modules/{name}" and name in pkg["dependencies"]:
            entry["version"] = pkg["dependencies"][name].lstrip("^")
        for spec, rng in pkg.get("overrides", {}).items():
            o_name, _, o_major = spec.partition("@^")
            if key and o_name == name and o_major in ("", major):
                entry["version"] = rng.lstrip("^")
    (work / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
    return True


def _npm_osv(fixed: dict[str, list[str]]):
    """OSV stand-in: a copy is affected when a fixed version of its major line is newer than it."""
    async def scan(repo: Path):
        lock = json.loads((repo / "web/package-lock.json").read_text())
        out = []
        for key, entry in lock["packages"].items():
            name, version = _name(key), entry.get("version", "")
            fix = next((f for f in fixed.get(name, []) if f.split(".")[0] == version.split(".")[0]
                        and _vt(version) < _vt(f)), None)
            if key and fix:
                out.append(Vulnerability(id=f"dep_{len(out) + 1:03d}", title=f"{name} {version}", severity="high",
                                         scanner_severity="high", file="web/package-lock.json", line=1,
                                         rule_id=f"GHSA-{name}", category=FindingCategory.DEPENDENCY, package=name,
                                         installed_version=version, fixed_version=fix))
        return out, []
    return scan


def _vt(v: str) -> tuple:
    return tuple(int(p) for p in v.split("."))


def _validate_npm(tmp_path, monkeypatch, copies: dict[str, str], fixed: dict[str, list[str]]):
    root = _npm_project(tmp_path, copies)
    scan = _npm_osv(fixed)
    monkeypatch.setattr(dependency_scanner, "scan_dependencies", scan)
    monkeypatch.setattr(finding_validation, "_npm_lock_only", _fake_npm)
    finding = asyncio.run(scan(root))[0][0]
    result = _run(finding_validation.FindingTarget(finding, root, ["javascript"], None, all_findings=[finding]),
                  tmp_path / "work")
    assert result.status == ValidationStatus.PASS, result.message
    files = {e.file for e in result.final_fix.edits}
    assert files == {"web/package.json", "web/package-lock.json"}, "both files change, with repo-relative paths"
    fix_validation.apply_fix(root, tmp_path / "out", result.final_fix.edits)
    assert "overrides" not in (root / "web/package.json").read_text(), "the scanned code is never written"
    return result, json.loads((tmp_path / "out/web/package.json").read_text())


def test_npm_direct_dependency_gets_a_new_range(tmp_path, monkeypatch):
    _, manifest = _validate_npm(tmp_path, monkeypatch, {"node_modules/lodash": "4.17.20"}, {"lodash": ["4.17.21"]})
    assert manifest["dependencies"]["lodash"] == "^4.17.21" and "overrides" not in manifest


def test_npm_transitive_dependency_is_overridden(tmp_path, monkeypatch):
    _, manifest = _validate_npm(tmp_path, monkeypatch, {"node_modules/qs": "6.11.0"}, {"qs": ["6.14.1"]})
    assert manifest["overrides"] == {"qs@^6": "^6.14.1"}


def test_npm_override_fixes_each_major_version_separately(tmp_path, monkeypatch):
    """dvws-node: brace-expansion 1.x (most packages) and 2.x (minimatch 5) are both affected.
    One override for every copy would force minimatch onto 1.x; each major line gets its own."""
    result, manifest = _validate_npm(
        tmp_path, monkeypatch,
        {"node_modules/brace-expansion": "1.1.12", "node_modules/minimatch/node_modules/brace-expansion": "2.0.2"},
        {"brace-expansion": ["1.1.17", "2.1.7"]})
    assert len(result.attempts) == 2, "the 2.x copy is found by the re-check and fixed in the next revision"
    assert manifest["overrides"] == {"brace-expansion@^1": "^1.1.17", "brace-expansion@^2": "^2.1.7"}


def test_dependency_without_a_fixed_version_says_so(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "flask==0.12\n"})
    finding = Vulnerability(id="dep_001", title="flask", severity="high", scanner_severity="high",
                            file="requirements.txt", line=1, rule_id="GHSA-x", category=FindingCategory.DEPENDENCY,
                            package="flask", installed_version="0.12", fixed_version=None)
    result = _run(finding_validation.FindingTarget(finding, root, ["python"], None), tmp_path / "work")
    assert result.status == ValidationStatus.INCONCLUSIVE and result.stop_reason == "no_fix"
    assert "No fixed version of flask" in result.message


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
