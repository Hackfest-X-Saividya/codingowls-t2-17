"""Post-fix validation loop: outcomes, retries and isolation."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from models.schemas import ChainFix, FixEdit, ValidationStatus
from services import fix_planner, fix_validation
from utils import sandbox

from conftest import FakeScanner, baseline_for, chain_at


def edit(root: Path, old: str, new: str, file: str = "app.py") -> FixEdit:
    """Replace the line whose stripped text is `old` (keeping its indentation) with `new`."""
    lines = (root / file).read_text(encoding="utf-8").split("\n")
    i = next(n for n, line in enumerate(lines, 1) if line.strip() == old)
    indent = lines[i - 1][: len(lines[i - 1]) - len(lines[i - 1].lstrip())]
    return FixEdit(file=file, start_line=i, end_line=i, original=lines[i - 1],
                   replacement="\n".join(indent + part for part in new.split("\n")))


def param_login(root: Path) -> list[FixEdit]:
    return [
        edit(root, "query = f\"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'\"",
             'query = "SELECT id FROM users WHERE username = ? AND password = ?"'),
        edit(root, "cursor.execute(query)", "cursor.execute(query, (username, password))"),
    ]


def param_audit(root: Path) -> list[FixEdit]:
    return [edit(root, "cursor.execute(f\"INSERT INTO audit (username) VALUES ('{username}')\")",
                 'cursor.execute("INSERT INTO audit (username) VALUES (?)", (username,))')]


def run_loop(base, chain, work: Path, edits=None, max_attempts=1, scanner=None):
    first = fix_validation.developer_fix(edits, chain, base.root) if edits else None
    return asyncio.run(fix_validation.run_chain_loop(
        chain, base, work, max_attempts, scanner=scanner or FakeScanner(), first_fix=first))


def check(attempt, name):
    return next(c for c in attempt.checks if c.name == name)


# 4. A fix that breaks the chain
def test_fix_that_breaks_the_chain_passes(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    other = chain_at(base, "login", 1)

    result = run_loop(base, chain, tmp_path / "work", param_login(root) + param_audit(root))

    assert result.status == ValidationStatus.PASS and not result.needs_manual_review
    [a] = result.attempts
    assert (a.weakness_addressed, a.path_broken, a.risk_eliminated) == (True, True, True)
    assert check(a, "reproduce_original").status == "passed"
    assert check(a, "alternative_paths").status == "passed"
    assert check(a, "scanner_recheck").status == "passed"
    assert a.other_chains == {other.id: "broken"}
    assert "within the scope" in a.summary and "no exploit was executed" in a.scope
    assert "?" in a.diff and a.original_preserved


# 5. One weakness fixed, another path to the same outcome left open
def test_fix_leaving_alternative_path_fails(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)

    result = run_loop(base, chain, tmp_path / "work", param_login(root))

    [a] = result.attempts
    assert result.status == ValidationStatus.FAIL
    # Removing the weakness and breaking the path are not the same as removing the risk
    assert a.weakness_addressed is True and a.path_broken is True and a.risk_eliminated is False
    assert check(a, "reproduce_original").status == "passed"
    alt = check(a, "alternative_paths")
    assert alt.status == "failed" and any(e.line == 26 for e in alt.evidence)
    assert any(p.endswith("(alternative path)") for p in a.remaining_paths)
    assert "same risk is still reachable" in a.summary


# 6. The vulnerability is gone, but the change breaks something
@pytest.mark.parametrize("breakage, expected", [
    (lambda r: [edit(r, 'return "ok"', 'return escape("ok")')], "name 'escape' is used but never defined"),
    (lambda r: [edit(r, '@app.route("/search")', "")], "route GET /search was removed"),
])
def test_fix_with_regression_fails(make_repo, tmp_path, breakage, expected):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)

    result = run_loop(base, chain, tmp_path / "work", param_login(root) + param_audit(root) + breakage(root))

    [a] = result.attempts
    assert result.status == ValidationStatus.FAIL
    assert check(a, "reproduce_original").status == "passed", "the vulnerability itself is fixed"
    assert check(a, "regression_static").status == "failed"
    assert any(expected in r for r in a.regressions)
    assert "regression" in a.summary


def test_fix_that_does_not_parse_fails_without_claiming_anything(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    broken = [edit(root, "cursor.execute(query)", "cursor.execute(query, (username, password)")]

    [a] = run_loop(base, chain, tmp_path / "work", broken).attempts
    assert a.status == ValidationStatus.FAIL
    assert check(a, "syntax").status == "failed"
    assert check(a, "reproduce_original").status == "error"
    assert a.path_broken is None and a.risk_eliminated is None


# 7. A new vulnerability introduced by the fix
def test_new_vulnerability_extending_the_chain(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    sneaky = [
        edit(root, "import sqlite3", "import os\nimport sqlite3"),
        edit(root, "user = cursor.fetchone()", 'user = cursor.fetchone()\nos.system(f"logger login {username}")'),
    ]

    [a] = run_loop(base, chain, tmp_path / "work", param_login(root) + param_audit(root) + sneaky).attempts
    assert a.status == ValidationStatus.NEW_VULNERABILITY
    assert a.risk_eliminated is True, "the original SQL chain is broken"
    [issue] = a.new_issues  # the scanner hit on the same line is not double-counted
    assert issue.origin == "dataflow" and "command injection" in issue.description
    assert issue.relation == "extends_chain" and issue.chain_id in {c.id for c in base.chains}


def test_new_vulnerability_in_unrelated_code_is_a_new_chain(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    new_route = edit(root, "return str(cursor.fetchall())", "return str(cursor.fetchall())")
    new_route.replacement += '\n\n\n@app.route("/calc")\ndef calc():\n    return str(eval(request.args.get("expr", "0")))'

    [a] = run_loop(base, chain, tmp_path / "work", param_login(root) + param_audit(root) + [new_route]).attempts
    assert a.status == ValidationStatus.NEW_VULNERABILITY
    [issue] = [i for i in a.new_issues if i.origin == "dataflow"]
    assert issue.relation == "new_chain" and "code injection" in issue.description


# 8. Inconclusive when evidence or execution is missing
def test_inconclusive_when_required_scanner_cannot_run(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    assert chain.finding_ids, "the chain has scanner evidence, so the re-check is required"

    result = run_loop(base, chain, tmp_path / "work", param_login(root) + param_audit(root),
                      scanner=FakeScanner(error="semgrep: network unreachable"))
    [a] = result.attempts
    assert result.status == ValidationStatus.INCONCLUSIVE and result.needs_manual_review
    assert check(a, "scanner_recheck").status == "error"
    assert check(a, "reproduce_original").status == "passed", "flow evidence alone is not enough here"


def test_inconclusive_when_patch_is_stale(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    stale = param_login(root)
    stale[1].original = "    cursor.execute(other_query)"

    [a] = run_loop(base, chain, tmp_path / "work", stale).attempts
    assert a.status == ValidationStatus.INCONCLUSIVE
    assert check(a, "apply_patch").status == "error" and "stale" in check(a, "apply_patch").detail
    assert a.original_preserved


def test_inconclusive_without_any_fix_or_open_path(make_repo, tmp_path):
    root = make_repo("chain_app")
    base = baseline_for(root)

    # The helper's `execute(sql)` has no template rewrite and AI is off: nothing is claimed
    result = run_loop(base, chain_at(base, "run_query"), tmp_path / "w1")
    assert result.status == ValidationStatus.INCONCLUSIVE and not result.attempts
    assert "No automated fix" in result.message

    # A mitigated chain has no open path to reproduce
    result = run_loop(base, chain_at(base, "ping", kind="command_injection"), tmp_path / "w2")
    assert result.status == ValidationStatus.INCONCLUSIVE and "nothing to reproduce" in result.message


# 9. Retries use the latest evidence and stop at the limit
def test_retry_uses_failure_evidence(make_repo, tmp_path):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)

    result = run_loop(base, chain, tmp_path / "work", max_attempts=3)  # suggested fixes only

    first, second = result.attempts
    assert first.status == ValidationStatus.FAIL and first.fix.origin == "template"
    assert first.remaining_signatures, "the open alternative path is recorded for the next suggestion"
    assert second.status == ValidationStatus.PASS
    assert "Attempt 1 left these paths open" in second.fix.rationale
    assert result.status == ValidationStatus.PASS

    # The second attempt builds on the first one's code: it only changes what was still missing
    assert all("INSERT INTO audit" in e.original for e in second.fix.edits)
    assert "-    cursor.execute(query)" not in second.diff and "INSERT INTO audit" in second.diff
    # ...and the final code contains both corrections, unlike the first suggestion
    final = "\n".join(e.replacement for e in result.final_fix.edits)
    assert "cursor.execute(query, (username, password))" in final
    assert 'cursor.execute("INSERT INTO audit (username) VALUES (?)", (username,))' in final.replace("'", '"')
    assert result.final_fix.edits != first.fix.edits and result.best_attempt == 2
    assert "+    cursor.execute(query, (username, password))" in result.final_diff


def _cosmetic_fixes(monkeypatch, suggested: list):
    """Every suggestion is new but changes nothing that matters."""
    async def useless_fix(chain, analysis, root_, history, use_ai):
        n = len(history) + 1
        line = (root_ / "app.py").read_text(encoding="utf-8").split("\n")[0]
        fix = ChainFix(strategy=f"cosmetic {n}", break_point=chain.direct_weaknesses[0], origin="template",
                       edits=[FixEdit(file="app.py", start_line=1, end_line=1, original=line,
                                      replacement=f"# attempt {n}\n{line}")])
        suggested.append(fix)
        return fix
    monkeypatch.setattr(fix_planner, "next_fix", useless_fix)


def test_stops_early_when_progress_stalls(make_repo, tmp_path, monkeypatch):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    suggested: list = []
    _cosmetic_fixes(monkeypatch, suggested)

    result = run_loop(base, chain, tmp_path / "work", max_attempts=5)

    assert len(result.attempts) == 2, "the second revision made no progress, so the loop stops"
    assert result.stop_reason == "stalled" and result.needs_manual_review
    first, second = result.attempts
    assert first.progress_score == second.progress_score > 0 and second.improved is False
    assert result.best_attempt == 1


def test_attempt_limit_while_still_improving(make_repo, tmp_path, monkeypatch):
    root = make_repo("fix_app")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    suggested: list = []
    _cosmetic_fixes(monkeypatch, suggested)
    real = fix_validation.ChainTarget.evaluate

    async def improving(self, fix, n, *args, **kwargs):
        a = await real(self, fix, n, *args, **kwargs)
        a.remaining_paths = ["x"] * max(0, 6 - n)  # fewer open paths each time
        return a

    monkeypatch.setattr(fix_validation.ChainTarget, "evaluate", improving)
    result = run_loop(base, chain, tmp_path / "work", max_attempts=3)
    assert len(result.attempts) == 3 and result.stop_reason == "limit"
    assert all(a.improved for a in result.attempts)
    assert result.best_attempt == 3 and len({fix_planner._edits_key(f.edits) for f in suggested}) == 3

    result = run_loop(base, chain, tmp_path / "work2", max_attempts=9)
    assert len(result.attempts) == 5, "hard cap of 5 attempts"


def test_attempt_stats_advice():
    from models.schemas import FixValidation, ValidationAttempt

    def v(n_attempts, status, reason, improved=False):
        attempts = [ValidationAttempt(attempt=i, fix=ChainFix(strategy="s", break_point="op"), status=status,
                                      summary="", improved=improved) for i in range(1, n_attempts + 1)]
        return FixValidation(id="v", scan_id="s", chain_id="c", state="complete", status=status,
                             attempts=attempts, stop_reason=reason)

    early = [v(1, ValidationStatus.PASS, "passed")] * 6 + [v(2, ValidationStatus.PASS, "passed")] * 3 + [
        v(3, ValidationStatus.PASS, "passed")]
    stats = fix_validation.attempt_stats(early, 3)
    assert stats["by_attempt"][0]["passed"] == 6 and stats["by_attempt"][1]["cumulative_pass_rate"] == 0.9
    assert "unlikely to help" in stats["advice"]

    struggling = [v(1, ValidationStatus.PASS, "passed")] * 3 + [v(3, ValidationStatus.FAIL, "limit", improved=True)] * 4
    assert "may help" in fix_validation.attempt_stats(struggling, 3)["advice"]
    assert "Not enough" in fix_validation.attempt_stats(early[:2], 3)["advice"]


def test_retry_stops_when_no_new_suggestion_exists(make_repo, tmp_path):
    root = make_repo("chain_app")
    base = baseline_for(root)
    chain = chain_at(base, "run_query")
    noop = [edit(root, "def get_db():", "def get_db():  # reviewed")]

    result = run_loop(base, chain, tmp_path / "work", noop, max_attempts=4)
    assert len(result.attempts) == 1 and result.status == ValidationStatus.FAIL
    assert "No new fix could be derived" in result.message


HELLO_APP = (
    "from flask import Flask, request\napp = Flask(__name__)\n\n"
    "@app.route('/hello')\ndef hello():\n    name = request.args.get('name', '')\n    return f\"Hello {name}\"\n"
)


def _hello(tmp_path: Path) -> Path:
    root = tmp_path / "hello" / "original"
    root.mkdir(parents=True)
    (root / "app.py").write_text(HELLO_APP, encoding="utf-8")
    return root


def test_linked_rule_still_matching_the_edited_sink_is_conflicting_evidence(tmp_path):
    """Escaping blocks the flow, but the pattern rule still fires on the edited line: not a 'new' finding."""
    root = _hello(tmp_path)
    base = baseline_for(root)
    [chain] = base.chains
    escaped = [edit(root, "from flask import Flask, request", "from flask import Flask, request\nfrom markupsafe import escape"),
               edit(root, 'return f"Hello {name}"', 'return f"Hello {escape(name)}"')]

    [a] = run_loop(base, chain, tmp_path / "work", escaped).attempts
    assert a.status == ValidationStatus.INCONCLUSIVE
    assert check(a, "reproduce_original").status == "passed"
    assert check(a, "scanner_recheck").status == "failed"
    assert not a.new_issues, "the same rule at the same sink is the linked finding persisting, not a new issue"
    assert "Conflicting evidence" in a.summary


def test_import_removed_from_current_library_is_a_regression(tmp_path):
    root = _hello(tmp_path)
    base = baseline_for(root)
    [chain] = base.chains
    old_api = [edit(root, "from flask import Flask, request", "from flask import Flask, request, escape"),
               edit(root, 'return f"Hello {name}"', "return 'Hello ' + escape(name)")]

    [a] = run_loop(base, chain, tmp_path / "work", old_api).attempts
    assert a.status == ValidationStatus.FAIL
    assert any("flask.escape" in r and "ImportError" in r for r in a.regressions)


def test_suggested_xss_fix_uses_an_autoescaped_template_and_passes(tmp_path):
    root = _hello(tmp_path)
    base = baseline_for(root)
    [chain] = base.chains
    result = run_loop(base, chain, tmp_path / "work")
    assert result.status == ValidationStatus.PASS
    assert "render_template_string('Hello {{ name }}', name=name)" in result.attempts[0].diff


def test_files_with_a_utf8_bom_are_analysed_and_patched(tmp_path):
    """Windows editors often save with a BOM; Python accepts it, so must we, and the patch keeps it."""
    root = tmp_path / "bom" / "original"
    root.mkdir(parents=True)
    (root / "app.py").write_bytes(b"\xef\xbb\xbf" + HELLO_APP.encode("utf-8"))
    base = baseline_for(root)
    [chain] = base.chains
    assert chain.fix.edits

    result = run_loop(base, chain, tmp_path / "work")
    assert result.status == ValidationStatus.PASS
    assert (tmp_path / "work" / "attempt-1" / "app.py").read_bytes().startswith(b"\xef\xbb\xbf")


def test_merging_retry_edits_never_mutates_history():
    dev = FixEdit(file="app.py", start_line=5, end_line=5, original="    return x", replacement="    return x.strip()")
    imp = FixEdit(file="app.py", start_line=1, end_line=1, original="import os", replacement="import os\nimport json")
    template = FixEdit(file="app.py", start_line=5, end_line=5, original="    return x", replacement="    return escape(x)")
    imp2 = FixEdit(file="app.py", start_line=1, end_line=1, original="import os", replacement="import os\nfrom markupsafe import escape")

    merged = fix_planner._merge_edits([dev, imp], [template, imp2])

    assert dev.replacement == "    return x.strip()" and imp.replacement == "import os\nimport json"
    by_line = {e.start_line: e.replacement for e in merged}
    assert by_line[5] == "    return escape(x)", "the newer edit for the same range supersedes the failed one"
    assert by_line[1] == "import os\nimport json\nfrom markupsafe import escape", "insertions are combined"
    partial = FixEdit(file="app.py", start_line=4, end_line=5, original="", replacement="")
    assert fix_planner._merge_edits([dev], [partial]) is None


# 10. The original code is preserved and fixes stay in the sandbox
def test_original_is_preserved_and_fix_is_isolated(make_repo, tmp_path):
    root = make_repo("fix_app")
    before = sandbox.tree_hashes(root)
    original_text = (root / "app.py").read_text(encoding="utf-8")
    base = baseline_for(root)
    chain = chain_at(base, "login", 0)
    work = tmp_path / "work"

    result = run_loop(base, chain, work, max_attempts=3)

    assert sandbox.tree_hashes(root) == before
    assert (root / "app.py").read_text(encoding="utf-8") == original_text
    assert all(a.original_preserved for a in result.attempts)
    patched = (work / "attempt-2" / "app.py").read_text(encoding="utf-8")
    assert "cursor.execute(query, (username, password))" in patched and patched != original_text


@pytest.mark.parametrize("path", ["../outside.py", "..\\outside.py", "C:/Windows/evil.py", "/etc/passwd"])
def test_patch_cannot_escape_the_sandbox(make_repo, tmp_path, path):
    root = make_repo("fix_app")
    with pytest.raises(fix_validation.PatchError):
        fix_validation.apply_fix(root, tmp_path / "attempt", [FixEdit(file=path, start_line=1, end_line=1, replacement="x")])
    assert not (root.parent / "outside.py").exists()
