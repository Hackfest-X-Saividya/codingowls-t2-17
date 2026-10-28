"""Chain-of-weakness analysis: detection, relationships, and no invented links."""
from __future__ import annotations

from models.schemas import FindingCategory, Vulnerability
from services import chain_analysis, flow_analyzer

from conftest import baseline_for, chain_at, fake_findings


def _nodes(chain, kind=None):
    return [n for n in chain.nodes if kind is None or n.kind == kind]


def _edge(chain, source_prefix, target_prefix):
    return [e for e in chain.edges if e.source.startswith(source_prefix) and e.target.startswith(target_prefix)]


# 1. A vulnerability that needs several connected weaknesses
def test_detects_chain_with_multiple_connected_weaknesses(make_repo):
    root = make_repo("chain_app")
    base = baseline_for(root)
    chain = chain_at(base, "run_query")

    # One sensitive operation reached through two routes: a branching chain
    entries = {n.label for n in _nodes(chain, "entry_point")}
    assert entries == {"GET /admin/users", "GET /report"}
    assert len(chain.paths) == 2
    assert all(p[-2].startswith("op:") and p[-1] == "impact:sql_injection" for p in chain.paths)

    labels = {n.id.split(":")[0] + ":" + n.id.split(":")[1]: n for n in chain.nodes}
    # Contributing weaknesses on different paths
    assert "weak:secretkey" in labels, "hardcoded session key should weaken the admin session check"
    assert "cond:noauth" in labels, "/report has no authentication"
    assert any(n.kind == "security_control" and "blocklist" in n.label for n in chain.nodes), "weak quote check"
    assert any(n.kind == "weakness" and n.id.startswith("weak:novalidation") for n in chain.nodes)

    # The open /report path makes it likely exploitable, and it is prioritised as such
    assert chain.exploitability == "likely"
    assert chain.severity == "critical"
    assert chain.priority >= 70
    assert chain.direct_weaknesses == [n.id for n in chain.nodes if n.kind == "sensitive_operation"]
    assert set(chain.contributing_weaknesses) >= {n.id for n in chain.nodes if n.id.startswith(("weak:", "cond:"))}
    assert any("hardcoded key" in c for c in chain.conditions)
    assert any("helper function" in u for u in chain.uncertainty), "interprocedural step must be disclosed"


# 2. Relationships are the right ones, with evidence and confidence
def test_relationships_carry_evidence_and_status(make_repo):
    root = make_repo("chain_app")
    base = baseline_for(root)
    chain = chain_at(base, "run_query")

    # secret key -> session check -> admin entry: confirmed, same file, with code and inference evidence
    [key_edge] = _edge(chain, "weak:secretkey", "ctrl:auth")
    assert key_edge.status == "confirmed"
    kinds = {e.kind.value for e in key_edge.evidence}
    assert {"code_pattern", "inferred"} <= kinds
    assert any(e.line == 20 for e in key_edge.evidence)  # app.secret_key = "..."
    assert _edge(chain, "ctrl:auth", "entry:app.py:admin_users")

    # input -> operation: static data flow through the helper, line by line
    reach = [e for e in chain.edges if e.target.startswith("op:") and e.relation == "attacker-controlled value reaches"]
    assert len(reach) == 2
    for e in reach:
        assert e.status == "confirmed"
        assert 0 < e.confidence < 1
        notes = [ev.description for ev in e.evidence if ev.kind.value == "static_dataflow"]
        assert any("passed to run_query(sql)" in n for n in notes)
        assert notes[-1] == "reaches cursor.execute"

    # The linked scanner finding sits on the path and is of the same class
    op = next(n for n in chain.nodes if n.kind == "sensitive_operation")
    assert op.line == 30 and op.finding_ids, "fake SQL rule on `cursor.execute(sql)` should corroborate"


def test_blocking_control_marks_chain_mitigated(make_repo):
    root = make_repo("chain_app")
    base = baseline_for(root)
    chain = chain_at(base, "ping", kind="command_injection")
    assert chain.exploitability == "mitigated"
    assert chain.severity == "low"
    ctrl = next(n for n in chain.nodes if n.kind == "security_control" and n.role == "control")
    assert "fullmatch" in ctrl.label
    assert any(e.relation == "blocked before reaching" for e in chain.edges)


# 3. No relationship without evidence
def test_does_not_link_unrelated_findings(make_repo):
    root = make_repo("chain_app")
    findings = fake_findings(root) + [
        Vulnerability(id="sec_001", title="Hardcoded API token", severity="high", scanner_severity="high",
                      file="app.py", line=21, rule_id="secret/generic-token", category=FindingCategory.SECRET),
        Vulnerability(id="dep_001", title="requests: header leak", severity="medium", scanner_severity="medium",
                      file="requirements.txt", line=1, rule_id="osv/GHSA-x", category=FindingCategory.DEPENDENCY,
                      package="requests", installed_version="2.0.0"),
    ]
    base = baseline_for(root, findings)
    linked = {fid for c in base.chains for fid in c.finding_ids}

    debug = next(v for v in findings if v.rule_id.endswith("debug-enabled"))
    assert debug.id not in linked, "debug=True has no data-flow relationship to any chain"
    assert "sec_001" not in linked, "an API token is not the session key"
    assert "dep_001" not in linked, "no chain calls into requests"

    # A parameter-free query is not a chain, even in a file full of SQL chains
    assert not any(c.function == "health" for c in base.chains)

    # JWT auth does not use the session cookie: the hardcoded session key must not attach
    token = chain_at(base, "token_report")
    assert not any(n.id.startswith("weak:secretkey") for n in token.nodes)
    assert any(n.kind == "security_control" and "decorator" in n.label for n in token.nodes)
    assert token.exploitability == "possible", "auth required and not bypassable"


def test_dependency_link_is_only_a_hypothesis(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
        "@app.route('/import', methods=['POST'])\ndef imp():\n    return str(yaml.load(request.get_data()))\n",
        encoding="utf-8")
    dep = Vulnerability(id="dep_001", title="PyYAML arbitrary code execution", severity="critical",
                        scanner_severity="critical", file="requirements.txt", line=1, rule_id="osv/PYSEC-1",
                        category=FindingCategory.DEPENDENCY, package="PyYAML", installed_version="5.3")
    analysis = flow_analyzer.analyze_repository(tmp_path)
    [chain] = chain_analysis.build_chains(analysis, [dep], tmp_path)
    [edge] = [e for e in chain.edges if e.source == "dep:PyYAML"]
    assert edge.status == "hypothesis" and edge.confidence < 0.5
    assert any("Link to vulnerable dependency" in u for u in chain.uncertainty)


def test_every_chain_can_be_found_again_by_its_signature(make_repo, tmp_path):
    """Validation re-finds a chain in edited code by signature; this must hold for every sink kind."""
    hello = tmp_path / "hello"
    hello.mkdir()
    (hello / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n\n"
        "@app.route('/hello')\ndef hello():\n    name = request.args.get('name', '')\n"
        "    if not name:\n        return 'who?'\n    return f'Hello {name}'\n",
        encoding="utf-8")
    for root in (make_repo("chain_app"), make_repo("fix_app"), hello):
        base = baseline_for(root)
        for chain in base.chains:
            assert chain_analysis.flows_for_signature(base.analysis, chain.signature), chain.title
    [xss] = baseline_for(hello).chains
    assert xss.kind == "xss" and xss.signature["occurrence"] == "1", "second return of hello()"
    assert "render_template_string('Hello {{ name }}', name=name)" in "".join(e.replacement for e in xss.fix.edits)


def test_chains_have_plain_language_summaries(make_repo):
    base = baseline_for(make_repo("chain_app"))
    shared = chain_at(base, "run_query")
    assert shared.title == "SQL injection via GET /report"
    assert shared.summary.startswith("Anyone can send a request to GET /report.")
    assert "“team” parameter goes straight into a database query" in shared.summary
    assert "There are 2 ways in." in shared.summary
    ping = chain_at(base, "ping", kind="command_injection")
    assert "blocked today" in ping.summary
    for chain in base.chains:  # no code identifiers leak into the plain text
        assert "request." not in chain.summary and "cursor" not in chain.summary


def test_chain_aware_fix_targets_operation_and_lists_other_paths(make_repo):
    root = make_repo("fix_app")
    base = baseline_for(root)
    first = chain_at(base, "login", 0)
    fix = first.fix
    assert fix.break_point == first.direct_weaknesses[0]
    assert fix.edits and fix.origin == "template"
    assert "cursor.execute(query, (username, password))" in "".join(e.replacement for e in fix.edits)
    # The audit insert in the same endpoint is another path to the same outcome
    assert any("same sql injection" in p for p in fix.remaining_paths)
    assert any("Alternative paths" in t for t in fix.tests)
