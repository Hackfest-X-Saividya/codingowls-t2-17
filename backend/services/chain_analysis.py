"""Chain-of-weakness analysis: connect findings into evidence-backed attack chains.

A chain is built around one sensitive operation (a sink) and contains every
path that reaches it:

    [no auth / auth control <- hardcoded session key]
            -> entry point -> untrusted input -> [missing | weak | blocking validation]
            -> sensitive operation <- [vulnerable dependency] -> impact

Relationships come only from evidence, never from co-location:
- input -> operation edges need a static data-flow path (flow_analyzer)
- a scanner finding is attached only if it sits on a line of that path and its
  rule matches the operation's vulnerability class
- a hardcoded secret key is linked only to endpoints whose authentication relies
  on the signed session cookie
- a vulnerable dependency is linked only when the operation calls into that
  package, and the edge stays a hypothesis (the advisory may not affect it)
Findings without such evidence stay standalone.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from models.schemas import (
    ChainEdge, ChainNode, Evidence, EvidenceKind, FindingCategory, Vulnerability, WeaknessChain,
)
from services.flow_analyzer import Control, Endpoint, Flow, FlowAnalysis


@dataclass(frozen=True)
class SinkClass:
    title: str
    weakness: str      # the direct weakness at the operation
    impact: str
    score: int         # 0-10 potential impact
    rule_pattern: str  # scanner rule ids / titles of the same class


SINK_CLASSES: dict[str, SinkClass] = {
    "sql_injection": SinkClass("SQL injection", "SQL query built from untrusted data",
                               "Read or modify database contents and bypass login checks", 9, r"sql|sqli"),
    "command_injection": SinkClass("OS command injection", "Shell command built from untrusted data",
                                   "Run arbitrary commands on the server (remote code execution)", 10,
                                   r"subprocess|command|shell|os[-_.]system|popen|exec"),
    "code_injection": SinkClass("Code injection", "Untrusted data evaluated as Python code",
                                "Execute arbitrary Python code in the application process", 10, r"eval|exec|code[-_]injection"),
    "deserialization": SinkClass("Insecure deserialization", "Untrusted data deserialized with an unsafe loader",
                                 "Execute arbitrary code while deserializing attacker data", 10,
                                 r"pickle|deserial|yaml|marshal"),
    "path_traversal": SinkClass("Path traversal", "File path built from untrusted data",
                                "Read, overwrite or delete files outside the intended directory", 7,
                                r"path|traversal|send[-_]file|open|file"),
    "template_injection": SinkClass("Server-side template injection", "Template source built from untrusted data",
                                    "Execute code through the template engine (SSTI) and inject HTML", 9,
                                    r"template|ssti|render|raw[-_]html|jinja"),
    "ssrf": SinkClass("Server-side request forgery", "Outbound request URL taken from untrusted data",
                      "Make the server send requests to internal services", 7, r"ssrf|request|urlopen"),
    "open_redirect": SinkClass("Open redirect", "Redirect target taken from untrusted data",
                               "Send users to attacker-controlled sites (phishing)", 4, r"redirect"),
    "xss": SinkClass("Reflected cross-site scripting", "HTML response built from untrusted data",
                     "Run attacker JavaScript in victims' browsers", 6,
                     r"xss|html|format[-_]string|directly[-_]returned|reflect"),
}

# Plain-language wording for non-specialists: (what the input reaches, what could happen)
PLAIN: dict[str, tuple[str, str]] = {
    "sql_injection": ("a database query", "An attacker could read, change or delete data, or log in as someone else."),
    "command_injection": ("a command the server runs", "An attacker could run any command on your server and take it over."),
    "code_injection": ("code the server executes", "An attacker could run their own code on your server."),
    "deserialization": ("an unsafe data loader", "An attacker could run their own code on your server by sending crafted data."),
    "path_traversal": ("a file path", "An attacker could read or overwrite files they should not have access to."),
    "template_injection": ("a page template", "An attacker could run code on your server through the template engine."),
    "ssrf": ("a web request the server makes", "An attacker could make your server contact internal systems for them."),
    "open_redirect": ("a redirect", "An attacker could send your users to a malicious website."),
    "xss": ("the page sent back to the browser", "An attacker could run scripts in other users' browsers and steal their accounts."),
}

# import name -> PyPI package, where they differ
MODULE_PACKAGES = {"yaml": "pyyaml", "jwt": "pyjwt", "bs4": "beautifulsoup4", "PIL": "pillow", "cv2": "opencv-python"}

EXPLOIT_FACTOR = {"likely": 1.0, "possible": 0.6, "mitigated": 0.15}
SEVERITIES = ["low", "medium", "high", "critical"]


def sink_key(flow: Flow) -> tuple[str, str, str, str]:
    return (flow.sink.file, flow.sink.function, flow.sink.callee, flow.sink.kind)


def occurrences(analysis: FlowAnalysis) -> dict[tuple[str, str, str], list[int]]:
    """Lines of every call to each sink callee, per function, tainted or not.

    The n-th `cursor.execute` in login() stays the n-th after a fix makes one of
    them safe, so a chain can be found again in edited code by its signature.
    """
    return {(file, fn, callee): sorted(lines)
            for file, facts in analysis.modules.items()
            for (fn, callee), lines in facts.sink_sites.items()}


def chain_signature(flow: Flow, occ: dict[tuple[str, str, str], list[int]]) -> dict[str, str]:
    file, fn, callee, kind = sink_key(flow)
    lines = occ.get((file, fn, callee), [flow.sink.line])
    return {"file": file, "function": fn, "callee": callee, "kind": kind,
            "occurrence": str(lines.index(flow.sink.line) if flow.sink.line in lines else 0)}


def flows_for_signature(analysis: FlowAnalysis, signature: dict[str, str]) -> list[Flow]:
    """Flows into the sink identified by `signature` (works on re-analysed, edited code).

    Empty when the call no longer receives untrusted data or no longer exists.
    """
    key = (signature["file"], signature["function"], signature["callee"], signature["kind"])
    lines = occurrences(analysis).get(key[:3], [])
    idx = int(signature.get("occurrence", "0"))
    if idx >= len(lines):
        return []
    return [f for f in analysis.flows if sink_key(f) == key and f.sink.line == lines[idx]]


def build_chains(
    analysis: FlowAnalysis,
    findings: list[Vulnerability],
    root: Optional[Path] = None,
) -> list[WeaknessChain]:
    """Build one chain per sensitive operation reached by untrusted data."""
    occ = occurrences(analysis)
    groups: dict[tuple, list[Flow]] = defaultdict(list)
    for f in analysis.flows:
        groups[sink_key(f) + (f.sink.line,)].append(f)

    chains = [_build_chain(flows, analysis, findings, occ) for flows in groups.values()]
    chains.sort(key=lambda c: (-c.priority, c.file, c.id))

    if root is not None:
        from services import fix_planner  # local import: fix_planner imports this module
        for chain in chains:
            chain.fix = fix_planner.plan_fix(chain, analysis, root)
    return chains


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, ChainNode] = {}
        self.edges: dict[tuple[str, str], ChainEdge] = {}

    def node(self, node: ChainNode) -> str:
        existing = self.nodes.get(node.id)
        if existing:
            existing.finding_ids = sorted(set(existing.finding_ids) | set(node.finding_ids))
        else:
            self.nodes[node.id] = node
        return node.id

    def edge(self, edge: ChainEdge) -> None:
        key = (edge.source, edge.target)
        existing = self.edges.get(key)
        if not existing:
            self.edges[key] = edge
            return
        # Same relationship seen on another path: keep the stronger claim, pool the evidence
        if edge.status == "confirmed" or edge.confidence > existing.confidence:
            existing.status, existing.confidence, existing.relation = edge.status, edge.confidence, edge.relation
        seen = {(e.kind, e.line, e.description) for e in existing.evidence}
        existing.evidence += [e for e in edge.evidence if (e.kind, e.line, e.description) not in seen]


def _build_chain(
    flows: list[Flow],
    analysis: FlowAnalysis,
    findings: list[Vulnerability],
    occ: dict[tuple, list[int]],
) -> WeaknessChain:
    first = flows[0]
    sink = first.sink
    cls = SINK_CLASSES[sink.kind]
    g = _Graph()
    uncertainty: list[str] = [
        "Paths come from static data-flow analysis; no exploit was executed against a running application.",
    ]
    conditions: list[str] = []
    controls: list[str] = []
    contributing: list[str] = []

    code_findings = [v for v in findings if v.category == FindingCategory.CODE and v.file == sink.file]
    rule_re = re.compile(cls.rule_pattern, re.I)

    def corroborating(lines: set[int]) -> list[Vulnerability]:
        return [v for v in code_findings if v.line in lines and rule_re.search(f"{v.rule_id} {v.title}")]

    all_lines = set().union(*(f.lines() for f in flows))
    op_findings = corroborating(all_lines)

    op = g.node(ChainNode(
        id=f"op:{sink.file}:{sink.line}", kind="sensitive_operation", role="direct",
        label=f"{cls.weakness} ({sink.callee})", detail=sink.code,
        file=sink.file, line=sink.line, finding_ids=[v.id for v in op_findings],
    ))
    impact = g.node(ChainNode(id=f"impact:{sink.kind}", kind="impact", role="impact",
                              label=cls.title, detail=cls.impact))

    paths: list[list[str]] = []
    path_scores: list[tuple[str, float, str]] = []  # (exploitability, confidence, reason)
    path_info: list[tuple[Flow, list[Endpoint], str, bool]] = []  # (flow, entries, access state, weak check)

    for flow in flows:
        entries = analysis.entries_for(flow)
        src = flow.source
        source_id = g.node(ChainNode(
            id=f"src:{src.file}:{src.line}:{_short_hash(src.expr)}", kind="untrusted_input", role="context",
            label=f"{src.kind}: {src.expr}", detail=src.code, file=src.file, line=src.line,
        ))

        # ----- entry side: endpoint, authentication, session key -----
        entry_ids: list[str] = []
        entry_state = "local" if not src.remote else "unknown"
        for ep in entries:
            entry_id, state = _entry(g, ep, analysis, findings, contributing, controls, conditions)
            entry_ids.append(entry_id)
            entry_state = _better_state(entry_state, state)
            g.edge(ChainEdge(
                source=entry_id, target=source_id, relation="accepts untrusted input", status="confirmed",
                confidence=0.95, evidence=[Evidence(kind=EvidenceKind.CODE_PATTERN, file=src.file, line=src.line,
                                                    code=src.code, description=f"{ep.function}() reads {src.expr}")],
            ))
        if src.remote and not entries:
            uncertainty.append(f"No HTTP route found for {flow.root}(); the input is request data but the entry point is unknown.")
            conditions.append(f"Attacker must reach {flow.root}() with control of {src.kind}")
        elif not src.remote:
            conditions.append(f"Attacker needs local control of the {src.kind}")

        # ----- validation between input and operation -----
        blocking = flow.blocking_controls
        weak = [c for c in flow.controls if not c.blocks(sink.kind)]
        if blocking:
            mid = _control_node(g, blocking[0], sink.kind, blocking=True)
            controls.append(f"{blocking[0].name} at {blocking[0].file}:{blocking[0].line} ({blocking[0].code})")
        elif weak:
            mid = _control_node(g, weak[-1], sink.kind, blocking=False)
            contributing.append(mid)
            conditions.append(f"Validation at line {weak[-1].line} ({weak[-1].name}) must be bypassed")
            uncertainty.append(
                f"Validation at {weak[-1].file}:{weak[-1].line} was graded '{weak[-1].strength}' heuristically; "
                "whether it can actually be bypassed was not tested.")
        else:
            mid = g.node(ChainNode(
                id=f"weak:novalidation:{src.file}:{src.line}:{_short_hash(src.expr)}:{sink.line}", kind="weakness",
                role="contributing", label=f"No validation of {src.expr} before {sink.callee}",
                detail=f"No sanitizer or validation check on the path from line {src.line} to line {sink.line}.",
                file=src.file, line=src.line,
            ))
            contributing.append(mid)
            conditions.append(f"{src.expr} reaches {sink.callee} (line {sink.line}) unvalidated")

        g.edge(ChainEdge(
            source=source_id, target=mid,
            relation="is checked by" if (blocking or weak) else "is used without validation",
            status="confirmed", confidence=0.9,
            evidence=[Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=c.file, line=c.line, code=c.code,
                               description=f"{c.kind}: {c.name} ({c.strength})") for c in flow.controls]
            or [Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=src.file, line=src.line, code=src.code,
                         description="no sanitizer or validation check on this path")],
        ))

        corroboration = corroborating(flow.lines())
        confidence = 0.9 - (0.3 if flow.assumed else 0) - 0.05 * len(flow.calls) + (0.05 if corroboration else 0)
        confidence = round(min(max(confidence, 0.1), 0.99), 2)
        evidence = [Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=s.file, line=s.line, code=s.code, description=s.note)
                    for s in flow.steps]
        evidence.append(Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=sink.file, line=sink.line, code=sink.code,
                                 description=f"reaches {sink.callee}"))
        evidence += [Evidence(kind=EvidenceKind.SCANNER, file=v.file, line=v.line, finding_id=v.id,
                              description=f"{v.source} rule {v.rule_id.split('.')[-1]} flags line {v.line}")
                     for v in corroboration]
        if flow.assumed:
            uncertainty.append("Part of a path goes through a call whose behaviour is unknown and was assumed to "
                               "preserve attacker control: " + "; ".join(s.note for s in flow.steps if s.assumed))
        if flow.calls:
            uncertainty.append(f"Path crosses helper function(s) {', '.join(flow.calls)}; followed within the module only.")
        g.edge(ChainEdge(
            source=mid, target=op,
            relation="blocked before reaching" if blocking else "attacker-controlled value reaches",
            status="hypothesis" if flow.assumed else "confirmed", confidence=confidence, evidence=evidence,
        ))

        for entry_id in entry_ids or [None]:
            paths.append([p for p in (entry_id, source_id, mid, op, impact) if p])

        path_info.append((flow, entries, entry_state, bool(weak)))
        if blocking:
            path_scores.append(("mitigated", confidence,
                                f"{blocking[0].name} at line {blocking[0].line} neutralises {cls.title.lower()} on this path."))
        else:
            path_scores.append(_path_exploitability(flow, entry_state, bool(weak), confidence, cls))

    # ----- dependency that implements the operation (hypothesis only) -----
    module = sink.callee.split(".")[0]
    package = MODULE_PACKAGES.get(module, module).lower().replace("_", "-")
    for dep in findings:
        if dep.category == FindingCategory.DEPENDENCY and (dep.package or "").lower().replace("_", "-") == package:
            dep_id = g.node(ChainNode(
                id=f"dep:{dep.package}", kind="weakness", role="contributing",
                label=f"Vulnerable dependency {dep.package} {dep.installed_version or ''}".strip(),
                detail=dep.title, file=dep.file, line=dep.line, finding_ids=[dep.id],
            ))
            contributing.append(dep_id)
            g.edge(ChainEdge(
                source=dep_id, target=op, relation="implements the sensitive operation", status="hypothesis",
                confidence=0.4, evidence=[
                    Evidence(kind=EvidenceKind.SCANNER, finding_id=dep.id, file=dep.file, line=dep.line,
                             description=f"{dep.source}: {dep.title}"),
                    Evidence(kind=EvidenceKind.INFERRED, file=sink.file, line=sink.line, code=sink.code,
                             description=f"{sink.callee} is provided by {dep.package}; whether the advisory "
                                         "affects this call was not verified"),
                ],
            ))
            uncertainty.append(f"Link to vulnerable dependency {dep.package} is a hypothesis.")

    unblocked_confirmed = any(e.target == op and e.status == "confirmed" and not e.relation.startswith("blocked")
                              for e in g.edges.values())
    g.edge(ChainEdge(
        source=op, target=impact, relation="enables", status="confirmed" if unblocked_confirmed else "hypothesis",
        confidence=0.85 if unblocked_confirmed else 0.5,
        evidence=[Evidence(kind=EvidenceKind.INFERRED, file=sink.file, line=sink.line, code=sink.code,
                           description=f"{sink.callee} with attacker-controlled input permits {cls.title.lower()}")],
    ))

    order = {"likely": 0, "possible": 1, "mitigated": 2}
    best_idx = min(range(len(path_scores)), key=lambda i: (order[path_scores[i][0]], -path_scores[i][1]))
    exploitability, best_conf, reason = path_scores[best_idx]
    level = SEVERITIES.index("critical" if cls.score >= 9 else "high" if cls.score >= 7 else "medium" if cls.score >= 5 else "low")
    if exploitability == "possible":
        level = max(level - 1, 0)
    elif exploitability == "mitigated":
        level = 0
    priority = round(cls.score * 10 * EXPLOIT_FACTOR[exploitability] * best_conf)

    signature = chain_signature(first, occ)
    # Name the chain after its most dangerous way in
    best_entries = path_info[best_idx][1]
    entry_label = best_entries[0].label if best_entries else next(
        (g.nodes[p[0]].label for p in paths if p and p[0].startswith("entry:")), f"{sink.function}()")
    finding_ids = sorted({fid for n in g.nodes.values() for fid in n.finding_ids})
    direct = [op]

    return WeaknessChain(
        id="chain_" + _short_hash("|".join(signature.values()), 10),
        title=f"{cls.title} via {entry_label}",
        summary=plain_summary(*path_info[best_idx], exploitability, len(flows), sink.kind, bool(keys_linked(g))),
        kind=sink.kind, file=sink.file, function=sink.function,
        impact=cls.impact, severity=SEVERITIES[level],
        exploitability=exploitability, exploitability_reason=reason, priority=priority,
        nodes=list(g.nodes.values()), edges=list(g.edges.values()), paths=_dedupe(paths),
        conditions=_dedupe_str(conditions), direct_weaknesses=direct,
        contributing_weaknesses=_dedupe_str(contributing), controls=_dedupe_str(controls),
        finding_ids=finding_ids, uncertainty=_dedupe_str(uncertainty), signature=signature,
    )


def _entry(
    g: _Graph, ep: Endpoint, analysis: FlowAnalysis, findings: list[Vulnerability],
    contributing: list[str], controls: list[str], conditions: list[str],
) -> tuple[str, str]:
    """Add the endpoint node and its access-control context; returns (node id, access state)."""
    entry_id = g.node(ChainNode(
        id=f"entry:{ep.file}:{ep.function}", kind="entry_point", role="context", label=ep.label,
        detail=f"{ep.framework} route handled by {ep.function}()", file=ep.file, line=ep.line,
    ))
    if not ep.auth:
        cond = g.node(ChainNode(
            id=f"cond:noauth:{ep.file}:{ep.function}", kind="condition", role="contributing",
            label=f"No authentication on {ep.label}",
            detail="No auth decorator, session/current_user check, before_request hook or auth dependency was found.",
            file=ep.file, line=ep.line,
        ))
        contributing.append(cond)
        conditions.append(f"Any client can send {ep.label} (no authentication found)")
        g.edge(ChainEdge(source=cond, target=entry_id, relation="lets any client reach", status="confirmed",
                         confidence=0.8, evidence=[Evidence(kind=EvidenceKind.CODE_PATTERN, file=ep.file, line=ep.line,
                                                            description="no access-control check found for this route")]))
        return entry_id, "open"

    auth = ep.auth[0]
    ctrl = g.node(ChainNode(
        id=f"ctrl:auth:{ep.file}:{ep.function}", kind="security_control", role="control",
        label=f"Authentication required ({auth.kind})", detail=auth.code, file=auth.file, line=auth.line,
    ))
    controls.append(f"Authentication ({auth.kind}) at {auth.file}:{auth.line}")
    g.edge(ChainEdge(source=ctrl, target=entry_id, relation="restricts access to", status="confirmed", confidence=0.8,
                     evidence=[Evidence(kind=EvidenceKind.CODE_PATTERN, file=auth.file, line=auth.line,
                                        code=auth.code, description=f"{auth.kind} access check")]))
    if not any(a.session_based for a in ep.auth):
        conditions.append(f"Attacker needs valid credentials for {ep.label}")
        return entry_id, "auth"

    # Session-cookie authentication is only as strong as the key that signs the cookie
    same_file = analysis.modules.get(ep.file)
    keys = [(k, True) for k in (same_file.secret_keys if same_file else [])]
    if not keys:
        keys = [(k, False) for m in analysis.modules.values() for k in m.secret_keys]
    if not keys:
        conditions.append(f"Attacker needs a valid session for {ep.label}")
        return entry_id, "auth"
    for key, same in keys[:2]:
        secret_findings = [v for v in findings if v.file == key.file and v.line == key.line
                           and (v.category == FindingCategory.SECRET or re.search(r"secret", v.rule_id, re.I))]
        key_id = g.node(ChainNode(
            id=f"weak:secretkey:{key.file}:{key.line}", kind="weakness", role="contributing",
            label=f"Hardcoded session signing key ({key.target})", detail=key.code, file=key.file, line=key.line,
            finding_ids=[v.id for v in secret_findings],
        ))
        contributing.append(key_id)
        evidence = [
            Evidence(kind=EvidenceKind.CODE_PATTERN, file=key.file, line=key.line, code=key.code,
                     description=f"{key.target} is a string literal in source control"),
            Evidence(kind=EvidenceKind.INFERRED, description="Flask signs the session cookie with this key; anyone "
                     "who knows it can forge a session that passes the session-based check"),
        ] + [Evidence(kind=EvidenceKind.SCANNER, finding_id=v.id, file=v.file, line=v.line,
                      description=f"{v.source} flags the hardcoded secret") for v in secret_findings]
        g.edge(ChainEdge(source=key_id, target=ctrl, relation="allows forging the session checked by",
                         status="confirmed" if same else "hypothesis", confidence=0.8 if same else 0.5, evidence=evidence))
    conditions.append(f"Session check on {ep.label} can be bypassed with a cookie forged using the hardcoded key")
    return entry_id, "bypassable" if keys[0][1] else "auth"


def _path_exploitability(flow: Flow, entry_state: str, weak: bool, confidence: float, cls: SinkClass) -> tuple[str, float, str]:
    where = f"{flow.source.expr} reaches {flow.sink.callee} at {flow.sink.file}:{flow.sink.line}"
    if flow.assumed:
        return "possible", confidence, f"{where}, but part of the path is assumed (unknown call). Not verified by execution."
    if weak:
        return "possible", confidence, f"{where} past validation that looks bypassable; bypass not demonstrated."
    if entry_state in ("open", "bypassable"):
        access = "without authentication" if entry_state == "open" else "behind a session check forgeable with the hardcoded key"
        return "likely", confidence, (f"Static data-flow shows {where} with no effective validation, reachable {access}. "
                                      "Not verified by running an exploit.")
    if entry_state == "auth":
        return "possible", confidence, f"{where} with no effective validation, but an authenticated session is required."
    if entry_state == "local":
        return "possible", confidence, f"{where}; the input is local ({flow.source.kind}), not network-facing."
    return "possible", confidence, f"{where}; the entry point could not be identified."


def _better_state(a: str, b: str) -> str:
    rank = {"open": 0, "bypassable": 1, "auth": 2, "unknown": 3, "local": 4}
    return a if rank[a] <= rank[b] else b


def _control_node(g: _Graph, c: Control, kind: str, blocking: bool) -> str:
    label = f"{c.name} ({c.kind}, {c.strength})"
    detail = (f"Neutralises {SINK_CLASSES[kind].title.lower()} on this path." if blocking else
              f"Present, but not effective against {SINK_CLASSES[kind].title.lower()}"
              f"{' (only graded ' + c.strength + ')' if c.kind == 'guard' else ''}.")
    return g.node(ChainNode(
        id=f"ctrl:{c.file}:{c.line}:{_short_hash(c.name)}", kind="security_control",
        role="control" if blocking else "contributing", label=label, detail=f"{detail} {c.code}",
        file=c.file, line=c.line,
    ))


def keys_linked(g: _Graph) -> list[str]:
    return [n for n in g.nodes if n.startswith("weak:secretkey")]


def _plain_input(flow: Flow) -> str:
    src = flow.source
    name = re.search(r"""\(\s*['"]([^'"]+)['"]""", src.expr) or re.search(r"""\[\s*['"]([^'"]+)['"]""", src.expr)
    label = f"“{name.group(1)}”" if name else ""
    if src.kind == "path parameter":
        return f"the {label or f'“{src.expr}”'} part of the web address"
    if src.kind in ("request body", "JSON body", "uploaded file"):
        return "data they upload" if src.kind == "uploaded file" else "the data they send"
    if src.kind in ("command-line argument", "stdin"):
        return "the input they type"
    noun = {"query parameter": "parameter", "form field": "form field", "cookie": "cookie",
            "HTTP header": "header", "request parameter": "parameter"}.get(src.kind, "value")
    return f"the {label} {noun}".replace("  ", " ") if label else f"a {noun} they control"


def plain_summary(
    flow: Flow, entries: list[Endpoint], access: str, weak: bool,
    exploitability: str, paths: int, kind: str, forgeable_login: bool,
) -> str:
    """Two or three everyday sentences: who can do it, what reaches what, what could happen."""
    target, consequence = PLAIN[kind]
    route = entries[0].label if entries else f"{flow.root}()"
    who = {
        "open": f"Anyone can send a request to {route}",
        "bypassable": f"{route} needs a login, but logins can be faked because the secret key is written in the code",
        "auth": f"Logged-in users can send a request to {route}",
        "local": "Someone with access to this machine can run it",
    }.get(access, f"If an attacker can reach {route}")
    if forgeable_login and access == "auth":
        who += " (and the login may be fakeable, because a secret key is written in the code)"
    if exploitability == "mitigated":
        how = f"{_plain_input(flow).capitalize()} is checked before it reaches {target}, so this is blocked today."
        return f"{who}. {how} Keep that check in place."
    middle = "is only partly checked before it goes into" if weak else "goes straight into"
    more = f" There are {paths} ways in." if paths > 1 else ""
    return f"{who}. {_plain_input(flow).capitalize()} {middle} {target}.{more} {consequence}"


def chain_context(chain: WeaknessChain) -> str:
    """Short text describing the chain, added to the per-finding AI prompt."""
    path = next(iter(chain.paths), [])
    labels = " -> ".join(next(n.label for n in chain.nodes if n.id == p) for p in path)
    fix = chain.fix
    lines = [
        f"This finding is part of an attack chain ({chain.exploitability} exploitable, priority {chain.priority}/100):",
        f"  {labels}",
        "Conditions: " + "; ".join(chain.conditions[:4]),
    ]
    if fix:
        lines.append(f"Preferred break point: {fix.strategy}. {fix.rationale}")
    lines.append("Make the fixed_code enforce the security property at that point, not just hide this symptom.")
    return "\n".join(lines)


def _short_hash(text: str, n: int = 8) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:n]


def _dedupe(paths: list[list[str]]) -> list[list[str]]:
    out: list[list[str]] = []
    for p in paths:
        if p not in out:
            out.append(p)
    return out


def _dedupe_str(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
