"""Chain-aware fix suggestions.

For each chain we pick where to interrupt it. The default break point is the
sensitive operation itself: making the operation safe for *any* input (a
parameterized query, an argument list without a shell, a safe loader, ...)
covers every path into it, including ones the analysis did not find, while
validating one input only cuts one path. Paths a fix does not cover (other
sinks of the same class reached from the same entry points) are listed so the
validation loop and the developer can check them.

Fixes come from three places:
- template: small AST-based rewrites for recognised code shapes; deterministic,
  so they work without an API key and in tests
- ai: Groq, given the chain, its evidence and the failure evidence of earlier
  attempts; edits are checked against the original file before use
- developer: edits supplied through the API

Which candidate is tried first is decided by choose(), shared with
finding_validation.py: the rule-based order, except that a predefined strategy
with a record of only failures in comparable cases goes after the LLM (it stays
the fallback). The record comes from the persisted validation history.

Every fix is a list of line-range edits against the scanned revision; it is
only ever applied to a sandbox copy (fix_validation.py), never to a real repo.
"""
from __future__ import annotations

import ast
import copy
import logging
import re
from pathlib import Path
from typing import Optional

from typing import Awaitable, Callable

from models.schemas import AttemptStatus, ChainFix, FixEdit, ValidationAttempt, WeaknessChain
from services import chain_analysis
from services.flow_analyzer import Flow, FlowAnalysis

logger = logging.getLogger(__name__)

STRATEGIES: dict[str, str] = {
    "sql_injection": "Parameterize the query at the database call",
    "command_injection": "Pass an argument list with shell=False at the process call",
    "code_injection": "Replace eval() with ast.literal_eval()",
    "deserialization": "Use a data-only loader at the deserialization call",
    "path_traversal": "Reduce the user-supplied part of the path to a plain file name",
    "template_injection": "Use a constant template and pass user data as context variables",
    "xss": "HTML-escape user data in the response",
    "ssrf": "Validate the destination URL against an allowlist of hosts before the request",
    "open_redirect": "Only redirect to relative paths or an allowlist of hosts",
}
PROPERTY: dict[str, str] = {
    "sql_injection": "user input is always bound as data and never parsed as SQL",
    "command_injection": "user input is passed as a single argument and never interpreted by a shell",
    "code_injection": "user input can only be parsed as a Python literal, never executed",
    "deserialization": "request data can only produce plain data objects, never arbitrary objects",
    "path_traversal": "the user-supplied part cannot contain directory separators or '..'",
    "template_injection": "user input is rendered as escaped text, never compiled as template code",
    "xss": "user input is HTML-escaped before it is returned",
    "ssrf": "the server only connects to approved hosts",
    "open_redirect": "users are only redirected to approved locations",
}


def plan_fix(chain: WeaknessChain, analysis: FlowAnalysis, root: Path) -> ChainFix:
    """The suggested fix for a chain: template edits where possible, guidance otherwise."""
    flows = chain_analysis.flows_for_signature(analysis, chain.signature)
    op = chain.direct_weaknesses[0]
    edits: list[FixEdit] = []
    note = ""
    try:
        edits = _template_edits(chain.kind, flows, root) if flows else []
    except Exception as e:  # a template that cannot handle this code shape must not break the scan
        logger.debug("Template fix failed for %s: %s", chain.id, e)
    if not edits:
        note = " No automatic rewrite matches this code shape; apply the change manually or use AI suggestions."
    covered = len(flows)
    return ChainFix(
        strategy=STRATEGIES[chain.kind],
        break_point=op,
        target_nodes=[op] + [n for n in chain.contributing_weaknesses if n.startswith("weak:novalidation")],
        rationale=(
            f"Enforces that {PROPERTY[chain.kind]} at the operation ({chain.signature['callee']}), so all "
            f"{covered} path(s) into it are interrupted regardless of where the input comes from. "
            f"The unvalidated inputs remain but no longer lead to {chain_analysis.SINK_CLASSES[chain.kind].title.lower()}."
            + note
        ),
        edits=edits,
        remaining_paths=remaining_paths(chain, analysis),
        tests=planned_checks(chain),
        origin="template",
        strategy_id=template_id(chain.kind),
    )


def template_id(kind: str) -> str:
    return f"template:{kind}"


# ---------- history-informed choice between strategies ----------

# strategy_id -> (passed, failed) in comparable cases elsewhere (validation_history.strategy_stats)
StrategyStats = dict[str, tuple[int, int]]
Candidate = tuple[str, Callable[[], Awaitable[Optional[ChainFix]]]]
NOT_RANKED = {"", "ai", "developer"}  # free-form fixes: the LLM gets the history as context instead


def strategy_record(strategy_id: str, stats: StrategyStats, history: list[ValidationAttempt]) -> tuple[int, int]:
    """(passed, failed) for a strategy: other investigations' record plus this investigation's attempts.

    Only evaluated attempts count: a patch that did not apply or a check that could not
    run (ERROR) says nothing about the strategy.
    """
    passed, failed = stats.get(strategy_id, (0, 0))
    for a in history:
        if a.fix.strategy_id != strategy_id or any(c.name == "apply_patch" for c in a.checks):
            continue
        if a.record_status == AttemptStatus.PASSED:
            passed += 1
        elif a.record_status in (AttemptStatus.FAILED, AttemptStatus.INCONCLUSIVE):
            failed += 1
    return passed, failed


def avoid_reason(strategy_id: str, stats: StrategyStats, history: list[ValidationAttempt]) -> Optional[str]:
    """Why history advises against trying this predefined strategy first, or None."""
    from utils.config import settings

    if strategy_id in NOT_RANKED:
        return None
    passed, failed = strategy_record(strategy_id, stats, history)
    if passed == 0 and failed >= settings.HISTORY_AVOID_AFTER_FAILURES:
        return f"{strategy_id} failed {failed} time(s) in comparable cases and never passed"
    return None


async def choose(
    candidates: list[Candidate], history: list[ValidationAttempt], stats: StrategyStats,
    is_new: Callable[[Optional[ChainFix]], bool],
) -> Optional[ChainFix]:
    """The first new fix from the candidates, in the rule-based order, except that predefined
    strategies history advises against are tried last (still the fallback, never dropped).
    Candidates are built lazily, so the LLM is only called when it is reached."""
    reasons = {sid: avoid_reason(sid, stats, history) for sid, _ in candidates}
    ranked = sorted(candidates, key=lambda c: reasons[c[0]] is not None)  # stable: keeps the rule-based order
    for sid, make in ranked:
        fix = await make()
        if not is_new(fix):
            continue
        note = ""  # only when history changed the order; with a single candidate it changes nothing
        if reasons[sid] and len(candidates) > 1:
            note = f"Used as the fallback although {reasons[sid]}."
        elif any(reasons[s] for s, _ in candidates if s != sid):
            note = "Tried first because " + "; ".join(r for r in reasons.values() if r) + "."
        return fix.model_copy(update={"strategy_id": fix.strategy_id or sid, "history_note": note})
    return None


async def _value(fix: Optional[ChainFix]) -> Optional[ChainFix]:
    return fix


def remaining_paths(chain: WeaknessChain, analysis: FlowAnalysis) -> list[str]:
    """Unblocked paths to the same outcome that a fix at this chain's operation would not touch."""
    own = {f.sink.line for f in chain_analysis.flows_for_signature(analysis, chain.signature)}
    own_flows = [f for f in analysis.flows if f.sink.file == chain.file and f.sink.line in own]
    entries = {e.function for f in own_flows for e in analysis.entries_for(f)}
    sources = {(f.source.file, f.source.function, f.source.expr) for f in own_flows}
    out = []
    for f in analysis.flows:
        if f.blocked or (f.sink.file == chain.file and f.sink.line in own):
            continue
        same_entry = bool(entries & {e.function for e in analysis.entries_for(f)})
        same_source = (f.source.file, f.source.function, f.source.expr) in sources
        if f.sink.kind == chain.kind and (same_entry or same_source):
            out.append(f"{f.source.expr} → {f.sink.callee} at {f.sink.file}:{f.sink.line} (same {chain.kind.replace('_', ' ')})")
        elif same_source:
            out.append(f"{f.source.expr} also reaches {f.sink.callee} at {f.sink.file}:{f.sink.line} "
                       f"({f.sink.kind.replace('_', ' ')}, separate chain)")
    return list(dict.fromkeys(out))


def planned_checks(chain: WeaknessChain) -> list[str]:
    rules = sorted({fid for fid in chain.finding_ids})
    checks = [
        f"Reproduce: re-run data-flow analysis; no unblocked path may reach {chain.signature['callee']} "
        f"in {chain.function}() ({chain.file})",
        f"Alternative paths: no other unblocked {chain.kind.replace('_', ' ')} path from the same entry points",
        "Targeted Semgrep re-scan of changed files: linked rule matches gone, no new findings",
        "Regression: changed files parse, keep their routes and functions, and introduce no undefined names",
    ]
    if rules:
        checks.insert(2, f"Linked findings must disappear: {', '.join(rules)}")
    return checks


# ---------- retry: next suggestion from failure evidence ----------

async def next_fix(
    chain: WeaknessChain,
    analysis: FlowAnalysis,
    root: Path,
    history: list[ValidationAttempt],
    use_ai: bool,
    lessons: str = "",
    stats: Optional[StrategyStats] = None,
) -> Optional[ChainFix]:
    """A fix that differs from every earlier attempt, built from the latest failure evidence.

    `history` may include attempts from earlier runs of the same investigation;
    `lessons` summarises outcomes of similar fixes elsewhere (LLM context) and `stats`
    is the per-strategy record in comparable cases (strategy order, see choose()).
    """
    stats = stats or {}
    tried = {_edits_key(a.fix.edits) for a in history}

    def new(fix: Optional[ChainFix]) -> bool:
        return bool(fix and fix.edits and _edits_key(fix.edits) not in tried)

    template = template_id(chain.kind)
    if not history:
        candidates: list[Candidate] = [(template, lambda: _value(chain.fix or plan_fix(chain, analysis, root)))]
        # The rule-based first attempt has no LLM step; history can only add one in front of a failing template
        with_ai = use_ai and avoid_reason(template, stats, history) is not None
    else:
        # `root`/`analysis` are the current, already-improved code: the next fix only adds what is
        # still missing. Deterministic first (reproducible, no API quota), then the LLM.
        candidates = [(template, lambda: _value(_fix_remaining(analysis, root, history[-1])))]
        with_ai = use_ai
    if with_ai:
        candidates.append(("ai", lambda: ai_fix(chain, analysis, root, history, lessons)))
    return await choose(candidates, history, stats, new)


def _fix_remaining(analysis: FlowAnalysis, root: Path, last: ValidationAttempt) -> Optional[ChainFix]:
    """Template fixes, on the current code, for the paths the last attempt left open."""
    extra: list[FixEdit] = []
    covered: list[str] = []
    strategies: list[str] = []
    for sig in last.remaining_signatures:
        flows = chain_analysis.flows_for_signature(analysis, sig)
        if not flows:
            continue
        try:
            edits = _template_edits(sig["kind"], flows, root)
        except Exception:
            edits = []
        if edits:
            extra += edits
            covered.append(f"{sig['callee']} in {sig['function']}()")
            strategies.append(STRATEGIES[sig["kind"]])
    if not extra:
        return None
    merged = _merge_edits([], extra)  # several sinks may each add the same import
    if merged is None:
        return None
    return ChainFix(
        strategy=f"{'; '.join(dict.fromkeys(strategies))} ({', '.join(covered)})",
        break_point=last.fix.break_point,
        target_nodes=last.fix.target_nodes,
        rationale=(f"Attempt {last.attempt} left these paths open: {'; '.join(last.remaining_paths[:3])}. "
                   f"Building on that code, this applies the same safe pattern to {', '.join(covered)}."),
        edits=merged,
        remaining_paths=[],
        tests=last.fix.tests,
        origin="template",
        strategy_id=template_id(last.remaining_signatures[0]["kind"]) if last.remaining_signatures else "",
    )


def _merge_edits(a: list[FixEdit], b: list[FixEdit]) -> Optional[list[FixEdit]]:
    """Combine earlier edits `a` with new edits `b` (copies; earlier attempts are never mutated).

    Same range: the newer edit wins, since the earlier change there did not hold up,
    except two pure insertions after the same line (imports), which are combined.
    Partial overlaps would make the patch ambiguous: None.
    """
    out = [x.model_copy() for x in a]
    for e in b:
        overlapping = [x for x in out if x.file == e.file and not (e.end_line < x.start_line or e.start_line > x.end_line)]
        if not overlapping:
            out.append(e.model_copy())
            continue
        x = overlapping[0]
        if len(overlapping) > 1 or (x.start_line, x.end_line) != (e.start_line, e.end_line):
            return None
        if _is_insertion(x) and _is_insertion(e):
            added = [line for line in e.replacement.split("\n") if line not in x.replacement.split("\n")]
            x.replacement = "\n".join([x.replacement, *added])
        else:
            out[out.index(x)] = e.model_copy()
    return out


def _is_insertion(e: FixEdit) -> bool:
    return e.start_line == e.end_line and e.replacement.startswith(e.original + "\n")


def _edits_key(edits: list[FixEdit]) -> tuple:
    return tuple(sorted((e.file, e.start_line, e.end_line, re.sub(r"\s+", "", e.replacement)) for e in edits))


# ---------- AI suggestions ----------

AI_FIX_PROMPT = """\
You are a senior application security engineer fixing a chain of weaknesses.

## Chain
{chain}

## Code (current version, including earlier attempts' changes; line numbers are exact)
{code}

## Previous attempts and why they failed
{history}

## Lessons from validated fixes of similar problems (other code; do not copy, adapt the approach)
{lessons}

Propose the smallest change to the code shown that enforces this security property: {prop}.
Earlier attempts' changes are already in that code; only add what is still missing or wrong.
Interrupt the chain where it is reliable (prefer the sensitive operation so every path is covered).
Do not modify unrelated code. Your fix must differ from every previous attempt and address the failure evidence.
Avoid approaches that the lessons show failing; prefer ones that passed, applied to this code.

Use APIs that exist in current library versions (e.g. escape comes from markupsafe, not flask).

Respond with JSON only, replacing every <...> placeholder:
{{
  "strategy": "<what the change does, in one sentence>",
  "break_point": "<one node id from the chain>",
  "target_nodes": ["<node ids this fix addresses>"],
  "rationale": "<which weakness or relationship the change addresses and why it holds>",
  "edits": [{{"file": "<path>", "start_line": <first line>, "end_line": <last line>, "replacement": "<new text for those lines, with indentation>"}}],
  "remaining_paths": ["<paths this fix does not cover, if any>"]
}}
"""


async def ai_fix(
    chain: WeaknessChain, analysis: FlowAnalysis, root: Path, history: list[ValidationAttempt], lessons: str = "",
) -> Optional[ChainFix]:
    from services import ai_enhancer
    from utils.config import settings

    if not settings.GROQ_API_KEY:
        return None
    import httpx

    prompt = AI_FIX_PROMPT.format(
        chain=_describe(chain), code=_code_context(chain, analysis, root),
        history=_describe_history(history) or "(none)", prop=PROPERTY[chain.kind], lessons=lessons or "(none)",
    )
    try:
        async with httpx.AsyncClient(timeout=90) as http:
            data = ai_enhancer._parse_ai_response((await ai_enhancer._groq_complete(http, prompt)).strip())
    except Exception as e:
        logger.warning("AI fix suggestion failed for %s: %s", chain.id, e)
        return None
    edits = []
    for raw in data.get("edits") or []:
        edit = _checked_edit(root, raw, allowed={chain.file} | {n.file for n in chain.nodes if n.file})
        if edit is None:
            logger.info("Discarding AI edit outside the chain or file bounds: %s", raw)
            return None
        edits.append(edit)
    if not edits:
        return None
    node_ids = {n.id for n in chain.nodes}
    return ChainFix(
        strategy=str(data.get("strategy", "AI-suggested fix"))[:200],
        break_point=data.get("break_point") if data.get("break_point") in node_ids else chain.direct_weaknesses[0],
        target_nodes=[n for n in data.get("target_nodes") or [] if n in node_ids],
        rationale=str(data.get("rationale", ""))[:1500],
        edits=edits,
        remaining_paths=[str(p) for p in data.get("remaining_paths") or []][:10],
        tests=planned_checks(chain),
        origin="ai",
        strategy_id="ai",
    )


def _checked_edit(root: Path, raw: dict, allowed: set[str]) -> Optional[FixEdit]:
    try:
        file, start, end = str(raw["file"]), int(raw["start_line"]), int(raw["end_line"])
    except (KeyError, TypeError, ValueError):
        return None
    if file not in allowed:
        return None
    lines = (root / file).read_text(encoding="utf-8-sig", errors="replace").split("\n")
    if not (1 <= start <= end <= len(lines)):
        return None
    return FixEdit(file=file, start_line=start, end_line=end, original="\n".join(lines[start - 1:end]),
                   replacement=str(raw.get("replacement", "")).rstrip("\n"))


def _describe(chain: WeaknessChain) -> str:
    labels = {n.id: f"{n.label} [{n.kind}, id={n.id}]" for n in chain.nodes}
    out = [f"{chain.title} — impact: {chain.impact}; exploitability: {chain.exploitability}"]
    for e in chain.edges:
        ev = "; ".join(f"L{x.line}: {x.description}" for x in e.evidence[:6])
        out.append(f"- {labels[e.source]} --{e.relation} ({e.status})--> {labels[e.target]}  evidence: {ev}")
    out.append("Conditions: " + "; ".join(chain.conditions))
    return "\n".join(out)


def _code_context(chain: WeaknessChain, analysis: FlowAnalysis, root: Path) -> str:
    facts = analysis.modules.get(chain.file)
    ranges = []
    for fn in {chain.function} | {f.root for f in chain_analysis.flows_for_signature(analysis, chain.signature)}:
        if facts and fn in facts.functions:
            ranges.append(facts.functions[fn])
    lines = (root / chain.file).read_text(encoding="utf-8-sig", errors="replace").split("\n")
    header = [i for i, l in enumerate(lines[:60], 1) if l.startswith(("import ", "from "))]
    chunks = [f"# {chain.file}"]
    for start, end in sorted(set(ranges + ([(header[0], header[-1])] if header else []))):
        chunks += [f"{i:4d}| {lines[i - 1]}" for i in range(start, min(end, len(lines)) + 1)]
        chunks.append("    ...")
    return "\n".join(chunks)


def _describe_history(history: list[ValidationAttempt], limit: int = 8) -> str:
    out = []
    for a in history[-limit:]:  # resumed investigations can carry many attempts; the latest matter most
        out.append(f"Attempt {a.attempt} ({a.fix.strategy_id or a.fix.origin}): {a.fix.strategy} -> "
                   f"{a.status.value}: {a.summary}")
        for e in a.fix.edits:
            out.append(f"  edit {e.file}:{e.start_line}-{e.end_line}: {e.replacement[:300]!r}")
        for c in a.checks:
            if c.status in ("failed", "error"):
                out.append(f"  failed check {c.name}: {c.detail}")
                out += [f"    L{x.line} {x.code}" for x in c.evidence[:5]]
        out += [f"  still open: {p}" for p in a.remaining_paths[:5]]
        out += [f"  regression: {r}" for r in a.regressions[:5]]
        out += [f"  new issue: {n.description} at {n.file}:{n.line}" for n in a.new_issues[:5]]
    return "\n".join(out)


# ---------- deterministic templates ----------

class _Source:
    def __init__(self, root: Path, rel: str) -> None:
        self.rel = rel
        self.text = (root / rel).read_text(encoding="utf-8-sig", errors="replace")
        self.lines = self.text.split("\n")
        self.tree = ast.parse(self.text)

    def function(self, qualname: str) -> Optional[ast.AST]:
        parts = qualname.split(".")
        scope: list[ast.stmt] = self.tree.body
        node: Optional[ast.AST] = None
        for p in parts:
            node = next((n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                         and n.name == p), None)
            if node is None:
                return None
            scope = node.body
        return node

    def stmt_at(self, fn: ast.AST, line: int) -> Optional[ast.stmt]:
        best = None
        for n in ast.walk(fn):
            if isinstance(n, ast.stmt) and n.lineno <= line <= (n.end_lineno or n.lineno):
                if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For,
                                      ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)):
                    if best is None or n.lineno >= best.lineno:
                        best = n
        return best

    def call_at(self, stmt: ast.stmt, line: int, callee_short: str) -> Optional[ast.Call]:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call) and n.lineno == line:
                f = n.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name == callee_short:
                    return n
        return None

    def assignment(self, fn: ast.AST, name: str, before: int) -> Optional[ast.Assign]:
        found = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and n.lineno < before
                 and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
        writes = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign))
                  and any(isinstance(t, ast.Name) and t.id == name
                          for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
        return found[-1] if len(found) == 1 and len(writes) == 1 else None

    def replace_stmt(self, stmt: ast.stmt, new: ast.stmt) -> Optional[FixEdit]:
        start, end = stmt.lineno, stmt.end_lineno or stmt.lineno
        first, last = self.lines[start - 1], self.lines[end - 1]
        indent = first[: len(first) - len(first.lstrip())]
        if len(indent) != stmt.col_offset or last[stmt.end_col_offset:].strip().split("#")[0].strip():
            return None  # statement shares its lines with other code
        tail = last[stmt.end_col_offset:]
        text = "\n".join(indent + l if i else indent + l for i, l in enumerate(ast.unparse(new).split("\n")))
        return FixEdit(file=self.rel, start_line=start, end_line=end,
                       original="\n".join(self.lines[start - 1:end]), replacement=text + tail)

    def add_import(self, statement: str, provides: str) -> Optional[FixEdit]:
        for n in self.tree.body:
            if isinstance(n, (ast.Import, ast.ImportFrom)) and any((a.asname or a.name).split(".")[0] == provides
                                                                    for a in n.names):
                return None
        imports = [n for n in self.tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        if imports:
            line = imports[-1].end_lineno or imports[-1].lineno
        elif self.tree.body and isinstance(self.tree.body[0], ast.Expr) and isinstance(
                getattr(self.tree.body[0], "value", None), ast.Constant):
            line = self.tree.body[0].end_lineno or 1
        else:
            return FixEdit(file=self.rel, start_line=1, end_line=1, original=self.lines[0],
                           replacement=f"{statement}\n{self.lines[0]}")
        return FixEdit(file=self.rel, start_line=line, end_line=line, original=self.lines[line - 1],
                       replacement=f"{self.lines[line - 1]}\n{statement}")


def _template_edits(kind: str, flows: list[Flow], root: Path) -> list[FixEdit]:
    sink = flows[0].sink
    src = _Source(root, sink.file)
    fn = src.function(sink.function)
    if fn is None:
        return []
    stmt = src.stmt_at(fn, sink.line)
    if stmt is None:
        return []
    builder = {
        "sql_injection": _fix_sql, "command_injection": _fix_command, "deserialization": _fix_deserialization,
        "code_injection": _fix_eval, "path_traversal": _fix_path, "template_injection": _fix_template,
        "xss": _fix_xss,
    }.get(kind)
    if builder is None:
        return []
    edits = builder(src, fn, stmt, flows)
    edits = [e for e in edits if e is not None]
    if not edits:
        return []
    # A template that produces invalid code is worse than none
    try:
        ast.parse(_apply_in_memory(src.lines, edits))
    except SyntaxError:
        return []
    return edits


def _apply_in_memory(lines: list[str], edits: list[FixEdit]) -> str:
    out = list(lines)
    for e in sorted(edits, key=lambda e: e.start_line, reverse=True):
        out[e.start_line - 1:e.end_line] = e.replacement.split("\n")
    return "\n".join(out)


def _resolve(src: _Source, fn: ast.AST, expr: ast.expr, before: int) -> tuple[ast.expr, Optional[ast.Assign]]:
    """Follow `name` to its single assignment in the function, so `query = f"..."; execute(query)` works."""
    if isinstance(expr, ast.Name):
        assign = src.assignment(fn, expr.id, before)
        if assign is not None:
            return assign.value, assign
    return expr, None


def _built_string(expr: ast.expr) -> Optional[list[object]]:
    """Parts of a string built in place (f-string or '+'), or None.

    A bare variable (e.g. a helper's `sql` parameter) is refused: rewriting it
    as `execute('?', (sql,))` would remove the taint but break the program.
    """
    if not isinstance(expr, (ast.JoinedStr, ast.BinOp)):
        return None
    parts = _parts(expr)
    if not parts or not any(isinstance(p, str) and p.strip() for p in parts):
        return None
    return parts


def _parts(expr: ast.expr) -> Optional[list[object]]:
    """Flatten an f-string or '+' concatenation into str constants and value expressions."""
    if isinstance(expr, ast.JoinedStr):
        out: list[object] = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                out.append(str(v.value))
            elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                out.append(v.value)
            else:
                return None
        return out
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _parts(expr.left), _parts(expr.right)
        return None if left is None or right is None else left + right
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value]
    if isinstance(expr, ast.expr):
        return [expr]
    return None


def _with_value(stmt: ast.Assign, value: ast.expr) -> ast.Assign:
    new = copy.deepcopy(stmt)
    new.value = value
    return new


def _rewrite_call(src: _Source, stmt: ast.stmt, call: ast.Call, change) -> Optional[FixEdit]:
    new_stmt = copy.deepcopy(stmt)
    for n in ast.walk(new_stmt):
        if isinstance(n, ast.Call) and n.lineno == call.lineno and n.col_offset == call.col_offset:
            change(n)
            return src.replace_stmt(stmt, new_stmt)
    return None


def _fix_sql(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    call = src.call_at(stmt, flows[0].sink.line, flows[0].sink.callee.split(".")[-1])
    if call is None or len(call.args) != 1 or call.keywords:
        return []
    query, assign = _resolve(src, fn, call.args[0], stmt.lineno)
    parts = _built_string(query)
    if not parts or all(isinstance(p, str) for p in parts):
        return []
    placeholder = "?" if "sqlite3" in src.text else "%s"
    sql, params = "", []
    for i, p in enumerate(parts):
        if isinstance(p, str):
            sql += p
            continue
        nxt = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
        if sql.endswith(("'", '"')) and nxt.startswith(sql[-1]):
            sql = sql[:-1]
            parts[i + 1] = nxt[1:]
        if sql.endswith("%") or str(parts[i + 1] if i + 1 < len(parts) else "").startswith("%"):
            return []  # LIKE '%...%' needs the wildcards moved into the parameter: leave to a person
        if (sql.count("'") - sql.count("\\'")) % 2 or sql.count('"') % 2:
            return []  # value sits inside a longer string literal ('by {user}'): needs concatenation in SQL
        sql += placeholder
        params.append(p)
    if re.search(r"\b(ORDER|GROUP)\s+BY\s*\?$|\bFROM\s*\?|\bTABLE\s*\?", sql, re.I):
        return []  # identifiers cannot be bound as parameters
    params_node = ast.Tuple(elts=[copy.deepcopy(p) for p in params], ctx=ast.Load())
    if assign is not None:
        return [
            src.replace_stmt(assign, _with_value(assign, ast.Constant(sql))),
            _rewrite_call(src, stmt, call, lambda c: c.args.append(params_node)),
        ]
    return [_rewrite_call(src, stmt, call, lambda c: c.args.__setitem__(slice(None), [ast.Constant(sql), params_node]))]


def _fix_command(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    call = src.call_at(stmt, flows[0].sink.line, flows[0].sink.callee.split(".")[-1])
    if call is None or not call.args or not flows[0].sink.callee.startswith("subprocess."):
        return []
    cmd, assign = _resolve(src, fn, call.args[0], stmt.lineno)
    parts = _built_string(cmd)
    if not parts:
        return []
    tokens: list[ast.expr] = []
    for i, p in enumerate(parts):
        if isinstance(p, str):
            if re.search(r"[|&;<>`$(){}*?]", p):
                return []  # uses shell features: needs a real redesign
            if i > 0 and not isinstance(parts[i - 1], str) and p and not p[0].isspace():
                return []
            if i + 1 < len(parts) and not isinstance(parts[i + 1], str) and p and not p[-1].isspace():
                return []
            tokens += [ast.Constant(t) for t in p.split()]
        else:
            tokens.append(copy.deepcopy(p))
    argv = ast.List(elts=tokens, ctx=ast.Load())

    def no_shell(c: ast.Call) -> None:
        c.keywords = [k for k in c.keywords if k.arg != "shell"]
        if assign is None:
            c.args[0] = argv

    edits = [_rewrite_call(src, stmt, call, no_shell)]
    if assign is not None:
        edits.append(src.replace_stmt(assign, _with_value(assign, argv)))
    return edits


def _fix_deserialization(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    callee = flows[0].sink.callee
    call = src.call_at(stmt, flows[0].sink.line, callee.split(".")[-1])
    if call is None or not isinstance(call.func, ast.Attribute):
        return []
    if callee in ("pickle.loads", "_pickle.loads", "cPickle.loads", "dill.loads"):
        def to_json(c: ast.Call) -> None:
            c.func = ast.Attribute(value=ast.Name("json", ast.Load()), attr="loads", ctx=ast.Load())
        return [_rewrite_call(src, stmt, call, to_json), src.add_import("import json", "json")]
    if callee in ("yaml.load", "yaml.unsafe_load"):
        def safe(c: ast.Call) -> None:
            c.func.attr = "safe_load"
            c.args = c.args[:1]
            c.keywords = [k for k in c.keywords if k.arg != "Loader"]
        return [_rewrite_call(src, stmt, call, safe)]
    return []


def _fix_eval(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    if flows[0].sink.callee != "eval":
        return []
    call = src.call_at(stmt, flows[0].sink.line, "eval")
    if call is None:
        return []

    def literal(c: ast.Call) -> None:
        c.func = ast.Attribute(value=ast.Name("ast", ast.Load()), attr="literal_eval", ctx=ast.Load())
        c.args = c.args[:1]
    return [_rewrite_call(src, stmt, call, literal), src.add_import("import ast", "ast")]


def _fix_path(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    # The variable holding the raw input: the first name the source was assigned to
    names = []
    for f in flows:
        first = next((s.note.split("assigned to ", 1)[1] for s in f.steps if s.note.startswith("assigned to ")), None)
        if first and first.isidentifier():
            names.append(first)
    if not names:
        return []
    var = names[0]
    use_werkzeug = "flask" in src.text or "werkzeug" in src.text
    wrapper = "secure_filename" if use_werkzeug else "os.path.basename"

    def wrap() -> ast.expr:
        return ast.Call(func=ast.parse(wrapper, mode="eval").body, args=[ast.Name(var, ast.Load())], keywords=[])

    # Prefer the join that builds the path, so the base directory stays intact
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call) and ast.unparse(n.func) in ("os.path.join", "posixpath.join")
                and any(isinstance(a, ast.Name) and a.id == var for a in n.args[1:])):
            outer = src.stmt_at(fn, n.lineno)
            if outer is None:
                return []

            def sanitize(c: ast.Call) -> None:
                c.args = [wrap() if isinstance(a, ast.Name) and a.id == var else a for a in c.args]
            edit = _rewrite_call(src, outer, n, sanitize)
            imp = src.add_import("from werkzeug.utils import secure_filename", "secure_filename") if use_werkzeug \
                else src.add_import("import os", "os")
            return [edit, imp]
    return []


def _fix_template(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    call = src.call_at(stmt, flows[0].sink.line, flows[0].sink.callee.split(".")[-1])
    if call is None or len(call.args) != 1:
        return []
    template, assign = _resolve(src, fn, call.args[0], stmt.lineno)
    parts = _built_string(template)
    if not parts or all(isinstance(p, str) for p in parts):
        return []
    text, kwargs, used = "", [], {k.arg for k in call.keywords}
    for i, p in enumerate(parts):
        if isinstance(p, str):
            if re.search(r"{{|{%|{#", p):
                return []
            text += p
            continue
        name = p.id if isinstance(p, ast.Name) and p.id not in used else f"value{i}"
        used.add(name)
        text += "{{ " + name + " }}"
        kwargs.append(ast.keyword(arg=name, value=copy.deepcopy(p)))

    def render(c: ast.Call) -> None:
        if assign is None:
            c.args[0] = ast.Constant(text)
        c.keywords += kwargs
    edits = [_rewrite_call(src, stmt, call, render)]
    if assign is not None:
        edits.append(src.replace_stmt(assign, _with_value(assign, ast.Constant(text))))
    return edits


def _fix_xss(src: _Source, fn, stmt, flows) -> list[Optional[FixEdit]]:
    if not isinstance(stmt, ast.Return) or stmt.value is None:
        return []
    new = copy.deepcopy(stmt)
    target = new.value.elts[0] if isinstance(new.value, ast.Tuple) and new.value.elts else new.value

    def esc(e: ast.expr) -> ast.expr:
        return ast.Call(func=ast.Name("escape", ast.Load()), args=[e], keywords=[])

    # An f-string response becomes an autoescaped template: the data is escaped by the engine,
    # and the response is no longer a formatted string (which pattern rules keep flagging)
    parts = _built_string(target) if isinstance(target, ast.JoinedStr) and "flask" in src.text else None
    if parts and not any(isinstance(p, str) and re.search(r"{{|{%|{#", p) for p in parts):
        text, kwargs = "", []
        for i, p in enumerate(parts):
            if isinstance(p, str):
                text += p
            else:
                name = p.id if isinstance(p, ast.Name) else f"value{i}"
                text += "{{ " + name + " }}"
                if name not in {k.arg for k in kwargs}:
                    kwargs.append(ast.keyword(arg=name, value=copy.deepcopy(p)))
        rendered = ast.Call(func=ast.Name("render_template_string", ast.Load()), args=[ast.Constant(text)], keywords=kwargs)
        if isinstance(new.value, ast.Tuple):
            new.value.elts[0] = rendered
        else:
            new.value = rendered
        return [src.replace_stmt(stmt, new),
                src.add_import("from flask import render_template_string", "render_template_string")]

    if isinstance(target, ast.JoinedStr):
        for v in target.values:
            if isinstance(v, ast.FormattedValue):
                v.value = esc(v.value)
    elif isinstance(target, ast.Name):
        if isinstance(new.value, ast.Tuple):
            new.value.elts[0] = esc(target)
        else:
            new.value = esc(target)
    else:
        return []
    return [src.replace_stmt(stmt, new), src.add_import("from markupsafe import escape", "escape")]
