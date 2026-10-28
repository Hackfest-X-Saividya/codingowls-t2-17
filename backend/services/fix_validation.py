"""Post-fix validation: does a fix actually break the chain, without regressions?

For each attempt the fix is applied to a fresh copy of the scanned revision
(the original copy is hashed before and after to prove it was not touched),
then evidence is collected:

  reproduce        re-run data-flow analysis; is there still an unblocked path into
                   the chain's operation? (path_broken / weakness_addressed)
  alternative      other unblocked paths of the same class from the same entry
  paths            points or inputs (risk_eliminated needs both of these clean)
  scanner          targeted Semgrep on the changed + chain files, before vs after:
                   linked rule matches gone? new findings?
  regression       changed files parse, keep their routes and functions, and do not
                   use names that are not defined; opt-in project test command
  new issues       unblocked paths that did not exist before, classified as
                   extending an existing chain, a new chain, or unrelated

Outcome (see decide()):
  PASS               not reproducible under these checks, no alternative path, no
                     blocking regression, no new issue: "validated within scope"
  FAIL               reproducible, alternative path open, or blocking regression
  NEW_VULNERABILITY  original chain broken, but the change introduced a new issue
  INCONCLUSIVE       patch did not apply, a required check could not run, or the
                     evidence conflicts (flow gone but linked scanner rule still fires)

A passing compile or test run alone never yields PASS: the reproduce and
alternative-path checks must run and come back clean.
"""
from __future__ import annotations

import ast
import asyncio
import builtins
import difflib
import logging
import os
import re
import shlex
import shutil
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional, Protocol

from models.schemas import (
    AttemptStatus, ChainFix, Evidence, EvidenceKind, FixEdit, NewIssue, ValidationAttempt, ValidationCheck, ValidationStatus,
    Vulnerability, WeaknessChain,
)
from services import chain_analysis, fix_planner
from services.flow_analyzer import Flow, FlowAnalysis, analyze_repository
from utils import sandbox

logger = logging.getLogger(__name__)

# (root, relative files, languages) -> (findings, error message or None)
Scanner = Callable[[Path, list[str], list[str]], Awaitable[tuple[list[Vulnerability], Optional[str]]]]


class PatchError(Exception):
    pass


@dataclass
class Baseline:
    """Analysis of the unmodified scanned revision."""
    root: Path
    analysis: FlowAnalysis
    chains: list[WeaknessChain]
    languages: list[str] = field(default_factory=list)


@dataclass
class LoopResult:
    status: ValidationStatus
    attempts: list[ValidationAttempt]
    message: str
    needs_manual_review: bool
    stop_reason: str = ""                # passed | stalled | limit | inconclusive | no_fix | not_reproducible
    best_attempt: Optional[int] = None   # attempt number of the passing / most-improved fix
    final_fix: Optional[ChainFix] = None  # final code, as edits against the original
    final_diff: str = ""
    result: Optional[AttemptStatus] = None  # the last evaluated attempt's status, else why nothing was evaluated


class Target(Protocol):
    """What a validation loop works on: an attack chain or a single finding."""
    root: Path  # the scanned revision; never modified

    def not_reproducible(self) -> Optional[str]: ...
    async def first_fix(self) -> Optional[ChainFix]: ...
    async def next_fix(self, current: Path, history: list[ValidationAttempt]) -> Optional[ChainFix]: ...
    async def evaluate(self, fix: ChainFix, attempt_no: int, patched: Path, changed: list[str]) -> ValidationAttempt: ...


@dataclass
class Resume:
    """Where earlier runs of the same investigation left off."""
    history: list[ValidationAttempt]          # every earlier evaluated attempt, oldest first
    best_fix: Optional[ChainFix] = None       # best code so far, as edits against the original
    best: Optional[ValidationAttempt] = None  # the attempt that produced it


class Journal(Protocol):
    """Persists every attempt as the loop runs (services/validation_history.py). Calls block (database I/O)."""

    def begin(self, attempt_no: int) -> None:
        """Record the attempt as RUNNING, before its fix is generated."""
    def generated(self, fix: ChainFix) -> None:
        """Record the generated fix (patch)."""
    def hashed(self, code_hash: str) -> Optional[str]:
        """Record the snapshot to validate; returns the earlier attempt that already validated this exact code, if any."""
    def close(self, status: AttemptStatus, reason: str) -> None:
        """End the attempt without evaluating it (no fix could be generated, or SKIPPED as already validated)."""
    def finish(self, attempt: ValidationAttempt) -> None:
        """Record the evaluated attempt's results."""


async def _log(journal: Optional[Journal], method: str, *args) -> Optional[str]:
    return await asyncio.to_thread(getattr(journal, method), *args) if journal else None


def record_status(a: ValidationAttempt) -> AttemptStatus:
    """PASSED / FAILED / INCONCLUSIVE / ERROR for an evaluated attempt.

    INCONCLUSIVE becomes ERROR when a check could not run for infrastructure reasons
    (scanner, OSV.dev, test runner): that says nothing about the fix itself.
    """
    if a.status == ValidationStatus.PASS:
        return AttemptStatus.PASSED
    if a.status in (ValidationStatus.FAIL, ValidationStatus.NEW_VULNERABILITY):
        return AttemptStatus.FAILED
    if any(c.infrastructure and c.status in ("error", "skipped") for c in a.checks):
        return AttemptStatus.ERROR
    return AttemptStatus.INCONCLUSIVE


def progress_score(a: ValidationAttempt) -> Optional[int]:
    """How far a fix is from done; lower is better, 0 means every check is clean.

    Weighted evidence from the attempt: still-open paths into the operation count most,
    then alternative paths, regressions and new issues, then a lingering scanner match.
    None when the attempt could not be evaluated (patch did not apply).
    """
    if a.status == ValidationStatus.INCONCLUSIVE and not any(c.name == "reproduce_original" for c in a.checks):
        return None
    if any(c.name == "syntax" and c.status == "failed" for c in a.checks):
        return 100  # does not even parse: worst possible
    alternatives = sum(p.endswith("(alternative path)") for p in a.remaining_paths)
    still_open = len(a.remaining_paths) - alternatives
    scanner = any(c.name == "scanner_recheck" and c.status == "failed" for c in a.checks)
    return 10 * still_open + 5 * alternatives + 5 * len(a.regressions) + 5 * len(a.new_issues) + 2 * scanner


def _problems(a: ValidationAttempt) -> frozenset[str]:
    """Outstanding problems, ignoring line numbers (edits above a problem shift them)."""
    texts = a.remaining_paths + a.regressions + [i.description for i in a.new_issues]
    return frozenset(re.sub(r":\d+|\bline \d+", "", t) for t in texts)


def made_progress(a: ValidationAttempt, best: Optional[ValidationAttempt]) -> bool:
    """Better than the best attempt so far.

    A lower score is progress. An equal score is progress only if the problems
    changed and none of the old ones remain (e.g. an upgrade fixed one advisory and
    the next version has a different one); the same problems again is a stall.
    """
    if a.progress_score is None:
        return False
    if best is None or best.progress_score is None:
        return True
    if a.progress_score != best.progress_score:
        return a.progress_score < best.progress_score
    return a.progress_score > 0 and not (_problems(a) & _problems(best))


# ---------- patch handling ----------

def apply_fix(original: Path, dest: Path, edits: list[FixEdit]) -> list[str]:
    """Copy original to dest and apply edits there. Returns changed files. original is never written."""
    if dest.exists():
        shutil.rmtree(dest)
    sandbox.copy_tree(original, dest)
    by_file: dict[str, list[FixEdit]] = {}
    for e in edits:
        by_file.setdefault(e.file, []).append(e)
    for rel, file_edits in by_file.items():
        try:
            target = sandbox.ensure_within(dest, rel)
            source = sandbox.ensure_within(original, rel)
        except ValueError as e:
            raise PatchError(str(e)) from e
        if not source.is_file():
            raise PatchError(f"{rel} does not exist in the code being fixed")
        data = source.read_bytes()
        bom = data.startswith(b"\xef\xbb\xbf")  # kept on write, but edits are matched without it
        raw = data.decode("utf-8-sig", errors="replace")
        newline = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.replace("\r\n", "\n").split("\n")
        ordered = sorted(file_edits, key=lambda e: e.start_line)
        for a, b in zip(ordered, ordered[1:]):
            if b.start_line <= a.end_line:
                raise PatchError(f"Overlapping edits in {rel} at lines {a.start_line}-{a.end_line} and {b.start_line}-{b.end_line}")
        for e in reversed(ordered):
            if not (1 <= e.start_line <= e.end_line <= len(lines)):
                raise PatchError(f"Edit {rel}:{e.start_line}-{e.end_line} is outside the file ({len(lines)} lines)")
            current = "\n".join(lines[e.start_line - 1:e.end_line])
            if e.original and current.rstrip() != e.original.replace("\r\n", "\n").rstrip():
                raise PatchError(f"{rel}:{e.start_line}-{e.end_line} does not match the current code; the patch is stale")
            lines[e.start_line - 1:e.end_line] = e.replacement.replace("\r\n", "\n").split("\n")
        target.write_bytes((b"\xef\xbb\xbf" if bom else b"") + newline.join(lines).encode("utf-8"))
    return sorted(by_file)


def unified_diff(original: Path, patched: Path, files: list[str]) -> str:
    out = []
    for rel in files:
        a = (original / rel).read_text(encoding="utf-8-sig", errors="replace").splitlines(keepends=True)
        b = (patched / rel).read_text(encoding="utf-8-sig", errors="replace").splitlines(keepends=True)
        out += difflib.unified_diff(a, b, fromfile=f"a/{rel}", tofile=f"b/{rel}", n=2)
    return "".join(out)[:20000]


def changed_files(original: Path, patched: Path) -> list[str]:
    """Files that differ between two trees (for validating a developer's local changes)."""
    a, b = sandbox.tree_hashes(original), sandbox.tree_hashes(patched)
    return sorted(f for f in set(a) | set(b) if a.get(f) != b.get(f))


def edits_between(original: Path, patched: Path, files: list[str]) -> list[FixEdit]:
    """The changes from original to patched as line-range edits against the original."""
    edits: list[FixEdit] = []
    for rel in files:
        if not (original / rel).is_file() or not (patched / rel).is_file():
            continue
        a = (original / rel).read_text(encoding="utf-8-sig", errors="replace").replace("\r\n", "\n").split("\n")
        b = (patched / rel).read_text(encoding="utf-8-sig", errors="replace").replace("\r\n", "\n").split("\n")
        ops = [op for op in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes() if op[0] != "equal"]
        # Merge changes a couple of lines apart into one readable edit
        hunks: list[list[int]] = []
        for _, i1, i2, j1, j2 in ops:
            if hunks and i1 - hunks[-1][1] <= 2:
                hunks[-1][1], hunks[-1][3] = i2, j2
            else:
                hunks.append([i1, i2, j1, j2])
        for i1, i2, j1, j2 in hunks:
            if i1 == i2:  # pure insertion: anchor on the line before (or the first line)
                anchor = max(i1, 1)
                inserted = b[j1:j2]
                replacement = [a[anchor - 1], *inserted] if i1 else [*inserted, a[0]]
                edits.append(FixEdit(file=rel, start_line=anchor, end_line=anchor, original=a[anchor - 1],
                                     replacement="\n".join(replacement)))
            else:
                edits.append(FixEdit(file=rel, start_line=i1 + 1, end_line=i2, original="\n".join(a[i1:i2]),
                                     replacement="\n".join(b[j1:j2])))
    return edits


# ---------- the loop ----------

async def run_loop(
    target: Target,
    workspace: Path,
    max_attempts: int,
    on_attempt: Optional[Callable[[ValidationAttempt], None]] = None,
    first_attempt: int = 1,
    resume: Optional[Resume] = None,
    journal: Optional[Journal] = None,
) -> LoopResult:
    """Suggest -> apply -> verify, revising from the latest failure evidence.

    The code carries forward: each attempt is applied on top of the best code so far
    (the previous attempt's, whenever it improved), so the last attempt holds the
    final code. Each attempt is still verified against the original scanned code.

    `resume` continues an investigation from an earlier run: its best code is the
    starting point, its attempts are the generator's history, and attempts are
    numbered on from `first_attempt`. `journal` persists each attempt from before
    its fix is generated until it ends; code an earlier attempt already validated
    is recorded as SKIPPED instead of being validated again.

    Stops on PASS or INCONCLUSIVE, when an attempt makes no progress over the best one
    so far (progress_score), when no new evidence-driven fix exists, when a fix only
    reproduces code that was already validated, or at max_attempts (capped at
    settings.FIX_ATTEMPTS_CAP).
    """
    from utils.config import settings

    max_attempts = min(max(max_attempts, 1), settings.FIX_ATTEMPTS_CAP)
    last = first_attempt + max_attempts - 1
    reason = target.not_reproducible()
    if reason:
        return LoopResult(ValidationStatus.INCONCLUSIVE, [], reason, True, stop_reason="not_reproducible")

    original = target.root
    current, carried = original, set()  # code the next fix applies to; files changed in it
    prior = list(resume.history) if resume else []
    attempts: list[ValidationAttempt] = []
    best: Optional[ValidationAttempt] = None
    if resume and resume.best_fix and resume.best_fix.edits:
        try:
            touched = await asyncio.to_thread(apply_fix, original, workspace / "resumed", resume.best_fix.edits)
            current, carried, best = workspace / "resumed", set(touched), resume.best
        except PatchError as e:
            logger.info("Could not restore the best code of the earlier run, starting from the original: %s", e)
    resumed = current != original
    message, stop_reason = "", ""
    for n in range(first_attempt, last + 1):
        await _log(journal, "begin", n)  # RUNNING before the fix is generated
        if n > first_attempt:
            fix = await target.next_fix(current, prior + attempts)
        else:  # resumed: the next revision of the best code so far, from all earlier evidence
            fix = await (target.next_fix(current, prior) if resumed else target.first_fix())
        if fix is None:
            stop_reason = "no_fix"
            specific = getattr(target, "no_fix_message", lambda: None)()
            message = ((specific or "No automated fix is available for this code; supply a fix to validate.")
                       if not attempts and not prior else
                       "No new fix could be derived from the failure evidence; manual review required.")
            await _log(journal, "close", AttemptStatus.INCONCLUSIVE, message)
            break
        await _log(journal, "generated", fix)
        attempt_dir = workspace / f"attempt-{n}"
        hashes_before = sandbox.tree_hashes(original)
        try:
            touched = await asyncio.to_thread(apply_fix, current, attempt_dir, fix.edits)
        except PatchError as e:
            touched = None
            attempt = ValidationAttempt(
                attempt=n, fix=fix, status=ValidationStatus.INCONCLUSIVE, summary=f"The fix could not be applied: {e}",
                checks=[ValidationCheck(name="apply_patch", status="error", detail=str(e))],
                scope="Nothing was evaluated because the patch did not apply.",
            )
        code_hash = await asyncio.to_thread(sandbox.code_hash, attempt_dir if touched is not None else current)
        duplicate = await _log(journal, "hashed", code_hash)
        if duplicate and touched is not None:
            stop_reason = "duplicate"
            message = f"This fix produces exactly the code already validated in {duplicate}; it was not validated again."
            await _log(journal, "close", AttemptStatus.SKIPPED, message)
            break
        if touched is not None:
            attempt = await target.evaluate(fix, n, attempt_dir, sorted(carried | set(touched)))
            attempt.diff = unified_diff(current, attempt_dir, touched)  # this attempt's own change
        attempt.code_hash = code_hash
        attempt.original_preserved = sandbox.tree_hashes(original) == hashes_before
        if not attempt.original_preserved:
            attempt.status = ValidationStatus.INCONCLUSIVE
            attempt.summary = "The original code changed during validation; results are not trustworthy."

        attempt.progress_score = progress_score(attempt)
        attempt.improved = made_progress(attempt, best)
        attempt.record_status = record_status(attempt)
        if attempt.improved and attempt.progress_score < 100:
            # Keep this code: the next revision builds on it
            best, current = attempt, attempt_dir
            carried |= set(touched or [])
        attempts.append(attempt)
        await _log(journal, "finish", attempt)
        if on_attempt:
            on_attempt(attempt)

        if attempt.status == ValidationStatus.PASS:
            stop_reason = "passed"
            break
        if attempt.status == ValidationStatus.INCONCLUSIVE:
            stop_reason = "inconclusive"
            break
        if n > first_attempt and not attempt.improved:
            stop_reason = "stalled"
            message = ("Stopped early: the latest revision made no progress over the best one so far. "
                       "Manual review required.")
            break
        if n == last:
            stop_reason = "limit"
            message = "No revision passed every check. Manual review required; the best revision is kept."
            break

    status = attempts[-1].status if attempts else ValidationStatus.INCONCLUSIVE
    if not message:
        message = attempts[-1].summary if attempts else "No validation was performed."
    final_fix, final_diff = None, ""
    if best is not None and current != original:
        files = sorted(carried)
        final_fix = best.fix.model_copy(update={"edits": edits_between(original, current, files)})
        final_diff = unified_diff(original, current, files)
    result = (attempts[-1].record_status if attempts else
              AttemptStatus.SKIPPED if stop_reason == "duplicate" else AttemptStatus.INCONCLUSIVE)
    return LoopResult(status, attempts, message, needs_manual_review=status != ValidationStatus.PASS,
                      stop_reason=stop_reason, best_attempt=best.attempt if best else None,
                      final_fix=final_fix, final_diff=final_diff, result=result)


@dataclass
class ChainTarget:
    """Validates fixes for an attack chain with data-flow, scanner and regression checks."""
    chain: WeaknessChain
    baseline: Baseline
    scanner: Optional[Scanner]
    use_ai: bool = False
    developer_fix: Optional[ChainFix] = None
    test_command: str = ""
    test_timeout: int = 300
    lessons: str = ""  # outcomes of similar fixes elsewhere (validation_history.lessons), for the LLM
    strategy_stats: dict = field(default_factory=dict)  # per-strategy record in comparable cases (fix_planner.choose)

    @property
    def root(self) -> Path:
        return self.baseline.root

    def not_reproducible(self) -> Optional[str]:
        if [f for f in flows_into(self.baseline.analysis, self.chain) if not f.blocked]:
            return None
        return ("The original chain has no open path on the scanned revision, so there is nothing to reproduce. "
                "Re-scan the repository or review it manually.")

    async def first_fix(self) -> Optional[ChainFix]:
        return self.developer_fix or await fix_planner.next_fix(
            self.chain, self.baseline.analysis, self.baseline.root, [], self.use_ai, lessons=self.lessons,
            stats=self.strategy_stats)

    async def next_fix(self, current: Path, history: list[ValidationAttempt]) -> Optional[ChainFix]:
        analysis = await asyncio.to_thread(analyze_repository, current)
        return await fix_planner.next_fix(self.chain, analysis, current, history, self.use_ai, lessons=self.lessons,
                                          stats=self.strategy_stats)

    async def evaluate(self, fix: ChainFix, attempt_no: int, patched: Path, changed: list[str]) -> ValidationAttempt:
        return await evaluate(self.chain, fix, attempt_no, self.baseline, patched, changed, self.scanner,
                              self.test_command, self.test_timeout)


async def run_chain_loop(
    chain: WeaknessChain,
    baseline: Baseline,
    workspace: Path,
    max_attempts: int,
    scanner: Optional[Scanner],
    use_ai: bool = False,
    first_fix: Optional[ChainFix] = None,
    test_command: str = "",
    test_timeout: int = 300,
    on_attempt: Optional[Callable[[ValidationAttempt], None]] = None,
) -> LoopResult:
    target = ChainTarget(chain, baseline, scanner, use_ai, first_fix, test_command, test_timeout)
    return await run_loop(target, workspace, max_attempts, on_attempt)


def attempt_stats(validations: list, limit: int) -> dict:
    """Per-attempt success rates across finished validations, and whether a higher limit would help.

    - Most passes on attempt 1-2: raising the limit is unlikely to help.
    - Many validations hitting the limit while still improving: a higher limit may help.
    """
    done = [v for v in validations if getattr(v, "state", "") == "complete" and v.attempts]
    total = len(done)
    passed_at: dict[int, int] = {}
    for v in done:
        if v.status == ValidationStatus.PASS:
            passed_at[len(v.attempts)] = passed_at.get(len(v.attempts), 0) + 1
    passes = sum(passed_at.values())
    reasons = Counter(v.stop_reason or "unknown" for v in done)
    limit_improving = sum(1 for v in done if v.stop_reason == "limit" and v.attempts[-1].improved)
    by_attempt = []
    cumulative = 0
    for k in range(1, max([limit, *passed_at.keys()] or [limit]) + 1):
        reached = sum(1 for v in done if len(v.attempts) >= k)
        cumulative += passed_at.get(k, 0)
        by_attempt.append({
            "attempt": k, "reached": reached, "passed": passed_at.get(k, 0),
            "pass_rate_when_reached": round(passed_at.get(k, 0) / reached, 2) if reached else None,
            "cumulative_pass_rate": round(cumulative / total, 2) if total else None,
        })
    early = sum(passed_at.get(k, 0) for k in (1, 2))
    if total < 5:
        advice = "Not enough finished validations yet to judge the attempt limit."
    elif limit_improving / total >= 0.3:
        advice = (f"{limit_improving} of {total} validations hit the limit while still improving; "
                  "raising FIX_MAX_ATTEMPTS (max 5) may help.")
    elif passes and early / passes >= 0.8:
        advice = (f"{early} of {passes} passing fixes passed on attempt 1 or 2; "
                  "raising the attempt limit is unlikely to help.")
    else:
        advice = "No clear signal; keep the current attempt limit."
    return {"validations": total, "passed": passes, "attempt_limit": limit, "by_attempt": by_attempt,
            "stop_reasons": dict(reasons), "hit_limit_while_improving": limit_improving, "advice": advice}


async def evaluate(
    chain: WeaknessChain,
    fix: ChainFix,
    attempt_no: int,
    baseline: Baseline,
    patched: Path,
    files: list[str],
    scanner: Optional[Scanner],
    test_command: str = "",
    test_timeout: int = 300,
) -> ValidationAttempt:
    """Collect all evidence for a patched tree and decide the outcome."""
    checks: list[ValidationCheck] = []
    regressions: list[str] = []
    py_files = [f for f in files if f.endswith(".py")]
    diff = unified_diff(baseline.root, patched, files)

    # 1. The modified code must still be code
    syntax_errors = []
    for rel in py_files:
        path = patched / rel
        if not path.exists():
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8-sig", errors="replace"), filename=rel)
        except SyntaxError as e:
            syntax_errors.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=e.lineno, code=(e.text or "").strip(),
                                          description=f"SyntaxError: {e.msg}"))
    checks.append(ValidationCheck(name="syntax", status="failed" if syntax_errors else "passed",
                                  detail=f"{len(py_files)} changed Python file(s) parsed", evidence=syntax_errors))
    regressions += [f"{e.file}:{e.line} {e.description}" for e in syntax_errors]

    attempt = ValidationAttempt(attempt=attempt_no, fix=fix, status=ValidationStatus.INCONCLUSIVE, summary="",
                                diff=diff, checks=checks, regressions=regressions)
    if syntax_errors:
        attempt.checks.append(ValidationCheck(name="reproduce_original", status="error",
                                      detail="Modified code does not parse, so the chain could not be re-evaluated."))
        attempt.status = ValidationStatus.FAIL
        attempt.summary = "The fix breaks the code (syntax error); the chain could not be re-evaluated."
        attempt.scope = "Syntax check only."
        return attempt

    after = await asyncio.to_thread(analyze_repository, patched)
    _reproduce(chain, baseline, after, attempt)
    _alternatives(chain, baseline, after, attempt)
    _api_surface(baseline, after, py_files, patched, attempt)
    new_flows = _new_flows(chain, baseline, after, attempt)
    await _scanner_check(chain, baseline, after, patched, files, scanner, new_flows, attempt)
    await _project_tests(baseline.root, patched, test_command, test_timeout, attempt)
    _other_chains(chain, baseline, after, files, attempt)
    decide(attempt, scanner_required=bool(chain.finding_ids))
    return attempt


def flows_into(analysis: FlowAnalysis, chain: WeaknessChain) -> list[Flow]:
    return chain_analysis.flows_for_signature(analysis, chain.signature)


def _flow_evidence(flow: Flow) -> list[Evidence]:
    ev = [Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=flow.source.file, line=flow.source.line,
                   code=flow.source.code, description=f"source: {flow.source.kind} {flow.source.expr}")]
    ev += [Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=s.file, line=s.line, code=s.code, description=s.note)
           for s in flow.steps]
    ev.append(Evidence(kind=EvidenceKind.STATIC_DATAFLOW, file=flow.sink.file, line=flow.sink.line,
                       code=flow.sink.code, description=f"reaches {flow.sink.callee}"))
    return ev


def _describe_flow(flow: Flow) -> str:
    return f"{flow.source.expr} → {flow.sink.callee} at {flow.sink.file}:{flow.sink.line}"


def _reproduce(chain: WeaknessChain, baseline: Baseline, after: FlowAnalysis, attempt: ValidationAttempt) -> None:
    if chain.file in after.errors:
        attempt.checks.append(ValidationCheck(name="reproduce_original", status="error",
                                              detail=f"{chain.file} could not be analysed: {after.errors[chain.file]}"))
        return
    before_open = {f.signature() for f in flows_into(baseline.analysis, chain) if not f.blocked}
    now = flows_into(after, chain)
    now_open = [f for f in now if not f.blocked]
    attempt.path_broken = not any(f.signature() in before_open for f in now_open)
    attempt.weakness_addressed = not now_open if attempt.fix.break_point.startswith("op:") else attempt.path_broken
    blocked_by = sorted({f"{c.name} at line {c.line}" for f in now if f.blocked for c in f.blocking_controls})
    if now_open:
        attempt.remaining_paths += [_describe_flow(f) for f in now_open]
        attempt.remaining_signatures.append(chain.signature)
        detail = (f"{len(now_open)} unblocked path(s) still reach {chain.signature['callee']}"
                  + ("" if attempt.path_broken else " (including the original path)"))
        attempt.checks.append(ValidationCheck(name="reproduce_original", status="failed", detail=detail,
                                              evidence=[e for f in now_open[:3] for e in _flow_evidence(f)]))
    else:
        sig = chain.signature
        still_called = int(sig.get("occurrence", "0")) < len(
            chain_analysis.occurrences(after).get((sig["file"], sig["function"], sig["callee"]), []))
        detail = ("No unblocked path reaches the operation any more"
                  + (f"; blocked by {', '.join(blocked_by)}" if blocked_by else
                     f"; {sig['callee']} is still called but no longer receives untrusted data" if still_called else
                     f"; the {sig['callee']} call was rewritten or removed"))
        attempt.checks.append(ValidationCheck(name="reproduce_original", status="passed", detail=detail))


def _alternatives(chain: WeaknessChain, baseline: Baseline, after: FlowAnalysis, attempt: ValidationAttempt) -> None:
    """Other unblocked paths to the same outcome: same class, same entry point or same input."""
    own_before = flows_into(baseline.analysis, chain)
    entries = {e.function for f in own_before for e in baseline.analysis.entries_for(f)}
    sources = {(f.source.file, f.source.function, f.source.expr) for f in own_before}
    own_now = {id(f) for f in flows_into(after, chain)}
    alt = []
    for f in after.flows:
        if f.blocked or id(f) in own_now or f.sink.kind != chain.kind:
            continue
        if entries & {e.function for e in after.entries_for(f)} or (f.source.file, f.source.function, f.source.expr) in sources:
            alt.append(f)
    if alt:
        attempt.remaining_paths += [_describe_flow(f) + " (alternative path)" for f in alt]
        occ = chain_analysis.occurrences(baseline.analysis)
        base_by_sig = {f.signature(): f for f in baseline.analysis.flows}
        for f in alt:
            base = base_by_sig.get(f.signature())
            if base is not None:
                sig = chain_analysis.chain_signature(base, occ)
                if sig not in attempt.remaining_signatures:
                    attempt.remaining_signatures.append(sig)
    attempt.risk_eliminated = bool(attempt.weakness_addressed) and bool(attempt.path_broken) and not alt
    attempt.checks.append(ValidationCheck(
        name="alternative_paths", status="failed" if alt else "passed",
        detail=(f"{len(alt)} other unblocked {chain.kind.replace('_', ' ')} path(s) from the same entry points or inputs"
                if alt else f"No other unblocked {chain.kind.replace('_', ' ')} path from the same entry points or inputs"),
        evidence=[e for f in alt[:3] for e in _flow_evidence(f)],
    ))


def _new_flows(chain: WeaknessChain, baseline: Baseline, after: FlowAnalysis, attempt: ValidationAttempt) -> list[Flow]:
    before_open = {f.signature() for f in baseline.analysis.flows if not f.blocked}
    own = {f.signature() for f in flows_into(baseline.analysis, chain)}
    new = [f for f in after.flows if not f.blocked and f.signature() not in before_open and f.signature() not in own]
    chain_sigs = {tuple(c.signature[k] for k in ("file", "function", "callee", "kind")): c.id for c in baseline.chains}
    chain_funcs = {(c.file, c.function): c.id for c in baseline.chains}
    for f in new:
        key = chain_analysis.sink_key(f)
        related = chain_sigs.get(key) or chain_funcs.get((f.sink.file, f.root)) or chain_funcs.get((f.sink.file, f.sink.function))
        attempt.new_issues.append(NewIssue(
            description=f"New {f.sink.kind.replace('_', ' ')} path: {_describe_flow(f)}",
            file=f.sink.file, line=f.sink.line, origin="dataflow",
            relation="extends_chain" if related else "new_chain", chain_id=related,
        ))
    return new


async def _scanner_check(
    chain: WeaknessChain, baseline: Baseline, after: FlowAnalysis, patched: Path, files: list[str],
    scanner: Optional[Scanner], new_flows: list[Flow], attempt: ValidationAttempt,
) -> None:
    targets = sorted({f for f in files if (patched / f).exists() and (baseline.root / f).exists()} | {chain.file})
    if scanner is None:
        attempt.checks.append(ValidationCheck(name="scanner_recheck", status="skipped", detail="Scanner not available",
                                              infrastructure=True))
        return
    (before, err_a), (now, err_b) = await asyncio.gather(
        scanner(baseline.root, targets, baseline.languages), scanner(patched, targets, baseline.languages))
    if err_a or err_b:
        attempt.checks.append(ValidationCheck(name="scanner_recheck", status="error", detail=err_a or err_b or "",
                                              infrastructure=True))
        return

    def key(v: Vulnerability, root: Path) -> tuple[str, str, str]:
        lines = (root / v.file).read_text(encoding="utf-8-sig", errors="replace").split("\n") if (root / v.file).exists() else []
        code = lines[v.line - 1].strip() if 0 < v.line <= len(lines) else ""
        return (v.rule_id, v.file, code)

    before_keys = Counter(key(v, baseline.root) for v in before)
    chain_lines = set().union(*(f.lines() for f in flows_into(baseline.analysis, chain))) or {0}
    cls = chain_analysis.SINK_CLASSES[chain.kind]
    linked = [v for v in before if v.file == chain.file and v.line in chain_lines
              and re.search(cls.rule_pattern, f"{v.rule_id} {v.title}", re.I)]

    # A linked rule still matches if it fires on an unchanged line, or on the (edited) sink line
    sig = chain.signature
    sites = chain_analysis.occurrences(after).get((sig["file"], sig["function"], sig["callee"]), [])
    idx = int(sig.get("occurrence", "0"))
    patched_lines = set().union(*(f.lines() for f in flows_into(after, chain))) | ({sites[idx]} if idx < len(sites) else set())
    unchanged = Counter(key(v, baseline.root) for v in linked)
    persisting = []
    for w in now:
        if w.file != chain.file:
            continue
        k = key(w, patched)
        if unchanged[k] > 0:
            unchanged[k] -= 1
            persisting.append(w)
        elif w.rule_id in {v.rule_id for v in linked} and w.line in patched_lines:
            persisting.append(w)
    persisting_ids = {id(w) for w in persisting}

    added = Counter(key(v, patched) for v in now if id(v) not in persisting_ids) - before_keys
    new_count = sum(added.values())
    new_lines = {(f.sink.file, f.sink.line) for f in new_flows}
    for v in now:
        k = key(v, patched)
        if id(v) not in persisting_ids and added[k] > 0:
            added[k] -= 1
            if (v.file, v.line) in new_lines:
                continue  # already reported from data flow
            in_chain_fn = any(c.file == v.file and _in_function(after, c.file, c.function, v.line) for c in baseline.chains)
            attempt.new_issues.append(NewIssue(
                description=f"New scanner finding {v.rule_id.split('.')[-1]}: {v.title}", file=v.file, line=v.line,
                origin="scanner", relation="extends_chain" if in_chain_fn else "unrelated",
            ))
    status = "failed" if persisting else "passed"
    detail = (f"{len(linked)} linked rule match(es) before, {len(persisting)} still present; "
              f"{new_count} new finding(s) in {len(targets)} file(s)")
    attempt.checks.append(ValidationCheck(
        name="scanner_recheck", status=status, detail=detail,
        evidence=[Evidence(kind=EvidenceKind.SCANNER, file=v.file, line=v.line, finding_id=v.id,
                           description=f"{v.rule_id.split('.')[-1]} still matches") for v in persisting],
    ))


def _in_function(analysis: FlowAnalysis, file: str, function: str, line: int) -> bool:
    facts = analysis.modules.get(file)
    span = facts.functions.get(function) if facts else None
    return bool(span and span[0] <= line <= span[1])


def _api_surface(baseline: Baseline, after: FlowAnalysis, py_files: list[str], patched: Path,
                 attempt: ValidationAttempt) -> None:
    """Routes and functions removed, or names used without being defined, count as regressions."""
    problems: list[Evidence] = []
    for rel in py_files:
        old, new = baseline.analysis.modules.get(rel), after.modules.get(rel)
        if old is None:
            continue
        if new is None:
            problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, description="file was removed or no longer parses"))
            continue
        for fn, ep in old.endpoints.items():
            if ep.label not in {e.label for e in new.endpoints.values()}:
                problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=ep.line, description=f"route {ep.label} was removed"))
        for fn in old.functions:
            if fn not in new.functions:
                problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=old.functions[fn][0],
                                         description=f"function {fn}() was removed"))
        old_text = (baseline.root / rel).read_text(encoding="utf-8-sig", errors="replace")
        new_text = (patched / rel).read_text(encoding="utf-8-sig", errors="replace")
        problems += python_regressions(rel, old_text, new_text, include_defs=False)  # defs checked above
    attempt.regressions += [f"{e.file}:{e.line or '-'} {e.description}" for e in problems]
    attempt.checks.append(ValidationCheck(
        name="regression_static", status="failed" if problems else "passed",
        detail=(f"{len(problems)} regression(s) in changed files" if problems
                else "Changed files keep their routes and functions and define every name they use"),
        evidence=problems,
    ))


def python_regressions(rel: str, old_text: str, new_text: str, include_defs: bool = True) -> list[Evidence]:
    """Static Python regressions a fix introduced: removed top-level functions/classes,
    names used but never defined (NameError), imports that no longer exist (ImportError)."""
    problems: list[Evidence] = []
    if include_defs:
        try:
            old_tree, new_tree = ast.parse(old_text), ast.parse(new_text)
        except SyntaxError:
            return problems
        kinds = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        new_defs = {n.name for n in new_tree.body if isinstance(n, kinds)}
        for n in old_tree.body:
            if isinstance(n, kinds) and n.name not in new_defs:
                problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=n.lineno,
                                         description=f"{n.name} was removed"))
    old_undef, new_undef = _undefined_names(old_text), _undefined_names(new_text)
    for name, line in sorted(new_undef.items(), key=lambda kv: kv[1]):
        if name not in old_undef:
            problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=line,
                                     description=f"name '{name}' is used but never defined or imported (NameError at runtime)"))
    old_removed = _removed_imports(old_text)
    for name, (line, why) in _removed_imports(new_text).items():
        if name not in old_removed:
            problems.append(Evidence(kind=EvidenceKind.TEST, file=rel, line=line,
                                     description=f"imports {name}, which current versions no longer provide "
                                                 f"({why}): ImportError at runtime"))
    return problems


# Imports a fix (often an AI one) may reach for that current library versions removed
REMOVED_IMPORTS = {
    ("flask", "escape"): "removed in Flask 2.3; use markupsafe.escape",
    ("flask", "Markup"): "removed in Flask 2.3; use markupsafe.Markup",
    ("flask", "safe_join"): "removed in Flask 2.1; use werkzeug.security.safe_join",
    ("jinja2", "escape"): "removed in Jinja 3.1; use markupsafe.escape",
    ("jinja2", "Markup"): "removed in Jinja 3.1; use markupsafe.Markup",
    ("werkzeug", "secure_filename"): "moved; use werkzeug.utils.secure_filename",
    ("cgi", "escape"): "removed in Python 3.8; use html.escape",
}


def _removed_imports(text: str) -> dict[str, tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                why = REMOVED_IMPORTS.get((n.module, a.name))
                if why:
                    out[f"{n.module}.{a.name}"] = (n.lineno, why)
    return out


def _undefined_names(text: str) -> dict[str, int]:
    """Names loaded somewhere but bound nowhere in the module (a coarse NameError detector)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__builtins__", "__spec__", "__path__"}
    loads: dict[str, int] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                bound.add(n.id)
            else:
                loads.setdefault(n.id, n.lineno)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                return {}  # star imports make this undecidable
            bound |= {(a.asname or a.name).split(".")[0] for a in n.names}
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound |= set(n.names)
        elif isinstance(n, ast.MatchAs) and n.name:
            bound.add(n.name)
    return {k: v for k, v in loads.items() if k not in bound}


async def _project_tests(original: Path, patched: Path, command: str, timeout: int, attempt: ValidationAttempt) -> None:
    if not command:
        attempt.checks.append(ValidationCheck(
            name="project_tests", status="skipped",
            detail="Not run: VALIDATION_TEST_COMMAND is not set (running the scanned project's code is opt-in)."))
        return
    argv = shlex.split(command, posix=os.name != "nt")
    # Run the baseline on its own copy, so failures that predate the fix are not blamed on it
    baseline_copy = patched.parent / f"{patched.name}-baseline-tests"
    if baseline_copy.exists():
        shutil.rmtree(baseline_copy)
    await asyncio.to_thread(sandbox.copy_tree, original, baseline_copy)
    (rc_before, out_before), (rc_after, out_after) = await asyncio.gather(
        asyncio.to_thread(sandbox.run_command, argv, baseline_copy, timeout),
        asyncio.to_thread(sandbox.run_command, argv, patched, timeout),
    )
    shutil.rmtree(baseline_copy, ignore_errors=True)
    if rc_after in (124, 127) or (rc_before in (124, 127)):
        attempt.checks.append(ValidationCheck(name="project_tests", status="error", infrastructure=True,
                                              detail=f"Test command could not run: {out_after[-500:] or out_before[-500:]}"))
        return
    if rc_after != 0 and rc_before == 0:
        attempt.regressions.append(f"Project tests pass on the original but fail after the fix (exit {rc_after})")
        attempt.checks.append(ValidationCheck(name="project_tests", status="failed", detail=out_after[-1500:],
                                              evidence=[Evidence(kind=EvidenceKind.TEST, description=f"`{command}` exit {rc_after}")]))
    else:
        detail = "Tests pass" if rc_after == 0 else f"Tests already failed before the fix (exit {rc_before}); not counted as a regression"
        attempt.checks.append(ValidationCheck(name="project_tests", status="passed", detail=detail))


def _other_chains(chain: WeaknessChain, baseline: Baseline, after: FlowAnalysis, files: list[str],
                  attempt: ValidationAttempt) -> None:
    for other in baseline.chains:
        if other.id == chain.id or other.file not in files:
            continue
        still = [f for f in flows_into(after, other) if not f.blocked]
        attempt.other_chains[other.id] = "still present" if still else "broken"


def decide(attempt: ValidationAttempt, scanner_required: bool) -> None:
    """Turn the collected evidence into an outcome, most decisive evidence first."""
    by_name = {c.name: c for c in attempt.checks}
    reproduce = by_name.get("reproduce_original")
    alternatives = by_name.get("alternative_paths")
    scan = by_name.get("scanner_recheck")
    executed = [c.name for c in attempt.checks if c.status in ("passed", "failed")]
    not_run = [f"{c.name} ({c.status})" for c in attempt.checks if c.status in ("skipped", "error")]
    attempt.scope = (f"Validated with: {', '.join(executed)}." + (f" Not covered: {', '.join(not_run)}." if not_run else "")
                     + " Static analysis and scanner checks only; no exploit was executed against a running app.")
    blocking_regression = any(c.status == "failed" for c in attempt.checks
                              if c.name in ("syntax", "regression_static", "project_tests"))

    if reproduce is None or reproduce.status == "error" or alternatives is None:
        attempt.status = ValidationStatus.INCONCLUSIVE
        attempt.summary = "The chain could not be re-evaluated on the modified code; manual review required."
    elif reproduce.status == "failed":
        attempt.status = ValidationStatus.FAIL
        attempt.summary = ("The original path is still open: " if not attempt.path_broken else
                           "The original path was cut, but another path still reaches the same operation: ") + "; ".join(attempt.remaining_paths[:2])
    elif alternatives.status == "failed":
        attempt.status = ValidationStatus.FAIL
        attempt.summary = ("The targeted path is broken, but the same risk is still reachable: "
                           + "; ".join(p for p in attempt.remaining_paths if p.endswith("(alternative path)"))[:500])
    elif blocking_regression:
        attempt.status = ValidationStatus.FAIL
        attempt.summary = "The chain is broken, but the fix introduces a regression: " + "; ".join(attempt.regressions[:3])
    elif scan is not None and scan.status == "failed":
        attempt.status = ValidationStatus.INCONCLUSIVE
        attempt.summary = ("Conflicting evidence: data-flow analysis finds no open path, but the linked scanner rule "
                           "still matches. Manual review required.")
    elif scanner_required and (scan is None or scan.status in ("error", "skipped")):
        attempt.status = ValidationStatus.INCONCLUSIVE
        attempt.summary = ("Data-flow analysis finds the chain broken, but the scanner re-check needed to confirm the "
                           f"linked findings could not run ({scan.detail if scan else 'missing'}).")
    elif attempt.new_issues:
        attempt.status = ValidationStatus.NEW_VULNERABILITY
        attempt.summary = "The original chain is broken, but the change introduces: " + "; ".join(
            f"{i.description} [{i.relation.replace('_', ' ')}]" for i in attempt.new_issues[:3])
    else:
        attempt.status = ValidationStatus.PASS
        attempt.summary = ("Validated within the scope of the performed checks: the original path no longer reproduces, "
                           "no alternative path to the same outcome was found, and no regression was detected.")


# ---------- scanner adapter ----------

async def semgrep_scanner(root: Path, files: list[str], languages: list[str]) -> tuple[list[Vulnerability], Optional[str]]:
    """Targeted Semgrep run with the scan's rulesets on just `files`."""
    from services import repo_manager, sarif_parser, semgrep_runner

    scan_id = f"validate-{uuid.uuid4().hex[:8]}"
    try:
        sarif = await semgrep_runner.run_scan(root, languages, scan_id, targets=[root / f for f in files])
        return sarif_parser.parse_sarif(sarif, root), None
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"
    finally:
        repo_manager.cleanup_scan(scan_id)


def developer_fix(edits: list[FixEdit], chain: Optional[WeaknessChain], root: Path,
                  finding_id: Optional[str] = None) -> ChainFix:
    """Wrap developer-supplied edits; fill in the original text so staleness is detected."""
    filled = []
    for e in edits:
        if not e.original:
            try:
                lines = sandbox.ensure_within(root, e.file).read_text(encoding="utf-8-sig", errors="replace").split("\n")
                e = e.model_copy(update={"original": "\n".join(lines[e.start_line - 1:e.end_line])})
            except (ValueError, OSError):
                pass  # apply_fix reports the problem
        filled.append(e)
    if chain is None:
        return ChainFix(strategy="Developer-supplied fix", break_point=finding_id or "", target_nodes=[finding_id or ""],
                        rationale="Supplied by the developer for validation.", edits=filled, origin="developer",
                        strategy_id="developer")
    return ChainFix(strategy="Developer-supplied fix", break_point=chain.direct_weaknesses[0],
                    target_nodes=list(chain.direct_weaknesses), rationale="Supplied by the developer for validation.",
                    edits=filled, tests=fix_planner.planned_checks(chain), origin="developer", strategy_id="developer")
