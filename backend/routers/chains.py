"""Fix validation API, for attack chains and for every single finding.

POST /api/scan/{scan_id}/chains/{chain_id}/validate      validate a chain's fix
POST /api/scan/{scan_id}/findings/{finding_id}/validate  validate any finding's fix (code, dependency, secret)
GET  /api/scan/{scan_id}/validations/{validation_id}     poll status, attempts and the final code
GET  /api/scan/{scan_id}/investigations/{investigation_id}  every persisted attempt for the problem
GET  /api/validation-stats                               success rate per attempt

A finding that belongs to a Python attack chain is validated with the chain checks;
any other finding with the single-finding checks (services/finding_validation.py).
Each attempt builds on the previous attempt's improved code, so the last attempt
holds the final code. Nothing here writes to the scanned repository or commits:
fixes are applied to copies of the scanned revision, and the developer applies the
final code.

Every attempt is persisted as it runs (services/validation_history.py). Clicking
Validate Fix again resumes the problem's investigation: numbering continues, the
best code so far is the starting point, and earlier attempts (plus similar fixes
elsewhere) inform the next fix, up to INVESTIGATION_MAX_ATTEMPTS attempts.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from models.schemas import (
    AttemptStatus, ChainFix, FindingCategory, FixEdit, FixValidation, Investigation, ScanStatus, ValidationAttempt,
    ValidationRequest, ValidationStatus, Vulnerability, WeaknessChain,
)
from routers.scan import _compute_summary, _vulns, scans
from services import (
    chain_analysis, finding_validation, fix_validation, flow_analyzer, repo_manager, scan_store, validation_history,
)
from services.secret_scanner import mask_secrets
from utils.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

# Each validation clones a repo and runs Semgrep twice per attempt; keep it bounded
_slots = asyncio.Semaphore(2)
_active: set[str] = set()


def _scan_for_update(scan_id: str) -> dict[str, Any]:
    """Keep the scan in memory while validations update it."""
    scan = scans.get(scan_id)
    if scan is None:
        scan = scan_store.load(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        scans[scan_id] = scan
    scan.setdefault("validations", {})
    return scan


def _validation(scan: dict[str, Any], validation_id: str) -> FixValidation:
    raw = scan["validations"].get(validation_id)
    if raw is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    v = raw if isinstance(raw, FixValidation) else FixValidation.model_validate(raw)
    if v.state == "running" and validation_id not in _active:
        # The server restarted while it ran
        v.state, v.status, v.needs_manual_review = "failed", ValidationStatus.INCONCLUSIVE, True
        v.result = AttemptStatus.ERROR
        v.message = "Validation was interrupted (server restart). Start it again."
    scan["validations"][validation_id] = v
    return v


def _chains(scan: dict[str, Any]) -> list[WeaknessChain]:
    return [c if isinstance(c, WeaknessChain) else WeaknessChain.model_validate(c) for c in scan.get("chains", [])]


def _reserve(scan_id: str, scan: dict[str, Any], request: ValidationRequest, chain_id: Optional[str],
             finding_id: Optional[str], validation_id: str) -> tuple[dict[str, Any], int, int]:
    """Create or resume the problem's investigation and claim it for one run (blocking: MongoDB).

    Returns (investigation, first attempt number, attempts left). A passed or
    exhausted investigation is never silently replaced: the request must ask for
    a new investigation.
    """
    findings = _vulns(scan)
    chain = next((c for c in _chains(scan) if c.id == chain_id), None)
    rule_finding = finding_id or (chain.finding_ids[0] if chain and chain.finding_ids else None)
    finding = next((f for f in findings if f.id == rule_finding), None)
    # What similar fixes are looked up by: the rule, and the vulnerability class where one is known
    vuln_class = chain.kind if chain else ("secret" if finding and finding.category == FindingCategory.SECRET else None)
    inv = validation_history.open_investigation(
        scan_id, validation_history.target_key(chain_id, finding_id), max_attempts=settings.INVESTIGATION_MAX_ATTEMPTS,
        finding_id=finding_id, chain_id=chain_id, rule_id=finding.rule_id if finding else None, vuln_class=vuln_class,
        repo_url=scan.get("repo_url"), file=chain.file if chain else (finding.file if finding else None),
        new=request.new_investigation)
    inv_id = inv["investigation_id"]

    def refuse(code: str, message: str) -> HTTPException:
        return HTTPException(status_code=409, detail={"code": code, "message": message, "investigation_id": inv_id})

    if inv["active_validation_id"]:
        raise refuse("already_running", "A validation for this problem is already running.")
    if inv["status"] == "passed":
        raise refuse("investigation_passed", "This problem's fix already passed validation. Start a new "
                                             "investigation to validate it again.")
    remaining = inv["max_attempts"] - validation_history.attempts_used(inv_id)
    if inv["status"] == "exhausted" or remaining <= 0:
        validation_history.mark_exhausted(inv_id)
        raise refuse("investigation_exhausted", f"This problem has used all {inv['max_attempts']} validation attempts "
                                                "(INVESTIGATION_MAX_ATTEMPTS). Review the attempt history, or start "
                                                "a new investigation.")
    first = validation_history.claim(inv_id, validation_id)
    if first is None:
        raise refuse("already_running", "A validation for this problem is already running.")
    return inv, first, remaining


async def _start(scan_id: str, scan: dict[str, Any], request: ValidationRequest,
                 chain_id: Optional[str], finding_id: Optional[str]) -> FixValidation:
    if scan["status"] not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(status_code=409, detail="Scan is not complete")
    for vid in list(scan["validations"]):
        v = _validation(scan, vid)
        if v.state == "running" and ((chain_id and v.chain_id == chain_id) or (finding_id and v.finding_id == finding_id)):
            raise HTTPException(status_code=409, detail="A validation for this problem is already running")

    validation_id = uuid.uuid4().hex[:10]
    inv, first, remaining = await asyncio.to_thread(_reserve, scan_id, scan, request, chain_id, finding_id,
                                                    validation_id)
    validation = FixValidation(
        id=validation_id, scan_id=scan_id, chain_id=chain_id, finding_id=finding_id,
        investigation_id=inv["investigation_id"], first_attempt=first, result=AttemptStatus.RUNNING,
        max_attempts=min(request.max_attempts or settings.FIX_MAX_ATTEMPTS, remaining),
        started_at=datetime.now(timezone.utc).isoformat(),
        message="Preparing a copy of the scanned code…",
    )
    scan["validations"][validation.id] = validation
    _active.add(validation.id)
    asyncio.create_task(_run(scan_id, validation, request.edits))
    return validation


@router.post("/scan/{scan_id}/chains/{chain_id}/validate", response_model=FixValidation)
async def start_chain_validation(scan_id: str, chain_id: str, request: ValidationRequest) -> FixValidation:
    scan = _scan_for_update(scan_id)
    if not any(c.id == chain_id for c in _chains(scan)):
        raise HTTPException(status_code=404, detail="Chain not found in this scan")
    return await _start(scan_id, scan, request, chain_id, None)


@router.post("/scan/{scan_id}/findings/{finding_id}/validate", response_model=FixValidation)
async def start_finding_validation(scan_id: str, finding_id: str, request: ValidationRequest) -> FixValidation:
    scan = _scan_for_update(scan_id)
    if not any(v.id == finding_id for v in _vulns(scan)):
        raise HTTPException(status_code=404, detail="Finding not found in this scan")
    # A finding on an attack chain gets the deeper chain checks
    chain = next((c for c in _chains(scan) if finding_id in c.finding_ids), None)
    return await _start(scan_id, scan, request, chain.id if chain else None, finding_id)


@router.get("/scan/{scan_id}/validations/{validation_id}", response_model=FixValidation)
async def get_validation(scan_id: str, validation_id: str) -> FixValidation:
    return _validation(_scan_for_update(scan_id), validation_id)


@router.get("/scan/{scan_id}/investigations/{investigation_id}", response_model=Investigation)
async def get_investigation(scan_id: str, investigation_id: str) -> Investigation:
    inv = await asyncio.to_thread(validation_history.get_investigation, investigation_id)
    if inv is None or inv.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/validation-stats")
async def validation_stats() -> dict[str, Any]:
    """Success rate per attempt across all validations, and whether a higher attempt limit would help."""
    validations = []
    for state in await asyncio.to_thread(scan_store.all_states):
        for raw in (state.get("validations") or {}).values():
            try:
                validations.append(FixValidation.model_validate(raw))
            except Exception:
                continue  # older formats
    return fix_validation.attempt_stats(validations, settings.FIX_MAX_ATTEMPTS)


def _adopt(scan: dict[str, Any], v: FixValidation, fix: ChainFix) -> None:
    """A fix that passed becomes the problem's fix, so the results show the verified code."""
    if v.chain_id:
        scan["chains"] = [c.model_copy(update={"fix": fix}) if c.id == v.chain_id else c for c in _chains(scan)]
    if v.finding_id and fix.edits:
        vulns = _vulns(scan)
        for i, f in enumerate(vulns):
            if f.id == v.finding_id:
                vulns[i] = f.model_copy(update={
                    "vulnerable_code": "\n".join(e.original for e in fix.edits),
                    "fixed_code": "\n".join(e.replacement for e in fix.edits),
                })
        scan["vulnerabilities"] = vulns


def _mask(result: fix_validation.LoopResult) -> None:
    """Secret findings: never show the credential in diffs or code."""
    def clean(fix: Optional[ChainFix]) -> Optional[ChainFix]:
        if fix is None:
            return None
        return fix.model_copy(update={"edits": [e.model_copy(update={
            "original": mask_secrets(e.original), "replacement": mask_secrets(e.replacement)}) for e in fix.edits]})
    for a in result.attempts:
        a.diff = mask_secrets(a.diff)
        a.fix = clean(a.fix)
    result.final_fix = clean(result.final_fix)
    result.final_diff = mask_secrets(result.final_diff)


class _Journal:
    """Persists the loop's attempts for one run in MongoDB (fix_validation.Journal)."""

    def __init__(self, v: FixValidation, secret: bool) -> None:
        self.v, self.secret = v, secret
        self.attempt_id: Optional[str] = None
        self.begun = 0  # attempts this run created

    def begin(self, attempt_no: int) -> None:
        self.attempt_id = validation_history.begin_attempt(self.v.investigation_id, self.v.id, attempt_no)
        self.begun += 1
        self.v.message = f"Attempt {attempt_no}: generating a fix…"

    def generated(self, fix: ChainFix) -> None:
        validation_history.set_fix(self.attempt_id, _mask_fix(fix) if self.secret else fix)
        self.v.message = "Applying the fix to a copy of the code…"

    def hashed(self, code_hash: str) -> Optional[str]:
        validation_history.set_code_hash(self.attempt_id, code_hash)
        self.v.message = "Checking the fix…"
        return validation_history.known_snapshot(self.v.investigation_id, code_hash)

    def close(self, status: AttemptStatus, reason: str) -> None:
        validation_history.close_attempt(self.attempt_id, status, reason)
        self.attempt_id = None

    def finish(self, attempt: ValidationAttempt) -> None:
        if self.secret:
            attempt = attempt.model_copy(update={"diff": mask_secrets(attempt.diff), "fix": _mask_fix(attempt.fix)})
        validation_history.finish_attempt(self.attempt_id, attempt)
        self.attempt_id = None

    def crashed(self, reason: str) -> None:
        """The run failed: its running attempt becomes ERROR; a run that failed before
        its first attempt (e.g. the clone) still leaves one ERROR attempt behind."""
        if not self.begun:
            self.attempt_id = validation_history.begin_attempt(
                self.v.investigation_id, self.v.id, self.v.first_attempt, phase="setup")
        validation_history.fail_running(self.v.id, reason)


def _mask_fix(fix: ChainFix) -> ChainFix:
    return fix.model_copy(update={"edits": [e.model_copy(update={
        "original": mask_secrets(e.original), "replacement": mask_secrets(e.replacement)}) for e in fix.edits]})


def _resume(investigation_id: str, developer_edits: bool) -> Optional[fix_validation.Resume]:
    """Earlier attempts of this investigation and the best code they reached (blocking: MongoDB)."""
    history = validation_history.history(investigation_id)
    if not history:
        return None
    resume = fix_validation.Resume(history)
    if developer_edits:
        return resume  # the developer's edits are against the original code
    best_fix, best_attempt = validation_history.best(investigation_id)
    best = next((a for a in history if a.attempt == best_attempt), None)
    if best_fix is not None and best is not None:
        resume.best_fix, resume.best = best_fix, best
    return resume


async def _run(scan_id: str, v: FixValidation, edits: Optional[list[FixEdit]]) -> None:
    scan = scans[scan_id]
    workspace = settings.TEMP_DIR / f"validation-{v.id}"
    secret = v.finding_id is not None and any(
        f.id == v.finding_id and f.category == FindingCategory.SECRET for f in _vulns(scan))
    journal = _Journal(v, secret)
    state = "failed"
    try:
        async with _slots:
            original = workspace / "original"
            sha = await asyncio.to_thread(repo_manager.clone_at_commit, scan["repo_url"], original, scan.get("commit"))
            v.message = "Re-analysing the scanned code…"
            findings = _vulns(scan)
            finding: Optional[Vulnerability] = next((f for f in findings if f.id == v.finding_id), None)
            use_ai = bool(settings.GROQ_API_KEY)
            target: Optional[fix_validation.Target] = None
            inv = await asyncio.to_thread(validation_history.get_investigation, v.investigation_id)
            # History from comparable cases: strategy order (rule-based and LLM) and LLM context
            similar = await asyncio.to_thread(
                validation_history.similar, rule_id=inv.rule_id, vuln_class=inv.vuln_class,
                repo_url=scan.get("repo_url"), file=inv.file,
                exclude_investigation=v.investigation_id)
            stats = await asyncio.to_thread(
                validation_history.strategy_stats, rule_id=inv.rule_id, vuln_class=inv.vuln_class,
                exclude_investigation=v.investigation_id)
            lessons = validation_history.lessons(similar, stats)

            if v.chain_id:
                analysis = await asyncio.to_thread(flow_analyzer.analyze_repository, original)
                chains = await asyncio.to_thread(chain_analysis.build_chains, analysis, findings, original)
                chain = next((c for c in chains if c.id == v.chain_id), None)
                if chain is not None:
                    baseline = fix_validation.Baseline(original, analysis, chains, scan.get("languages", []))
                    target = fix_validation.ChainTarget(
                        chain, baseline, fix_validation.semgrep_scanner, use_ai,
                        fix_validation.developer_fix(edits, chain, original) if edits else None,
                        settings.VALIDATION_TEST_COMMAND, settings.VALIDATION_TEST_TIMEOUT, lessons, stats)
                elif finding is None:
                    raise RuntimeError("The chain could not be reproduced on the checked-out code.")
            if target is None and finding is not None:
                v.chain_id = None  # chain no longer reproducible: fall back to the finding's own checks
                target = finding_validation.FindingTarget(
                    finding, original, scan.get("languages", []), fix_validation.semgrep_scanner, use_ai,
                    fix_validation.developer_fix(edits, None, original, finding.id) if edits else None,
                    findings, lessons, stats)
            if target is None:
                raise RuntimeError("Nothing to validate.")

            v.message = "Generating a fix…"
            resume = await asyncio.to_thread(_resume, v.investigation_id, bool(edits))
            result = await fix_validation.run_loop(
                target, workspace, v.max_attempts, on_attempt=v.attempts.append, first_attempt=v.first_attempt,
                resume=resume, journal=journal)
            if secret:
                _mask(result)
            v.attempts = result.attempts
            v.status, v.message, v.needs_manual_review = result.status, result.message, result.needs_manual_review
            v.result = result.result
            v.stop_reason, v.best_attempt = result.stop_reason, result.best_attempt
            v.final_fix, v.final_diff = result.final_fix, result.final_diff
            if result.final_fix and result.best_attempt:
                await asyncio.to_thread(validation_history.record_best, v.investigation_id, result.final_fix,
                                        result.best_attempt)
            if result.status == ValidationStatus.PASS and result.final_fix:
                _adopt(scan, v, result.final_fix)
            if not scan.get("commit") and sha:
                v.message += f" (The scan recorded no commit; validated against the current HEAD {sha[:8]}.)"
            logger.info("Validation %s: %s after %d attempt(s) (%s)", v.id, result.status.value,
                        len(result.attempts), result.stop_reason)
            state = "complete"
    except Exception as e:
        logger.exception("Validation %s failed", v.id)
        v.status, v.needs_manual_review = ValidationStatus.INCONCLUSIVE, True
        v.result = AttemptStatus.ERROR
        v.message = f"Validation could not run: {e}"
        try:
            await asyncio.to_thread(journal.crashed, f"The validation crashed: {type(e).__name__}: {e}")
        except Exception:
            logger.exception("Could not record the failed attempt of validation %s", v.id)
    finally:
        try:
            await asyncio.to_thread(validation_history.release, v.investigation_id, v.id)
        except Exception:
            logger.exception("Could not release investigation %s", v.investigation_id)
        # Only now does the run look finished: a click right after it must find the investigation free
        v.state = state
        _active.discard(v.id)
        v.finished_at = datetime.now(timezone.utc).isoformat()
        try:
            scan_store.save(scan_id, scan, _compute_summary(_vulns(scan)).model_dump())
        except Exception:
            logger.exception("Could not persist validation %s", v.id)
        if not settings.VALIDATION_KEEP_WORKSPACE:
            shutil.rmtree(workspace, onerror=repo_manager._force_remove)
