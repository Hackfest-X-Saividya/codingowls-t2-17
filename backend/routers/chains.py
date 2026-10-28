"""Fix validation API, for attack chains and for every single finding.

POST /api/scan/{scan_id}/chains/{chain_id}/validate      validate a chain's fix
POST /api/scan/{scan_id}/findings/{finding_id}/validate  validate any finding's fix (code, dependency, secret)
GET  /api/scan/{scan_id}/validations/{validation_id}     poll status, attempts and the final code
GET  /api/validation-stats                               success rate per attempt

A finding that belongs to a Python attack chain is validated with the chain checks;
any other finding with the single-finding checks (services/finding_validation.py).
Each attempt builds on the previous attempt's improved code, so the last attempt
holds the final code. Nothing here writes to the scanned repository or commits:
fixes are applied to copies of the scanned revision, and the developer applies the
final code.
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
    ChainFix, FindingCategory, FixEdit, FixValidation, ScanStatus, ValidationRequest, ValidationStatus, Vulnerability,
    WeaknessChain,
)
from routers.scan import _compute_summary, _vulns, scans
from services import chain_analysis, finding_validation, fix_validation, flow_analyzer, repo_manager, scan_store
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
        v.message = "Validation was interrupted (server restart). Start it again."
    scan["validations"][validation_id] = v
    return v


def _chains(scan: dict[str, Any]) -> list[WeaknessChain]:
    return [c if isinstance(c, WeaknessChain) else WeaknessChain.model_validate(c) for c in scan.get("chains", [])]


def _start(scan_id: str, scan: dict[str, Any], request: ValidationRequest,
           chain_id: Optional[str], finding_id: Optional[str]) -> FixValidation:
    if scan["status"] not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(status_code=409, detail="Scan is not complete")
    for vid in list(scan["validations"]):
        v = _validation(scan, vid)
        if v.state == "running" and ((chain_id and v.chain_id == chain_id) or (finding_id and v.finding_id == finding_id)):
            raise HTTPException(status_code=409, detail="A validation for this problem is already running")
    validation = FixValidation(
        id=uuid.uuid4().hex[:10], scan_id=scan_id, chain_id=chain_id, finding_id=finding_id,
        max_attempts=request.max_attempts or settings.FIX_MAX_ATTEMPTS,
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
    return _start(scan_id, scan, request, chain_id, None)


@router.post("/scan/{scan_id}/findings/{finding_id}/validate", response_model=FixValidation)
async def start_finding_validation(scan_id: str, finding_id: str, request: ValidationRequest) -> FixValidation:
    scan = _scan_for_update(scan_id)
    if not any(v.id == finding_id for v in _vulns(scan)):
        raise HTTPException(status_code=404, detail="Finding not found in this scan")
    # A finding on an attack chain gets the deeper chain checks
    chain = next((c for c in _chains(scan) if finding_id in c.finding_ids), None)
    return _start(scan_id, scan, request, chain.id if chain else None, finding_id)


@router.get("/scan/{scan_id}/validations/{validation_id}", response_model=FixValidation)
async def get_validation(scan_id: str, validation_id: str) -> FixValidation:
    return _validation(_scan_for_update(scan_id), validation_id)


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


async def _run(scan_id: str, v: FixValidation, edits: Optional[list[FixEdit]]) -> None:
    scan = scans[scan_id]
    workspace = settings.TEMP_DIR / f"validation-{v.id}"
    try:
        async with _slots:
            original = workspace / "original"
            sha = await asyncio.to_thread(repo_manager.clone_at_commit, scan["repo_url"], original, scan.get("commit"))
            v.message = "Re-analysing the scanned code…"
            findings = _vulns(scan)
            finding: Optional[Vulnerability] = next((f for f in findings if f.id == v.finding_id), None)
            use_ai = bool(settings.GROQ_API_KEY)
            target: Optional[fix_validation.Target] = None

            if v.chain_id:
                analysis = await asyncio.to_thread(flow_analyzer.analyze_repository, original)
                chains = await asyncio.to_thread(chain_analysis.build_chains, analysis, findings, original)
                chain = next((c for c in chains if c.id == v.chain_id), None)
                if chain is not None:
                    baseline = fix_validation.Baseline(original, analysis, chains, scan.get("languages", []))
                    target = fix_validation.ChainTarget(
                        chain, baseline, fix_validation.semgrep_scanner, use_ai,
                        fix_validation.developer_fix(edits, chain, original) if edits else None,
                        settings.VALIDATION_TEST_COMMAND, settings.VALIDATION_TEST_TIMEOUT)
                elif finding is None:
                    raise RuntimeError("The chain could not be reproduced on the checked-out code.")
            if target is None and finding is not None:
                v.chain_id = None  # chain no longer reproducible: fall back to the finding's own checks
                target = finding_validation.FindingTarget(
                    finding, original, scan.get("languages", []), fix_validation.semgrep_scanner, use_ai,
                    fix_validation.developer_fix(edits, None, original, finding.id) if edits else None,
                    findings)
            if target is None:
                raise RuntimeError("Nothing to validate.")

            v.message = "Applying the fix and checking it…"
            result = await fix_validation.run_loop(target, workspace, v.max_attempts, on_attempt=v.attempts.append)
            if finding is not None and finding.category == FindingCategory.SECRET:
                _mask(result)
            v.attempts = result.attempts
            v.status, v.message, v.needs_manual_review = result.status, result.message, result.needs_manual_review
            v.stop_reason, v.best_attempt = result.stop_reason, result.best_attempt
            v.final_fix, v.final_diff = result.final_fix, result.final_diff
            if result.status == ValidationStatus.PASS and result.final_fix:
                _adopt(scan, v, result.final_fix)
            if not scan.get("commit") and sha:
                v.message += f" (The scan recorded no commit; validated against the current HEAD {sha[:8]}.)"
            logger.info("Validation %s: %s after %d attempt(s) (%s)", v.id, result.status.value,
                        len(result.attempts), result.stop_reason)
            v.state = "complete"
    except Exception as e:
        logger.exception("Validation %s failed", v.id)
        v.state, v.status, v.needs_manual_review = "failed", ValidationStatus.INCONCLUSIVE, True
        v.message = f"Validation could not run: {e}"
    finally:
        _active.discard(v.id)
        v.finished_at = datetime.now(timezone.utc).isoformat()
        try:
            scan_store.save(scan_id, scan, _compute_summary(_vulns(scan)).model_dump())
        except Exception:
            logger.exception("Could not persist validation %s", v.id)
        if not settings.VALIDATION_KEEP_WORKSPACE:
            shutil.rmtree(workspace, onerror=repo_manager._force_remove)
