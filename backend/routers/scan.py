from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, Response

from models.schemas import (
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanResultsResponse,
    ScanStatus,
    ScanStatusResponse,
    ScanStep,
    ScanSummary,
    STEP_LABELS,
    STEP_WEIGHTS,
    FixValidation,
    Vulnerability,
    WeaknessChain,
)
from services import pdf_report, pipeline, repo_manager, sarif_export, scan_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

# Running scans (progress changes constantly); finished scans are also in scan_store
scans: dict[str, dict[str, Any]] = {}

ALL_STEPS = list(ScanStep)


def _compute_progress(completed_steps: list[ScanStep]) -> int:
    """Compute overall progress percentage from completed steps."""
    total_weight = sum(STEP_WEIGHTS.values())
    completed_weight = sum(STEP_WEIGHTS[s] for s in completed_steps)
    return int((completed_weight / total_weight) * 100)


def _get_scan(scan_id: str) -> dict[str, Any]:
    """Look up a scan in memory first, then in persistent storage."""
    scan = scans.get(scan_id) or scan_store.load(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _vulns(scan: dict[str, Any]) -> list[Vulnerability]:
    return [v if isinstance(v, Vulnerability) else Vulnerability.model_validate(v)
            for v in scan.get("vulnerabilities", [])]


@router.post("/scan", response_model=ScanResponse)
async def initiate_scan(request: ScanRequest) -> ScanResponse:
    """Start a new security scan on a GitHub repository."""
    scan_id = uuid.uuid4().hex[:12]

    scans[scan_id] = {
        "status": ScanStatus.PENDING,
        "progress": 0,
        "current_step": "",
        "steps_completed": [],
        "steps_remaining": [s.value for s in ALL_STEPS],
        "repo_url": request.repo_url,
        "repo_name": repo_manager.extract_repo_name(request.repo_url),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "language": "",
        "languages": [],
        "vulnerabilities": [],
        "warnings": [],
        "chains": [],
        "validations": {},
        "commit": None,
        "error": None,
    }

    # Launch background scan task
    asyncio.create_task(_run_scan(scan_id, request.repo_url))

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="Scan initiated successfully",
    )


@router.get("/scans", response_model=list[ScanHistoryItem])
async def list_scans(limit: int = Query(20, ge=1, le=100)) -> list[ScanHistoryItem]:
    """Recent scans, newest first (running scans included)."""
    items: dict[str, ScanHistoryItem] = {}
    for row in scan_store.recent(limit):
        items[row["scan_id"]] = ScanHistoryItem(**row)
    for scan_id, s in scans.items():
        if s["status"] in (ScanStatus.PENDING, ScanStatus.RUNNING):
            items[scan_id] = ScanHistoryItem(
                scan_id=scan_id, repo_url=s["repo_url"], repo_name=s["repo_name"],
                status=s["status"], started_at=s["started_at"],
            )
    return sorted(items.values(), key=lambda i: i.started_at, reverse=True)[:limit]


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    """Get the current status of a scan."""
    scan = _get_scan(scan_id)

    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan["status"],
        progress=scan["progress"],
        current_step=scan["current_step"],
        steps_completed=scan["steps_completed"],
        steps_remaining=scan["steps_remaining"],
        error=scan.get("error"),
    )


@router.get("/scan/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str) -> ScanResultsResponse:
    """Get the results of a completed scan."""
    scan = _get_scan(scan_id)

    if scan["status"] in (ScanStatus.PENDING, ScanStatus.RUNNING, "pending", "running"):
        raise HTTPException(status_code=202, detail="Scan still in progress")

    if scan["status"] in (ScanStatus.FAILED, "failed"):
        raise HTTPException(status_code=500, detail=scan.get("error", "Scan failed"))

    vulns = _vulns(scan)
    return ScanResultsResponse(
        scan_id=scan_id,
        repo_url=scan["repo_url"],
        repo_name=scan["repo_name"],
        scanned_at=scan["started_at"],
        language=scan.get("language", "unknown"),
        languages=scan.get("languages", []),
        summary=_compute_summary(vulns),
        vulnerabilities=vulns,
        warnings=scan.get("warnings", []),
        chains=[c if isinstance(c, WeaknessChain) else WeaknessChain.model_validate(c)
                for c in scan.get("chains", [])],
        validations=[v if isinstance(v, FixValidation) else FixValidation.model_validate(v)
                     for v in (scan.get("validations") or {}).values()],
        chain_stats=scan.get("chain_stats"),
    )


@router.get("/scan/{scan_id}/sarif")
async def get_scan_sarif(scan_id: str) -> JSONResponse:
    """Download results as SARIF 2.1.0 (for GitHub code scanning and other tools)."""
    scan = _get_scan(scan_id)
    if scan["status"] not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(status_code=409, detail="Scan is not complete")
    return JSONResponse(
        sarif_export.to_sarif(_vulns(scan)),
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.sarif"'},
    )


@router.get("/scan/{scan_id}/pdf")
async def get_scan_pdf(scan_id: str) -> Response:
    """Download a PDF report containing every finding."""
    scan = _get_scan(scan_id)
    if scan["status"] not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(status_code=409, detail="Scan is not complete")

    # Rendering a few hundred findings takes a moment; keep the event loop free
    pdf = await asyncio.to_thread(
        pdf_report.render_pdf,
        repo_name=scan["repo_name"],
        repo_url=scan["repo_url"],
        scanned_at=scan["started_at"],
        languages=scan.get("languages", []),
        findings=_vulns(scan),
        warnings=scan.get("warnings", []),
        scan_id=scan_id,
    )
    filename = f"security-report-{scan['repo_name'].replace('/', '-')}-{scan_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _compute_summary(vulns: list[Vulnerability]) -> ScanSummary:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category: dict[str, int] = {}
    for v in vulns:
        sev = v.severity.lower()
        if sev in counts:
            counts[sev] += 1
        by_category[v.category.value] = by_category.get(v.category.value, 0) + 1
    return ScanSummary(total=len(vulns), by_category=by_category, **counts)


def _mark_step(scan_id: str, step: ScanStep) -> None:
    """Mark a step as the current step and update progress."""
    scan = scans[scan_id]
    scan["status"] = ScanStatus.RUNNING
    scan["current_step"] = STEP_LABELS[step]

    completed = [s for s in ALL_STEPS if s.value in scan["steps_completed"]]
    scan["progress"] = _compute_progress(completed)
    scan["steps_remaining"] = [
        s.value for s in ALL_STEPS if s.value not in scan["steps_completed"]
    ]


def _complete_step(scan_id: str, step: ScanStep) -> None:
    """Mark a step as completed."""
    scan = scans[scan_id]
    if step.value not in scan["steps_completed"]:
        scan["steps_completed"].append(step.value)

    completed = [s for s in ALL_STEPS if s.value in scan["steps_completed"]]
    scan["progress"] = _compute_progress(completed)
    scan["steps_remaining"] = [
        s.value for s in ALL_STEPS if s.value not in scan["steps_completed"]
    ]


def _persist(scan_id: str, vulns: Optional[list[Vulnerability]] = None) -> None:
    scan = scans[scan_id]
    scan["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary = _compute_summary(vulns or []).model_dump()
    try:
        scan_store.save(scan_id, scan, summary)
    except Exception:  # history is best-effort; never fail the scan over it
        logger.exception("Could not persist scan %s", scan_id)


async def _run_scan(scan_id: str, repo_url: str) -> None:
    """Execute the full scan pipeline in the background."""

    def on_step(step: ScanStep, done: bool) -> None:
        (_complete_step if done else _mark_step)(scan_id, step)

    try:
        on_step(ScanStep.CLONE_REPO, False)
        repo_path = await repo_manager.clone_repository(repo_url, scan_id)
        # Fix validation re-clones exactly this revision, since the checkout is deleted below
        scans[scan_id]["commit"] = repo_manager.head_commit(repo_path)
        on_step(ScanStep.CLONE_REPO, True)

        result = await pipeline.analyze(repo_path, scan_id, on_step=on_step)

        scans[scan_id]["languages"] = result.languages
        scans[scan_id]["language"] = ", ".join(result.languages) or "unknown"
        scans[scan_id]["warnings"] = result.warnings
        scans[scan_id]["vulnerabilities"] = result.findings
        scans[scan_id]["chains"] = result.chains
        scans[scan_id]["chain_stats"] = result.chain_stats
        scans[scan_id]["status"] = ScanStatus.COMPLETE
        scans[scan_id]["progress"] = 100
        scans[scan_id]["current_step"] = "Scan complete"
        scans[scan_id]["steps_remaining"] = []
        _persist(scan_id, result.findings)

        logger.info(
            "Scan %s complete: %d findings", scan_id, len(result.findings)
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scans[scan_id]["status"] = ScanStatus.FAILED
        scans[scan_id]["error"] = str(e) or type(e).__name__
        scans[scan_id]["current_step"] = f"Failed: {e}"
        _persist(scan_id)

    finally:
        # Clean up cloned repo (keep results in memory and in scan_store)
        repo_manager.cleanup_scan(scan_id)
