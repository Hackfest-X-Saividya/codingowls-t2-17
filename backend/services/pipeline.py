"""The analysis pipeline, shared by the web API (routers/scan.py) and the CLI (cli.py).

Given a checked-out repository, runs every detector and returns the findings:

    detect languages -> Semgrep (code) -> parse SARIF
                     -> OSV (dependencies)
                     -> secret scanner
                     -> chain-of-weakness analysis (data flow + all findings)
                     -> LLM enhancement of code findings, with their chain as context
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from models.schemas import FindingCategory, ScanStep, Vulnerability, WeaknessChain
from services import (
    ai_enhancer, chain_analysis, dependency_scanner, flow_analyzer, repo_manager, sarif_parser, secret_scanner,
    semgrep_runner,
)

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# on_step(step, done): called with done=False when a step starts, True when it ends
StepCallback = Callable[[ScanStep, bool], None]


@dataclass
class PipelineResult:
    languages: list[str]
    findings: list[Vulnerability]
    warnings: list[str] = field(default_factory=list)
    chains: list[WeaknessChain] = field(default_factory=list)
    chain_stats: dict[str, int] = field(default_factory=dict)


async def analyze(
    repo_path: Path,
    scan_id: str,
    on_step: Optional[StepCallback] = None,
    use_ai: bool = True,
) -> PipelineResult:
    step = on_step or (lambda _s, _d: None)
    warnings: list[str] = []

    step(ScanStep.DETECT_LANGUAGE, False)
    languages = repo_manager.detect_languages(repo_path)
    if not languages:
        warnings.append("No supported programming language detected; ran generic rules only.")
    step(ScanStep.DETECT_LANGUAGE, True)

    step(ScanStep.ANALYZE, False)
    sarif_path = await semgrep_runner.run_scan(repo_path, languages, scan_id)
    step(ScanStep.ANALYZE, True)

    step(ScanStep.PARSE_RESULTS, False)
    code_findings = sarif_parser.parse_sarif(sarif_path, repo_path)
    step(ScanStep.PARSE_RESULTS, True)

    step(ScanStep.SCAN_DEPENDENCIES, False)
    dep_findings, dep_warnings = await dependency_scanner.scan_dependencies(repo_path)
    warnings += dep_warnings
    step(ScanStep.SCAN_DEPENDENCIES, True)

    step(ScanStep.SCAN_SECRETS, False)
    secret_findings, secret_warnings = secret_scanner.scan_secrets(repo_path)
    warnings += secret_warnings
    # Semgrep's own secret rules can flag the same line; keep the masked version only
    secret_lines = {(v.file, v.line) for v in secret_findings}
    code_findings = [
        v for v in code_findings
        if not ((v.file, v.line) in secret_lines and "secret" in v.rule_id.lower())
    ]
    step(ScanStep.SCAN_SECRETS, True)

    step(ScanStep.CHAIN_ANALYSIS, False)
    chains, chain_warnings, chain_stats = await build_chains(
        repo_path, languages, code_findings + dep_findings + secret_findings)
    warnings += chain_warnings
    step(ScanStep.CHAIN_ANALYSIS, True)

    # Only code findings go to the LLM: dependency + secret findings already carry
    # authoritative advisory text / fix steps, and skipping them saves API quota.
    step(ScanStep.AI_ENHANCE, False)
    context = {fid: chain_analysis.chain_context(c) for c in reversed(chains) for fid in c.finding_ids}
    code_findings = await ai_enhancer.enhance_vulnerabilities(code_findings, use_ai=use_ai, context=context)
    step(ScanStep.AI_ENHANCE, True)

    findings = code_findings + dep_findings + secret_findings
    findings.sort(key=lambda v: (SEVERITY_RANK.get(v.severity, 9), v.category != FindingCategory.CODE, v.file, v.line))
    logger.info(
        "Pipeline done: %d code, %d dependency, %d secret findings, %d chains",
        len(code_findings), len(dep_findings), len(secret_findings), len(chains),
    )
    return PipelineResult(languages=languages, findings=findings, warnings=warnings, chains=chains,
                          chain_stats=chain_stats)


async def build_chains(
    repo_path: Path, languages: list[str], findings: list[Vulnerability],
) -> tuple[list[WeaknessChain], list[str], dict[str, int]]:
    """Data-flow analysis + chain construction; never fails the scan.

    The stats let the UI say why a scan has no chains (no Python vs. nothing found).
    """
    warnings: list[str] = []
    try:
        analysis = await asyncio.to_thread(flow_analyzer.analyze_repository, repo_path)
        chains = await asyncio.to_thread(chain_analysis.build_chains, analysis, findings, repo_path)
    except Exception:
        logger.exception("Chain analysis failed")
        return [], ["Chain-of-weakness analysis failed; findings are shown individually."], {"failed": 1}
    stats = {"python_files": len(analysis.files) - len(analysis.errors), "flows": len(analysis.flows),
             "endpoints": sum(len(m.endpoints) for m in analysis.modules.values())}
    other = [lang for lang in languages if lang != "python"]
    if other:
        warnings.append(f"Chain-of-weakness analysis covers Python only; {', '.join(other)} findings are shown individually.")
    if analysis.errors:
        warnings.append(f"{len(analysis.errors)} Python file(s) could not be parsed for chain analysis: "
                        + ", ".join(sorted(analysis.errors)[:5]))
    warnings += analysis.notes
    return chains, warnings, stats
