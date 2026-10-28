from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

from utils.config import settings

logger = logging.getLogger(__name__)

# Semgrep rulesets for each language
RULESETS: dict[str, list[str]] = {
    "python": [
        "p/python",
        "p/flask",
        "p/django",
        "p/owasp-top-ten",
    ],
    "javascript": [
        "p/javascript",
        "p/nodejs",
        "p/owasp-top-ten",
    ],
    "java": [
        "p/java",
        "p/owasp-top-ten",
    ],
    "go": [
        "p/golang",
        "p/owasp-top-ten",
    ],
    "ruby": [
        "p/ruby",
        "p/owasp-top-ten",
    ],
    "php": [
        "p/php",
        "p/owasp-top-ten",
    ],
}

# Default ruleset for any language
DEFAULT_RULESETS = ["p/owasp-top-ten", "p/security-audit"]


def rulesets_for(languages: list[str]) -> list[str]:
    """Union of the rulesets for every detected language, in a stable order."""
    rulesets: list[str] = []
    for language in languages or [""]:
        for ruleset in RULESETS.get(language, DEFAULT_RULESETS):
            if ruleset not in rulesets:
                rulesets.append(ruleset)
    return rulesets


async def run_scan(repo_path: Path, languages: list[str], scan_id: str) -> Path:
    """Run Semgrep analysis on a repository and output SARIF results.

    Returns the path to the SARIF output file.
    """
    sarif_path = settings.TEMP_DIR / scan_id / "results.sarif"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)

    rulesets = rulesets_for(languages)
    config_args: list[str] = []
    for ruleset in rulesets:
        config_args.extend(["--config", ruleset])

    cmd = [
        "semgrep",
        "scan",
        *config_args,
        "--sarif",
        "--output", str(sarif_path),
        "--metrics=off",
        str(repo_path),
    ]

    logger.info("Running Semgrep: %s", " ".join(cmd))

    # Run in a thread: asyncio subprocesses are unsupported on Windows'
    # SelectorEventLoop (used by uvicorn --reload) and raise NotImplementedError.
    proc = await asyncio.to_thread(
        subprocess.run,
        cmd,
        capture_output=True,
        timeout=settings.SCAN_TIMEOUT_SECONDS,
        # Force UTF-8: on Windows Semgrep otherwise writes SARIF as cp1252
        # and crashes on emoji in rule metadata.
        env={**os.environ, "PYTHONUTF8": "1"},
    )

    stdout_text = proc.stdout.decode(errors="replace").strip()
    stderr_text = proc.stderr.decode(errors="replace").strip()

    logger.info("Semgrep rc=%d", proc.returncode)
    if stdout_text:
        logger.info("Semgrep stdout: %s", stdout_text[:1000])
    if stderr_text:
        logger.info("Semgrep stderr: %s", stderr_text[:1000])

    # Semgrep returns 0 for clean, 1 for findings, other codes for errors
    if proc.returncode not in (0, 1):
        logger.error("Semgrep failed (rc=%d): %s", proc.returncode, stderr_text)
        raise RuntimeError(f"Semgrep analysis failed: {stderr_text[:200]}")

    if not sarif_path.exists():
        logger.warning("Semgrep produced no SARIF output file")
        # Create empty SARIF if no output (clean scan)
        empty_sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": []}}, "results": []}],
        }
        with open(sarif_path, "w") as f:
            json.dump(empty_sarif, f)

    # Count results and log SARIF details
    try:
        with open(sarif_path, encoding="utf-8") as f:
            data = json.load(f)
        result_count = sum(len(run.get("results", [])) for run in data.get("runs", []))
        rule_count = sum(
            len(run.get("tool", {}).get("driver", {}).get("rules", []))
            for run in data.get("runs", [])
        )
        logger.info(
            "Semgrep analysis complete. %d findings, %d rules loaded. Output: %s",
            result_count, rule_count, sarif_path,
        )
    except Exception:
        logger.info("Semgrep analysis complete. Output: %s", sarif_path)

    return sarif_path


async def check_semgrep_installed() -> bool:
    """Check if Semgrep CLI is installed and accessible."""
    try:
        proc = await asyncio.to_thread(
            subprocess.run, ["semgrep", "--version"], capture_output=True
        )
        version = proc.stdout.decode().strip()
        logger.info("Semgrep version: %s", version)
        return proc.returncode == 0
    except FileNotFoundError:
        logger.warning("Semgrep not found")
        return False
