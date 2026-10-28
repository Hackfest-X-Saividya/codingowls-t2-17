from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from models.schemas import Vulnerability

logger = logging.getLogger(__name__)

# Map SARIF severity levels to our severity scale
SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

# Rule ID patterns that indicate critical severity
CRITICAL_PATTERNS: list[str] = [
    "sql-injection",
    "sqli",
    "tainted-sql",
    "formatted-sql",
    "command-injection",
    "code-injection",
    "unsafe-deserialization",
    "insecure-deserialization",
    "path-traversal",
    "arbitrary-file",
]


def parse_sarif(sarif_path: Path, repo_path: Path) -> list[Vulnerability]:
    """Parse a SARIF file and extract vulnerability information.

    Works with both CodeQL and Semgrep SARIF output.
    Returns a list of Vulnerability objects.
    """
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error("Failed to parse SARIF file: %s", e)
        return []

    vulnerabilities: list[Vulnerability] = []
    vuln_counter = 0

    for run in sarif_data.get("runs", []):
        rules = _build_rule_index(run)
        results = run.get("results", [])

        for result in results:
            vuln_counter += 1
            vuln = _parse_result(result, rules, repo_path, vuln_counter)
            if vuln:
                vulnerabilities.append(vuln)

    logger.info("Parsed %d vulnerabilities from SARIF", len(vulnerabilities))
    return vulnerabilities


def _build_rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build an index of rule ID -> rule metadata from the SARIF run."""
    rules: dict[str, dict[str, Any]] = {}
    tool = run.get("tool", {})
    driver = tool.get("driver", {})

    for rule in driver.get("rules", []):
        rule_id = rule.get("id", "")
        rules[rule_id] = rule

    return rules


def _first_sentence(text: str, limit: int = 120) -> str:
    """First sentence of a message, cut at a word boundary if still too long."""
    sentence = text.strip().split("\n", 1)[0]
    end = sentence.find(". ")
    if end > 0:
        sentence = sentence[:end + 1]
    if len(sentence) > limit:
        sentence = sentence[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"
    return sentence


def _is_critical(rule_id: str, message: str) -> bool:
    """Check if a finding should be elevated to critical severity."""
    text = (rule_id + " " + message).lower()
    return any(pattern in text for pattern in CRITICAL_PATTERNS)


def _parse_result(
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    repo_path: Path,
    index: int,
) -> Vulnerability | None:
    """Parse a single SARIF result into a Vulnerability object."""
    rule_id = result.get("ruleId", "unknown")
    rule = rules.get(rule_id, {})

    # Extract severity from SARIF level
    sarif_level = result.get("level", "warning")
    scanner_severity = SEVERITY_MAP.get(sarif_level, "medium")

    # Extract message
    message = result.get("message", {}).get("text", "Security issue detected")

    # Upgrade to critical for known dangerous patterns
    severity = "critical" if _is_critical(rule_id, message) else scanner_severity

    # Extract title from rule metadata (try multiple SARIF fields)
    title = rule.get("shortDescription", {}).get("text", "")
    if title.startswith("Semgrep Finding:") or not title:
        # Semgrep's shortDescription is just "Semgrep Finding: <rule id>"; the
        # message holds the human-readable description, so use its first sentence
        title = _first_sentence(message) or title or rule.get("name", "")

    # Extract location info
    locations = result.get("locations", [])
    if not locations:
        return None

    location = locations[0].get("physicalLocation", {})
    artifact = location.get("artifactLocation", {})
    region = location.get("region", {})

    file_path = artifact.get("uri", "unknown")
    # Make path relative to repo root
    if file_path.startswith("file://"):
        file_path = file_path[7:]
    try:
        file_path = Path(file_path).relative_to(repo_path).as_posix()
    except ValueError:
        file_path = file_path.replace("\\", "/")  # Keep as-is if not relative to repo

    line = region.get("startLine", 0)
    end_line = region.get("endLine", line)

    # Try to extract the vulnerable code snippet
    snippet = region.get("snippet", {}).get("text", "")
    if not snippet:
        snippet = _read_code_snippet(repo_path, file_path, line, end_line)

    return Vulnerability(
        id=f"vuln_{index:03d}",
        title=title,
        severity=severity,
        scanner_severity=scanner_severity,
        file=file_path,
        line=line,
        end_line=end_line,
        rule_id=rule_id,
        vulnerable_code=snippet,
    )


def _read_code_snippet(
    repo_path: Path, file_path: str, start_line: int, end_line: int
) -> str:
    """Read a code snippet from the source file."""
    try:
        full_path = repo_path / file_path
        if not full_path.exists():
            return ""

        # Ensure we don't traverse outside repo
        full_path = full_path.resolve()
        if not str(full_path).startswith(str(repo_path.resolve())):
            return ""

        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        # Provide context: 2 lines before and after
        context_start = max(0, start_line - 3)
        context_end = min(len(lines), end_line + 2)
        return "\n".join(lines[context_start:context_end])
    except Exception as e:
        logger.debug("Could not read snippet from %s: %s", file_path, e)
        return ""
