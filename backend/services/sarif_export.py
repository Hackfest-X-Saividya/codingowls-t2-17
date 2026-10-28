"""Export findings as SARIF 2.1.0.

The output can be uploaded to GitHub code scanning
(github/codeql-action/upload-sarif) so findings show up in the repo's
Security tab and as pull-request annotations, alongside CodeQL.
"""
from __future__ import annotations

from typing import Any

from models.schemas import Vulnerability

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "AI Security Scanner"

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub maps security-severity to Critical (>=9), High (>=7), Medium (>=4), Low
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def _rule_id(v: Vulnerability) -> str:
    # Dependency rule ids contain " (CVE-...)"; keep the bare advisory id
    return v.rule_id.split(" ", 1)[0] or "unknown"


def to_sarif(findings: list[Vulnerability], version: str = "1.0.0") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for v in findings:
        rid = _rule_id(v)
        category = v.category.value if hasattr(v.category, "value") else str(v.category)
        if rid not in rules:
            help_text = v.ai_explanation or v.title
            if v.fixed_code:
                help_text += f"\n\nSuggested fix:\n{v.fixed_code}"
            rules[rid] = {
                "id": rid,
                "name": rid.replace("/", "_").replace(".", "_"),
                "shortDescription": {"text": v.title[:200]},
                "fullDescription": {"text": (v.ai_explanation or v.title)[:1000]},
                "help": {"text": help_text[:4000]},
                "helpUri": v.references[0] if v.references else None,
                "properties": {
                    "tags": ["security", category, v.source],
                    "security-severity": SECURITY_SEVERITY.get(v.severity, "5.5"),
                    "precision": "high" if v.confidence >= 0.8 else "medium",
                },
            }
            if rules[rid]["helpUri"] is None:
                del rules[rid]["helpUri"]

        message = v.title
        if v.ai_explanation:
            message += f"\n\n{v.ai_explanation[:800]}"
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(v.severity, "warning"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.file.replace("\\", "/")},
                    "region": {
                        "startLine": max(v.line, 1),
                        "endLine": max(v.end_line or v.line, v.line, 1),
                    },
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": f"{rid}:{v.file}:{v.line}"},
            "properties": {
                "category": category,
                "source": v.source,
                "severity": v.severity,
                "confidence": v.confidence,
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
