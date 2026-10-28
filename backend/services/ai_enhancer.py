from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Optional

import httpx

from models.schemas import Vulnerability
from utils.config import settings

logger = logging.getLogger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

ENHANCEMENT_PROMPT = """\
You are a senior application security engineer. Analyze the following vulnerability found by static analysis and provide a detailed, actionable assessment.

## Vulnerability Details
- **Rule ID:** {rule_id}
- **Title:** {title}
- **Scanner Severity:** {scanner_severity}
- **File:** {file}
- **Line:** {line}

## Vulnerable Code
```
{vulnerable_code}
```
{chain_context}
Respond with a JSON object containing exactly these fields:
{{
  "ai_explanation": "A clear, plain-English explanation of what the vulnerability is and why the code is insecure. 2-3 sentences aimed at a developer who may not be a security expert.",
  "attack_scenario": "A step-by-step realistic attack scenario showing how an attacker could exploit this vulnerability. Use numbered steps.",
  "fixed_code": "The corrected version of the vulnerable code snippet. Show only the fixed code, not the entire file.",
  "business_impact": "One sentence describing the potential business impact if this vulnerability is exploited.",
  "fix_time_estimate": "Estimated time to fix (e.g., '5 minutes', '30 minutes', '2 hours').",
  "severity": "Your assessed severity: 'critical', 'high', 'medium', or 'low'. May differ from the scanner's assessment.",
  "confidence": 0.95,
  "false_positive_likelihood": 0.05
}}

Important: Return ONLY valid JSON. No markdown code fences, no extra text.
"""


async def enhance_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    use_ai: bool = True,
    context: Optional[dict[str, str]] = None,
) -> list[Vulnerability]:
    """Enhance a list of vulnerabilities with AI-generated analysis.

    Uses Groq (GROQ_MODEL) to generate explanations, attack scenarios, and fixes.
    `context` maps finding ids to their attack-chain description, so the fix
    targets the chain's break point rather than the isolated symptom.
    With use_ai=False (or no API key) only the rule-based fallback text is added.
    """
    if not vulnerabilities:
        return []
    if not use_ai or not settings.GROQ_API_KEY:
        if use_ai:
            logger.warning("No Groq API key configured; skipping AI enhancement")
        return _apply_fallback_enhancements(vulnerabilities)

    async with httpx.AsyncClient(timeout=90) as http:
        return await _enhance_all(
            vulnerabilities, lambda p: _groq_complete(http, p), concurrency=4, context=context
        )


async def _enhance_all(
    vulnerabilities: list[Vulnerability],
    complete: Callable[[str], Awaitable[str]],
    concurrency: int,
    context: Optional[dict[str, str]] = None,
) -> list[Vulnerability]:
    # Bounded parallelism keeps us under provider rate limits
    semaphore = asyncio.Semaphore(concurrency)

    async def _safe_enhance(vuln: Vulnerability) -> Vulnerability:
        async with semaphore:
            try:
                return await _enhance_single(complete, vuln, (context or {}).get(vuln.id, ""))
            except Exception as e:
                logger.error("AI enhancement failed for %s: %s", vuln.id, e)
                return _apply_single_fallback(vuln)

    enhanced = await asyncio.gather(*[_safe_enhance(v) for v in vulnerabilities])
    return list(enhanced)


async def _groq_complete(http: httpx.AsyncClient, prompt: str) -> str:
    """Call Groq's OpenAI-compatible chat API, retrying on rate limits."""
    payload = {
        "model": settings.GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        "max_completion_tokens": 2048,
        "temperature": 0.2,
    }
    if "gpt-oss" in settings.GROQ_MODEL:
        # gpt-oss models "think" before answering; low effort keeps us under the
        # free tier's tokens-per-minute limit without hurting this task
        payload["reasoning_effort"] = "low"
    headers = {"Authorization": f"Bearer {settings.GROQ_API_KEY}"}

    for attempt in range(6):
        res = await http.post(GROQ_URL, json=payload, headers=headers)
        if res.status_code != 429:
            break
        await asyncio.sleep(min(float(res.headers.get("retry-after", 2 ** attempt)), 60))
    if res.status_code >= 400:
        logger.warning("Groq returned %d: %s", res.status_code, res.text[:300])
    res.raise_for_status()
    return res.json()["choices"][0]["message"]["content"]


async def _enhance_single(
    complete: Callable[[str], Awaitable[str]], vuln: Vulnerability, chain_context: str = ""
) -> Vulnerability:
    """Enhance a single vulnerability using the given LLM completion function."""
    prompt = ENHANCEMENT_PROMPT.format(
        rule_id=vuln.rule_id,
        title=vuln.title,
        scanner_severity=vuln.scanner_severity,
        file=vuln.file,
        line=vuln.line,
        vulnerable_code=vuln.vulnerable_code or "(code snippet not available)",
        chain_context=f"\n## Attack Chain Context\n{chain_context}\n" if chain_context else "",
    )

    response_text = (await complete(prompt)).strip()
    data = _parse_ai_response(response_text)

    severity = str(data.get("severity", vuln.severity)).lower()
    return vuln.model_copy(update={
        "severity": severity if severity in ("critical", "high", "medium", "low") else vuln.severity,
        "fixed_code": data.get("fixed_code", ""),
        "ai_explanation": data.get("ai_explanation", ""),
        "attack_scenario": data.get("attack_scenario", ""),
        "business_impact": data.get("business_impact", ""),
        "fix_time_estimate": data.get("fix_time_estimate", ""),
        "confidence": data.get("confidence", 0.8),
        "false_positive_likelihood": data.get("false_positive_likelihood", 0.1),
    })


def _parse_ai_response(text: str) -> dict[str, Any]:
    """Parse JSON response from the LLM, handling edge cases."""
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

    logger.warning("Could not parse AI response as JSON")
    return {}


def _apply_fallback_enhancements(
    vulnerabilities: list[Vulnerability],
) -> list[Vulnerability]:
    """Apply basic enhancement without AI when API key is unavailable."""
    return [_apply_single_fallback(v) for v in vulnerabilities]


def _apply_single_fallback(vuln: Vulnerability) -> Vulnerability:
    """Generate a basic enhancement for a single vulnerability without AI."""
    explanations: dict[str, str] = {
        "sql-injection": (
            "This code constructs SQL queries using string concatenation or "
            "interpolation with user input, allowing attackers to inject "
            "malicious SQL commands."
        ),
        "command-line-injection": (
            "This code passes user-controlled input to a system command, "
            "allowing attackers to execute arbitrary commands on the server."
        ),
        "code-injection": (
            "This code evaluates user-controlled input as code, allowing "
            "attackers to execute arbitrary code in the application context."
        ),
        "path-injection": (
            "This code uses user-controlled input in file paths without "
            "validation, allowing attackers to read or write arbitrary files."
        ),
        "xss": (
            "This code includes user input in HTML output without proper "
            "escaping, allowing attackers to inject malicious scripts."
        ),
    }

    explanation = "Security vulnerability detected by static analysis."
    for pattern, desc in explanations.items():
        if pattern in vuln.rule_id.lower():
            explanation = desc
            break

    return vuln.model_copy(update={
        "fixed_code": "(AI enhancement unavailable — set GROQ_API_KEY for detailed fixes)",
        "ai_explanation": explanation,
        "attack_scenario": "(AI enhancement unavailable — set GROQ_API_KEY for attack scenarios)",
        "business_impact": "Potential security breach if exploited.",
        "fix_time_estimate": "Varies",
        "confidence": 0.7,
        "false_positive_likelihood": 0.2,
    })
