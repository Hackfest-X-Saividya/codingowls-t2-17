"""Detect hardcoded secrets (API keys, tokens, private keys, passwords).

Scans every text file in the checkout (including .env / config files that
code rules don't look at). Matched values are always masked in the report so
the scanner never re-publishes a leaked credential.

Limitation: the repo is shallow-cloned, so secrets that were committed and
later deleted from history are not visible.
"""
from __future__ import annotations

import logging
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from models.schemas import FindingCategory, Vulnerability

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000
MAX_FINDINGS = 100
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", "vendor"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
              "composer.lock", "gemfile.lock", "go.sum", "cargo.lock"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg", ".pdf", ".zip", ".gz", ".tar",
              ".jar", ".war", ".class", ".so", ".dll", ".exe", ".bin", ".woff", ".woff2", ".ttf",
              ".eot", ".mp3", ".mp4", ".mov", ".pyc", ".lock", ".min.js", ".map"}
PLACEHOLDER = re.compile(
    r"(your|example|sample|dummy|placeholder|changeme|change_me|xxx|\*\*\*|<|>|\$\{|\{\{|"
    r"process\.env|os\.environ|getenv|env\(|redacted|test|fake|insert|replace)", re.I)


@dataclass(frozen=True)
class SecretRule:
    slug: str
    name: str
    pattern: re.Pattern
    severity: str
    confidence: float
    group: int = 0          # regex group holding the secret value
    check_entropy: bool = False


RULES: list[SecretRule] = [
    SecretRule("private-key", "Private key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical", 0.95),
    SecretRule("aws-access-key-id", "AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high", 0.9, 1),
    SecretRule("aws-secret-access-key", "AWS secret access key", re.compile(
        r"(?i)aws.{0,20}(?:secret|private).{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]"), "critical", 0.85, 1),
    SecretRule("github-token", "GitHub token", re.compile(
        r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), "critical", 0.95, 1),
    SecretRule("gitlab-token", "GitLab personal access token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), "critical", 0.95, 1),
    SecretRule("slack-token", "Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "high", 0.9, 1),
    SecretRule("slack-webhook", "Slack webhook URL", re.compile(
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"), "medium", 0.9, 1),
    SecretRule("stripe-secret-key", "Stripe live secret key", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), "critical", 0.95, 1),
    SecretRule("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "high", 0.85, 1),
    SecretRule("anthropic-api-key", "Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), "critical", 0.95, 1),
    SecretRule("openai-api-key", "OpenAI API key", re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"), "critical", 0.95, 1),
    SecretRule("groq-api-key", "Groq API key", re.compile(r"\b(gsk_[A-Za-z0-9]{40,})\b"), "critical", 0.95, 1),
    SecretRule("huggingface-token", "Hugging Face token", re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"), "high", 0.9, 1),
    SecretRule("twilio-api-key", "Twilio API key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "high", 0.7, 1),
    SecretRule("sendgrid-api-key", "SendGrid API key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "high", 0.95, 1),
    SecretRule("npm-token", "npm access token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "high", 0.9, 1),
    SecretRule("jwt", "JSON Web Token", re.compile(
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium", 0.6, 1),
    SecretRule("database-url", "Database connection string with password", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@'\"]+:([^\s@'\"]{3,})@[^\s'\"]+"),
        "high", 0.8, 1, True),
    SecretRule("generic-secret", "Hardcoded password / secret", re.compile(
        r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
        r"client[_-]?secret|private[_-]?key)[\w.-]*\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"),
        "medium", 0.6, 1, True),
]


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 6, 20)}{value[-2:]}"


def _is_text_candidate(path: Path) -> bool:
    name = path.name.lower()
    if name in SKIP_FILES or any(name.endswith(ext) for ext in BINARY_EXT):
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def _finding(index: int, rule: SecretRule, rel: str, line_no: int, line: str, secret: str) -> Vulnerability:
    masked_line = line.replace(secret, mask(secret)) if secret else line
    masked_line = masked_line.strip()[:300]
    return Vulnerability(
        id=f"sec_{index:03d}",
        title=f"{rule.name} committed to repository",
        severity=rule.severity,
        scanner_severity=rule.severity,
        file=rel,
        line=line_no,
        end_line=line_no,
        rule_id=f"secret/{rule.slug}",
        vulnerable_code=masked_line,
        fixed_code=(
            "# 1. Revoke / rotate this credential at the provider - it is already exposed.\n"
            "# 2. Remove it from the code and load it at runtime, e.g.:\n"
            "#      Python: os.environ[\"MY_SECRET\"]    Node: process.env.MY_SECRET\n"
            "# 3. Purge it from git history (git filter-repo / BFG) and add the file to .gitignore."
        ),
        ai_explanation=(
            f"A value that looks like a {rule.name.lower()} is stored in the source code. Anyone who can "
            "read the repository (or any fork, clone or CI log) can use it. Removing it from the latest "
            "commit is not enough, because it stays in git history; the credential must be rotated."
        ),
        attack_scenario=(
            "1. Attacker (or an automated bot) scans public repositories for credential patterns.\n"
            "2. They find this value and test it against the provider's API.\n"
            "3. They use it to access data, run up costs, or move further into your infrastructure."
        ),
        business_impact="Leaked credentials enable unauthorised access, data breaches and unexpected cloud bills.",
        fix_time_estimate="30 minutes",
        confidence=rule.confidence,
        false_positive_likelihood=round(1 - rule.confidence, 2),
        category=FindingCategory.SECRET,
        source="secret-scanner",
    )


def scan_secrets(repo_path: Path) -> tuple[list[Vulnerability], list[str]]:
    """Return (findings, warnings)."""
    findings: list[Vulnerability] = []
    seen: set[tuple[str, int, str]] = set()
    files_scanned = 0

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(root) / filename
            if not _is_text_candidate(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            files_scanned += 1
            rel = path.relative_to(repo_path).as_posix()

            for line_no, line in enumerate(text.splitlines(), 1):
                if len(line) > 2000:  # minified / generated content
                    continue
                for rule in RULES:
                    for m in rule.pattern.finditer(line):
                        secret = m.group(rule.group) if rule.group else ""
                        if rule.check_entropy and (PLACEHOLDER.search(secret) or _entropy(secret) < 3.0):
                            continue
                        key = (rel, line_no, rule.slug if rule.slug != "generic-secret" else secret)
                        # Skip the generic rule when a specific rule already matched this line
                        if rule.slug == "generic-secret" and any(k[:2] == (rel, line_no) for k in seen):
                            continue
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(_finding(len(findings) + 1, rule, rel, line_no, line, secret))
                        if len(findings) >= MAX_FINDINGS:
                            logger.warning("Secret scan stopped at %d findings", MAX_FINDINGS)
                            return findings, [f"Secret scan stopped after {MAX_FINDINGS} findings."]

    logger.info("Secret scan: %d files, %d findings", files_scanned, len(findings))
    return findings, []
