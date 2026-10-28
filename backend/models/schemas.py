from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="Public GitHub repository URL")

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith("https://github.com/"):
            raise ValueError("URL must be a public GitHub repository (https://github.com/...)")
        parts = v.replace("https://github.com/", "").split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError("URL must include owner and repository name")
        # Strip .git suffix if present
        if parts[1].endswith(".git"):
            parts[1] = parts[1][:-4]
        return f"https://github.com/{parts[0]}/{parts[1]}"


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStep(str, Enum):
    CLONE_REPO = "clone_repo"
    DETECT_LANGUAGE = "detect_language"
    ANALYZE = "analyze"
    PARSE_RESULTS = "parse_results"
    SCAN_DEPENDENCIES = "scan_dependencies"
    SCAN_SECRETS = "scan_secrets"
    AI_ENHANCE = "ai_enhance"


STEP_LABELS: dict[ScanStep, str] = {
    ScanStep.CLONE_REPO: "Cloning repository",
    ScanStep.DETECT_LANGUAGE: "Detecting languages",
    ScanStep.ANALYZE: "Running Semgrep security scan",
    ScanStep.PARSE_RESULTS: "Parsing results",
    ScanStep.SCAN_DEPENDENCIES: "Checking dependencies for known vulnerabilities",
    ScanStep.SCAN_SECRETS: "Scanning for leaked secrets",
    ScanStep.AI_ENHANCE: "Enhancing with AI analysis",
}

STEP_WEIGHTS: dict[ScanStep, int] = {
    ScanStep.CLONE_REPO: 10,
    ScanStep.DETECT_LANGUAGE: 5,
    ScanStep.ANALYZE: 30,
    ScanStep.PARSE_RESULTS: 5,
    ScanStep.SCAN_DEPENDENCIES: 10,
    ScanStep.SCAN_SECRETS: 5,
    ScanStep.AI_ENHANCE: 35,
}


class FindingCategory(str, Enum):
    CODE = "code"              # insecure code patterns (Semgrep)
    DEPENDENCY = "dependency"  # known-vulnerable package versions (OSV)
    SECRET = "secret"          # hardcoded credentials


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    progress: int = 0
    current_step: str = ""
    steps_completed: list[str] = []
    steps_remaining: list[str] = []
    error: Optional[str] = None


class Vulnerability(BaseModel):
    id: str
    title: str
    severity: str
    scanner_severity: str
    file: str
    line: int
    end_line: Optional[int] = None
    rule_id: str
    vulnerable_code: str = ""
    fixed_code: str = ""
    ai_explanation: str = ""
    attack_scenario: str = ""
    business_impact: str = ""
    fix_time_estimate: str = ""
    confidence: float = 0.0
    false_positive_likelihood: float = 0.0
    category: FindingCategory = FindingCategory.CODE
    source: str = "semgrep"
    # Dependency findings only
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    references: list[str] = []


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    by_category: dict[str, int] = {}


class ScanResultsResponse(BaseModel):
    scan_id: str
    repo_url: str
    repo_name: str
    scanned_at: str
    language: str
    languages: list[str] = []
    summary: ScanSummary
    vulnerabilities: list[Vulnerability]
    warnings: list[str] = []


class ScanHistoryItem(BaseModel):
    scan_id: str
    repo_url: str
    repo_name: str
    status: ScanStatus
    started_at: str
    finished_at: Optional[str] = None
    total: int = 0
    critical: int = 0
    high: int = 0
