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
    CHAIN_ANALYSIS = "chain_analysis"
    AI_ENHANCE = "ai_enhance"


STEP_LABELS: dict[ScanStep, str] = {
    ScanStep.CLONE_REPO: "Cloning repository",
    ScanStep.DETECT_LANGUAGE: "Detecting languages",
    ScanStep.ANALYZE: "Running Semgrep security scan",
    ScanStep.PARSE_RESULTS: "Parsing results",
    ScanStep.SCAN_DEPENDENCIES: "Checking dependencies for known vulnerabilities",
    ScanStep.SCAN_SECRETS: "Scanning for leaked secrets",
    ScanStep.CHAIN_ANALYSIS: "Connecting weaknesses into attack chains",
    ScanStep.AI_ENHANCE: "Enhancing with AI analysis",
}

STEP_WEIGHTS: dict[ScanStep, int] = {
    ScanStep.CLONE_REPO: 10,
    ScanStep.DETECT_LANGUAGE: 5,
    ScanStep.ANALYZE: 30,
    ScanStep.PARSE_RESULTS: 5,
    ScanStep.SCAN_DEPENDENCIES: 10,
    ScanStep.SCAN_SECRETS: 5,
    ScanStep.CHAIN_ANALYSIS: 5,
    ScanStep.AI_ENHANCE: 30,
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


# ---------- Chain-of-weakness analysis ----------
# Kept generic (nodes/edges/evidence) so new vulnerability types and analysis
# techniques only add node kinds and evidence kinds, not new models.

class EvidenceKind(str, Enum):
    STATIC_DATAFLOW = "static_dataflow"  # path established by flow_analyzer
    SCANNER = "scanner_finding"          # a detector (Semgrep, OSV, secret scanner) flagged it
    CODE_PATTERN = "code_pattern"        # structural fact read from the code (decorator, assignment)
    INFERRED = "inferred"                # follows from framework/library semantics, not observed
    TEST = "test_observation"            # observed while running checks or tests
    MANUAL = "manual"                    # confirmed by a person


class Evidence(BaseModel):
    kind: EvidenceKind
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    code: str = ""
    finding_id: Optional[str] = None


class ChainNode(BaseModel):
    id: str
    kind: str   # entry_point | untrusted_input | weakness | security_control | condition | sensitive_operation | impact
    label: str
    detail: str = ""
    role: str = "context"  # direct | contributing | control | context | impact
    file: Optional[str] = None
    line: Optional[int] = None
    finding_ids: list[str] = []


class ChainEdge(BaseModel):
    source: str
    target: str
    relation: str
    status: str = "confirmed"  # confirmed | hypothesis
    confidence: float = 0.0
    evidence: list[Evidence] = []


class FixEdit(BaseModel):
    file: str
    start_line: int
    end_line: int
    original: str = ""      # exact text of lines start..end; the edit is refused if it no longer matches
    replacement: str = ""


class ChainFix(BaseModel):
    strategy: str
    break_point: str          # node id where the chain is interrupted
    target_nodes: list[str] = []
    rationale: str = ""
    edits: list[FixEdit] = []
    remaining_paths: list[str] = []  # paths this fix does not cover
    tests: list[str] = []            # checks that verify it
    origin: str = "template"         # template | ai | developer
    # Which strategy produced it: a predefined one ("template:sql_injection", "template:secret-env",
    # "template:dependency-upgrade", "scan-suggestion"), "ai" or "developer". History is kept per strategy.
    strategy_id: str = ""
    history_note: str = ""           # how past outcomes influenced choosing it, if they did


class WeaknessChain(BaseModel):
    id: str
    title: str
    summary: str = ""          # plain-language explanation for non-specialists
    kind: str                  # sink kind, e.g. sql_injection
    file: str
    function: str
    impact: str
    severity: str
    exploitability: str        # likely | possible | mitigated
    exploitability_reason: str
    priority: int = 0          # 0-100: impact x exploitability x evidence
    nodes: list[ChainNode] = []
    edges: list[ChainEdge] = []
    paths: list[list[str]] = []  # node ids from entry to impact, one per path
    conditions: list[str] = []
    direct_weaknesses: list[str] = []
    contributing_weaknesses: list[str] = []
    controls: list[str] = []
    finding_ids: list[str] = []
    uncertainty: list[str] = []
    signature: dict[str, str] = {}  # stable identity used to re-find the chain after a fix
    fix: Optional[ChainFix] = None


class ValidationStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NEW_VULNERABILITY = "new_vulnerability"
    INCONCLUSIVE = "inconclusive"


class ValidationCheck(BaseModel):
    name: str
    status: str  # passed | failed | error | skipped
    detail: str = ""
    evidence: list[Evidence] = []
    # The check could not run for a reason outside the code (scanner, OSV.dev, test runner):
    # says nothing about the fix, so it is reported as ERROR rather than INCONCLUSIVE
    infrastructure: bool = False


class AttemptStatus(str, Enum):
    """Status of one persisted attempt; coarser than ValidationStatus and adds RUNNING / ERROR."""
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"              # the fix was evaluated and does not hold (incl. new vulnerability)
    INCONCLUSIVE = "INCONCLUSIVE"  # evaluated, but the evidence does not decide (patch stale, conflicting)
    ERROR = "ERROR"                # infrastructure problem or crash: nothing is known about the fix
    SKIPPED = "SKIPPED"            # the fix produced code an earlier attempt already validated; not run again


class NewIssue(BaseModel):
    description: str
    file: str
    line: int
    origin: str          # dataflow | scanner
    relation: str        # new_chain | extends_chain | unrelated
    chain_id: Optional[str] = None


class ValidationAttempt(BaseModel):
    attempt: int
    fix: ChainFix
    status: ValidationStatus
    summary: str
    weakness_addressed: Optional[bool] = None
    path_broken: Optional[bool] = None
    risk_eliminated: Optional[bool] = None
    checks: list[ValidationCheck] = []
    remaining_paths: list[str] = []
    remaining_signatures: list[dict[str, str]] = []  # open sinks, so a retry can target them
    new_issues: list[NewIssue] = []
    regressions: list[str] = []
    other_chains: dict[str, str] = {}  # chain id -> "broken" | "still present"
    original_preserved: Optional[bool] = None
    scope: str = ""
    diff: str = ""
    # Lower is better: open paths, alternative paths, regressions and new issues, weighted.
    # None when the attempt could not be evaluated. Used to stop early when progress stalls.
    progress_score: Optional[int] = None
    improved: Optional[bool] = None  # better than every earlier attempt
    # SHA-256 of the code snapshot that was validated (the unpatched code if the patch did not apply)
    code_hash: Optional[str] = None
    record_status: Optional[AttemptStatus] = None


class FixValidation(BaseModel):
    id: str
    scan_id: str
    chain_id: Optional[str] = None    # set when the chain checks were used
    finding_id: Optional[str] = None  # set when started from a finding
    investigation_id: Optional[str] = None  # persisted attempt history this run belongs to
    first_attempt: int = 1                  # attempt number of this run's first attempt in the investigation
    state: str = "running"  # running | complete | failed
    status: Optional[ValidationStatus] = None
    result: Optional[AttemptStatus] = None  # RUNNING while running, then the last attempt's (ERROR on a crash)
    message: str = ""
    max_attempts: int = 3
    attempts: list[ValidationAttempt] = []
    # passed | stalled | limit | inconclusive | no_fix | not_reproducible | duplicate
    stop_reason: Optional[str] = None
    best_attempt: Optional[int] = None
    final_fix: Optional[ChainFix] = None  # final code (edits against the original): passing, else best
    final_diff: str = ""
    needs_manual_review: bool = False
    started_at: str = ""
    finished_at: Optional[str] = None


class ValidationRequest(BaseModel):
    # Omit edits to validate the suggested fix; pass edits to validate a developer's own fix
    edits: Optional[list[FixEdit]] = None
    max_attempts: Optional[int] = Field(None, ge=1, le=5)
    # Close the current investigation (e.g. at its attempt limit) and start a new one
    new_investigation: bool = False


class AttemptRecord(BaseModel):
    """One persisted validation attempt (services/validation_history.py)."""
    attempt_id: str
    investigation_id: str
    validation_id: str
    attempt_number: int
    parent_attempt_id: Optional[str] = None
    code_hash: Optional[str] = None
    finding_id: Optional[str] = None
    chain_id: Optional[str] = None
    rule_id: Optional[str] = None
    vuln_class: Optional[str] = None
    phase: Optional[str] = None  # how far it got: generating | applying | validating
    status: AttemptStatus
    outcome: Optional[ValidationStatus] = None  # the detailed validation outcome, when one was reached
    failure_reason: Optional[str] = None
    strategy: str = ""
    strategy_id: str = ""
    selection_note: str = ""  # how history influenced the choice of this attempt's strategy
    fix_origin: str = ""
    patch: list[FixEdit] = []
    diff: str = ""
    checks: list[ValidationCheck] = []
    created_at: str
    finished_at: Optional[str] = None


class Investigation(BaseModel):
    """Every attempt to fix one problem (a finding or chain of one scan), across Validate Fix runs."""
    investigation_id: str
    scan_id: str
    target_key: str
    finding_id: Optional[str] = None
    chain_id: Optional[str] = None
    rule_id: Optional[str] = None
    vuln_class: Optional[str] = None
    file: Optional[str] = None
    status: str  # open | passed | exhausted | closed (only an explicit new investigation closes one)
    max_attempts: int
    active_validation_id: Optional[str] = None
    best_attempt: Optional[int] = None  # attempt whose code the next run resumes from
    created_at: str
    updated_at: str
    attempts: list[AttemptRecord] = []


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
    chains: list[WeaknessChain] = []
    validations: list[FixValidation] = []
    # None: scan predates chain analysis. Otherwise python_files / flows / endpoints analysed.
    chain_stats: Optional[dict[str, int]] = None


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
