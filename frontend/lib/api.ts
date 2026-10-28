function getApiUrl(): string {
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: "pending" | "running" | "complete" | "failed";
  progress: number;
  current_step: string;
  steps_completed: string[];
  steps_remaining: string[];
  error: string | null;
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  scanner_severity: string;
  file: string;
  line: number;
  end_line: number | null;
  rule_id: string;
  vulnerable_code: string;
  fixed_code: string;
  ai_explanation: string;
  attack_scenario: string;
  business_impact: string;
  fix_time_estimate: string;
  confidence: number;
  false_positive_likelihood: number;
  category: FindingCategory;
  source: string;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  references: string[];
}

export type FindingCategory = "code" | "dependency" | "secret";

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  by_category: Partial<Record<FindingCategory, number>>;
}

export type EvidenceKind =
  | "static_dataflow"
  | "scanner_finding"
  | "code_pattern"
  | "inferred"
  | "test_observation"
  | "manual";

export interface Evidence {
  kind: EvidenceKind;
  description: string;
  file: string | null;
  line: number | null;
  code: string;
  finding_id: string | null;
}

export interface ChainNode {
  id: string;
  kind: string;
  label: string;
  detail: string;
  role: "direct" | "contributing" | "control" | "context" | "impact";
  file: string | null;
  line: number | null;
  finding_ids: string[];
}

export interface ChainEdge {
  source: string;
  target: string;
  relation: string;
  status: "confirmed" | "hypothesis";
  confidence: number;
  evidence: Evidence[];
}

export interface FixEdit {
  file: string;
  start_line: number;
  end_line: number;
  original: string;
  replacement: string;
}

export interface ChainFix {
  strategy: string;
  break_point: string;
  target_nodes: string[];
  rationale: string;
  edits: FixEdit[];
  remaining_paths: string[];
  tests: string[];
  origin: "template" | "ai" | "developer";
  /** e.g. "template:sql_injection", "template:secret-env", "scan-suggestion", "ai", "developer" */
  strategy_id?: string;
  /** How past outcomes influenced choosing this strategy, if they did */
  history_note?: string;
}

export interface WeaknessChain {
  id: string;
  title: string;
  summary: string;
  kind: string;
  file: string;
  function: string;
  impact: string;
  severity: Vulnerability["severity"];
  exploitability: "likely" | "possible" | "mitigated";
  exploitability_reason: string;
  priority: number;
  nodes: ChainNode[];
  edges: ChainEdge[];
  paths: string[][];
  conditions: string[];
  direct_weaknesses: string[];
  contributing_weaknesses: string[];
  controls: string[];
  finding_ids: string[];
  uncertainty: string[];
  fix: ChainFix | null;
}

export type ValidationStatus = "pass" | "fail" | "new_vulnerability" | "inconclusive";

export interface ValidationCheck {
  name: string;
  status: "passed" | "failed" | "error" | "skipped";
  detail: string;
  evidence: Evidence[];
  /** Could not run for reasons outside the code (scanner, OSV.dev, test runner) */
  infrastructure?: boolean;
}

/**
 * Status of one persisted attempt.
 * ERROR = infrastructure problem or crash, not a verdict on the fix.
 * SKIPPED = the fix produced code an earlier attempt already validated, so it was not run again.
 */
export type AttemptStatus = "RUNNING" | "PASSED" | "FAILED" | "INCONCLUSIVE" | "ERROR" | "SKIPPED";

export interface ValidationAttempt {
  attempt: number;
  fix: ChainFix;
  status: ValidationStatus;
  summary: string;
  weakness_addressed: boolean | null;
  path_broken: boolean | null;
  risk_eliminated: boolean | null;
  checks: ValidationCheck[];
  remaining_paths: string[];
  new_issues: { description: string; file: string; line: number; origin: string; relation: string; chain_id: string | null }[];
  regressions: string[];
  other_chains: Record<string, string>;
  original_preserved: boolean | null;
  scope: string;
  diff: string;
  progress_score: number | null;
  improved: boolean | null;
  code_hash: string | null;
  record_status: AttemptStatus | null;
}

export interface FixValidation {
  id: string;
  scan_id: string;
  chain_id: string | null;
  finding_id: string | null;
  investigation_id: string | null;
  /** Attempt number of this run's first attempt within the investigation */
  first_attempt: number;
  final_diff: string;
  state: "running" | "complete" | "failed";
  status: ValidationStatus | null;
  result: AttemptStatus | null;
  message: string;
  attempts: ValidationAttempt[];
  stop_reason: "passed" | "stalled" | "limit" | "inconclusive" | "no_fix" | "not_reproducible" | "duplicate" | null;
  /** Attempt number of the best code so far (the passing one, else the most improved) */
  best_attempt: number | null;
  /** The passing fix, or the best revision when none passed */
  final_fix: ChainFix | null;
  needs_manual_review: boolean;
  started_at: string;
  finished_at: string | null;
}

/** One persisted attempt; attempts are never overwritten. */
export interface AttemptRecord {
  attempt_id: string;
  investigation_id: string;
  validation_id: string;
  attempt_number: number;
  parent_attempt_id: string | null;
  code_hash: string | null;
  finding_id: string | null;
  chain_id: string | null;
  rule_id: string | null;
  vuln_class: string | null;
  /** How far the attempt got: setup | generating | applying | validating */
  phase: string | null;
  status: AttemptStatus;
  outcome: ValidationStatus | null;
  failure_reason: string | null;
  strategy: string;
  strategy_id: string;
  selection_note: string;
  fix_origin: string;
  patch: FixEdit[];
  diff: string;
  checks: ValidationCheck[];
  created_at: string;
  finished_at: string | null;
}

/** Every attempt to fix one problem, across Validate Fix runs. */
export interface Investigation {
  investigation_id: string;
  scan_id: string;
  target_key: string;
  status: "open" | "passed" | "exhausted" | "closed";
  max_attempts: number;
  active_validation_id: string | null;
  best_attempt: number | null;
  created_at: string;
  updated_at: string;
  attempts: AttemptRecord[];
}

export interface ScanResultsResponse {
  scan_id: string;
  repo_url: string;
  repo_name: string;
  scanned_at: string;
  language: string;
  languages: string[];
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
  warnings: string[];
  chains: WeaknessChain[];
  validations: FixValidation[];
  /** null: the scan predates chain analysis */
  chain_stats: { python_files?: number; flows?: number; endpoints?: number; failed?: number } | null;
}

export interface ScanHistoryItem {
  scan_id: string;
  repo_url: string;
  repo_name: string;
  status: "pending" | "running" | "complete" | "failed";
  started_at: string;
  finished_at: string | null;
  total: number;
  critical: number;
  high: number;
}

/** A refused validation start; `code` says why (e.g. investigation_passed, investigation_exhausted). */
export class ValidationStartError extends Error {
  constructor(
    message: string,
    public code: string | null = null,
  ) {
    super(message);
  }
}

async function validationStartError(res: Response): Promise<ValidationStartError> {
  const body = await res.json().catch(() => ({}));
  const detail = body?.detail;
  if (detail && typeof detail === "object" && typeof detail.message === "string")
    return new ValidationStartError(detail.message, detail.code ?? null);
  return new ValidationStartError(typeof detail === "string" ? detail : "Failed to start validation");
}

export async function startScan(repoUrl: string): Promise<ScanResponse> {
  const res = await fetch(`${getApiUrl()}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl }),
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Failed to start scan" }));
    throw new Error(error.detail || "Failed to start scan");
  }

  return res.json();
}

export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/status`);

  if (!res.ok) {
    throw new Error("Failed to get scan status");
  }

  return res.json();
}

export async function listScans(limit = 10): Promise<ScanHistoryItem[]> {
  const res = await fetch(`${getApiUrl()}/api/scans?limit=${limit}`);

  if (!res.ok) {
    throw new Error("Failed to load scan history");
  }

  return res.json();
}

/** PDF report with every finding. Returns the file and the server's suggested name. */
export async function downloadScanPdf(scanId: string): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/pdf`);

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Failed to generate PDF report" }));
    throw new Error(error.detail || "Failed to generate PDF report");
  }

  const disposition = res.headers.get("Content-Disposition") ?? "";
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `security-report-${scanId}.pdf`;
  return { blob: await res.blob(), filename };
}

export function getScanSarifUrl(scanId: string): string {
  return `${getApiUrl()}/api/scan/${scanId}/sarif`;
}

/** Validate a chain's fix in the backend sandbox. Omit edits to validate the suggested fix. */
export async function startValidation(
  scanId: string,
  chainId: string,
  edits?: FixEdit[],
  newInvestigation = false,
): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/chains/${chainId}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...(edits ? { edits } : {}), ...(newInvestigation ? { new_investigation: true } : {}) }),
  });

  if (!res.ok) throw await validationStartError(res);

  return res.json();
}

/** Validate the fix for any single finding (code, dependency or secret). */
export async function startFindingValidation(
  scanId: string,
  findingId: string,
  newInvestigation = false,
): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/findings/${findingId}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(newInvestigation ? { new_investigation: true } : {}),
  });

  if (!res.ok) throw await validationStartError(res);

  return res.json();
}

export async function getValidation(scanId: string, validationId: string): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/validations/${validationId}`);

  if (!res.ok) {
    throw new Error("Failed to load validation");
  }

  return res.json();
}

/** Every persisted attempt of an investigation, oldest first. */
export async function getInvestigation(scanId: string, investigationId: string): Promise<Investigation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/investigations/${investigationId}`);

  if (!res.ok) {
    throw new Error("Failed to load attempt history");
  }

  return res.json();
}

export async function getScanResults(scanId: string): Promise<ScanResultsResponse> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/results`);

  if (!res.ok) {
    if (res.status === 202) {
      throw new Error("Scan still in progress");
    }
    const error = await res.json().catch(() => ({ detail: "Failed to get results" }));
    throw new Error(error.detail || "Failed to get results");
  }

  return res.json();
}
