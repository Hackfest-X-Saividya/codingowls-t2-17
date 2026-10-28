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
}

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
}

export interface FixValidation {
  id: string;
  scan_id: string;
  chain_id: string | null;
  finding_id: string | null;
  final_diff: string;
  state: "running" | "complete" | "failed";
  status: ValidationStatus | null;
  message: string;
  attempts: ValidationAttempt[];
  stop_reason: "passed" | "stalled" | "limit" | "inconclusive" | "no_fix" | "not_reproducible" | null;
  best_attempt: number | null;
  /** The passing fix, or the best revision when none passed */
  final_fix: ChainFix | null;
  needs_manual_review: boolean;
  started_at: string;
  finished_at: string | null;
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
): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/chains/${chainId}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(edits ? { edits } : {}),
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Failed to start validation" }));
    throw new Error(typeof error.detail === "string" ? error.detail : "Failed to start validation");
  }

  return res.json();
}

/** Validate the fix for any single finding (code, dependency or secret). */
export async function startFindingValidation(scanId: string, findingId: string): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/findings/${findingId}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: "Failed to start validation" }));
    throw new Error(typeof error.detail === "string" ? error.detail : "Failed to start validation");
  }

  return res.json();
}

export async function getValidation(scanId: string, validationId: string): Promise<FixValidation> {
  const res = await fetch(`${getApiUrl()}/api/scan/${scanId}/validations/${validationId}`);

  if (!res.ok) {
    throw new Error("Failed to load validation");
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
