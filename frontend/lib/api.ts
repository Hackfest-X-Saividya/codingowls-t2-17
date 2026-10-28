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
