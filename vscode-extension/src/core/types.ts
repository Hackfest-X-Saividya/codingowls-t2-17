// Pure data types shared by the extension. Nothing in src/core imports "vscode",
// so it can be unit-tested with plain Node.

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export type Category = "code" | "dependency" | "secret";
export const CATEGORIES: readonly Category[] = ["code", "dependency", "secret"];

export type GroupBy = "severity" | "file" | "category";
export const GROUP_BYS: readonly GroupBy[] = ["severity", "file", "category"];

/** Mirrors backend/models/schemas.py `Vulnerability` (as written by `cli.py scan --json`). */
export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  scanner_severity: string;
  file: string; // relative to the scanned folder, forward slashes
  line: number; // 1-based
  end_line: number; // 1-based, inclusive
  rule_id: string;
  vulnerable_code: string;
  fixed_code: string;
  ai_explanation: string;
  attack_scenario: string;
  business_impact: string;
  fix_time_estimate: string;
  confidence: number;
  false_positive_likelihood: number;
  category: Category;
  source: string;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  references: string[];
}

export interface ScanReport {
  languages: string[];
  warnings: string[];
  vulnerabilities: Finding[];
}

/** A finding plus the live state the extension tracks for it. */
export interface TrackedFinding {
  /** Unique within one scan (backend ids like vuln_001 are positional). */
  uid: string;
  /** Stable across scans; used to remember ignored findings. */
  key: string;
  data: Finding;
  /** Current 1-based position; shifts as the user edits the file. */
  line: number;
  endLine: number;
  /** The code at this finding was edited after the scan. */
  stale: boolean;
  /** The suggested fix was applied (pending a re-scan to confirm). */
  fixed: boolean;
  ignored: boolean;
}

export interface FilterState {
  severities: Severity[]; // empty = all
  categories: Category[]; // empty = all
  text: string; // case-insensitive search in title, file, rule, package
  showIgnored: boolean;
}

export const EMPTY_FILTER: FilterState = { severities: [], categories: [], text: "", showIgnored: false };

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const CATEGORY_LABEL: Record<Category, string> = {
  code: "Code",
  dependency: "Dependencies",
  secret: "Secrets",
};
