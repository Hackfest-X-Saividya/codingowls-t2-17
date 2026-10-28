import { createHash } from "crypto";
import { CATEGORIES, Category, Finding, ScanReport, SEVERITIES, Severity, TrackedFinding } from "./types";

const str = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
const num = (v: unknown, fallback = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : fallback);
const strOrNull = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

function toSeverity(v: unknown): Severity {
  const s = str(v).toLowerCase();
  return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "low";
}

function toCategory(v: unknown): Category {
  const c = str(v).toLowerCase();
  return (CATEGORIES as readonly string[]).includes(c) ? (c as Category) : "code";
}

function toFinding(raw: Record<string, unknown>, index: number): Finding {
  const line = Math.max(1, Math.trunc(num(raw.line, 1)));
  const endLine = Math.max(line, Math.trunc(num(raw.end_line, line)));
  return {
    id: str(raw.id) || `finding_${index + 1}`,
    title: str(raw.title) || str(raw.rule_id) || "Untitled finding",
    severity: toSeverity(raw.severity),
    scanner_severity: str(raw.scanner_severity),
    file: str(raw.file).replace(/\\/g, "/").replace(/^\.\//, ""),
    line,
    end_line: endLine,
    rule_id: str(raw.rule_id),
    vulnerable_code: str(raw.vulnerable_code),
    fixed_code: str(raw.fixed_code),
    ai_explanation: str(raw.ai_explanation),
    attack_scenario: str(raw.attack_scenario),
    business_impact: str(raw.business_impact),
    fix_time_estimate: str(raw.fix_time_estimate),
    confidence: num(raw.confidence),
    false_positive_likelihood: num(raw.false_positive_likelihood),
    category: toCategory(raw.category),
    source: str(raw.source),
    package: strOrNull(raw.package),
    installed_version: strOrNull(raw.installed_version),
    fixed_version: strOrNull(raw.fixed_version),
    references: Array.isArray(raw.references) ? raw.references.filter((r): r is string => typeof r === "string") : [],
  };
}

/** Validates and normalises the JSON written by `cli.py scan --json`. Throws on a wrong shape. */
export function parseReport(json: unknown): ScanReport {
  if (!json || typeof json !== "object" || !Array.isArray((json as { vulnerabilities?: unknown }).vulnerabilities)) {
    throw new Error("Scanner output has no 'vulnerabilities' list");
  }
  const obj = json as { languages?: unknown; warnings?: unknown; vulnerabilities: unknown[] };
  const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return {
    languages: strings(obj.languages),
    warnings: strings(obj.warnings),
    vulnerabilities: obj.vulnerabilities
      .filter((v): v is Record<string, unknown> => !!v && typeof v === "object")
      .map(toFinding),
  };
}

/** Stable identity of a finding across scans (backend ids are positional, so they can't be used). */
export function findingKey(f: Finding): string {
  const code = f.vulnerable_code.replace(/\s+/g, " ").trim();
  return createHash("sha1").update(`${f.rule_id}\u0000${f.file}\u0000${code}`).digest("hex").slice(0, 16);
}

export function track(findings: Finding[], ignoredKeys: ReadonlySet<string>): TrackedFinding[] {
  return findings.map((data, i) => {
    const key = findingKey(data);
    return {
      uid: `${i}:${data.id}`,
      key,
      data,
      line: data.line,
      endLine: data.end_line,
      stale: false,
      fixed: false,
      ignored: ignoredKeys.has(key),
    };
  });
}

/** Text the backend writes when AI enhancement is off or failed; not worth showing as content. */
export function isPlaceholder(text: string | null | undefined): boolean {
  const t = (text ?? "").trim();
  return (
    !t ||
    /^\(AI enhancement unavailable/i.test(t) ||
    t === "(code snippet not available)" ||
    t === "Security vulnerability detected by static analysis." ||
    t === "Potential security breach if exploited."
  );
}
