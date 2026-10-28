import {
  CATEGORIES,
  CATEGORY_LABEL,
  Category,
  FilterState,
  GroupBy,
  SEVERITIES,
  SEVERITY_LABEL,
  Severity,
  TrackedFinding,
} from "./types";

export interface Group {
  /** Unique within one grouping, e.g. "severity:critical" or "file:src/app.py". */
  id: string;
  kind: GroupBy;
  label: string;
  /** Severity value, category value or file path, depending on `kind`. */
  value: string;
  topSeverity: Severity;
  findings: TrackedFinding[];
}

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s); // 0 = critical

export function isFilterActive(f: FilterState): boolean {
  return f.severities.length > 0 || f.categories.length > 0 || f.text.trim() !== "";
}

export function matchesFilter(t: TrackedFinding, filter: FilterState): boolean {
  if (t.ignored && !filter.showIgnored) return false;
  if (filter.severities.length && !filter.severities.includes(t.data.severity)) return false;
  if (filter.categories.length && !filter.categories.includes(t.data.category)) return false;
  const q = filter.text.trim().toLowerCase();
  if (q) {
    const d = t.data;
    const hay = [d.title, d.file, d.rule_id, d.package ?? "", d.source].join("\n").toLowerCase();
    if (!q.split(/\s+/).every((word) => hay.includes(word))) return false;
  }
  return true;
}

const bySeverityThenLocation = (a: TrackedFinding, b: TrackedFinding) =>
  severityRank(a.data.severity) - severityRank(b.data.severity) ||
  a.data.file.localeCompare(b.data.file) ||
  a.line - b.line ||
  a.data.title.localeCompare(b.data.title);

const byLocationThenSeverity = (a: TrackedFinding, b: TrackedFinding) =>
  a.line - b.line || severityRank(a.data.severity) - severityRank(b.data.severity) || a.data.title.localeCompare(b.data.title);

const topSeverity = (items: TrackedFinding[]): Severity =>
  items.reduce<Severity>((top, t) => (severityRank(t.data.severity) < severityRank(top) ? t.data.severity : top), "low");

/** Filters, groups and sorts findings for the sidebar. Empty groups are dropped. */
export function groupFindings(findings: TrackedFinding[], groupBy: GroupBy, filter: FilterState): Group[] {
  const visible = findings.filter((t) => matchesFilter(t, filter));

  if (groupBy === "severity") {
    return SEVERITIES.map((sev) => {
      const items = visible.filter((t) => t.data.severity === sev).sort(bySeverityThenLocation);
      return { id: `severity:${sev}`, kind: groupBy, label: SEVERITY_LABEL[sev], value: sev, topSeverity: sev, findings: items };
    }).filter((g) => g.findings.length > 0);
  }

  if (groupBy === "category") {
    return CATEGORIES.map((cat: Category) => {
      const items = visible.filter((t) => t.data.category === cat).sort(bySeverityThenLocation);
      return { id: `category:${cat}`, kind: groupBy, label: CATEGORY_LABEL[cat], value: cat, topSeverity: topSeverity(items), findings: items };
    }).filter((g) => g.findings.length > 0);
  }

  const byFile = new Map<string, TrackedFinding[]>();
  for (const t of visible) {
    const list = byFile.get(t.data.file);
    if (list) list.push(t);
    else byFile.set(t.data.file, [t]);
  }
  return [...byFile.entries()]
    .map(([file, items]): Group => ({
      id: `file:${file}`,
      kind: groupBy,
      label: file.split("/").pop() || file,
      value: file,
      topSeverity: topSeverity(items),
      findings: items.sort(byLocationThenSeverity),
    }))
    .sort((a, b) => severityRank(a.topSeverity) - severityRank(b.topSeverity) || b.findings.length - a.findings.length || a.value.localeCompare(b.value));
}

export type Summary = Record<Severity, number> & { total: number; ignored: number };

/** Counts of non-ignored findings per severity. */
export function summarize(findings: TrackedFinding[]): Summary {
  const s: Summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0, ignored: 0 };
  for (const t of findings) {
    if (t.ignored) {
      s.ignored++;
      continue;
    }
    s[t.data.severity]++;
    s.total++;
  }
  return s;
}

/** "35 findings · 1 critical · 6 high" (only non-zero severities). */
export function summaryText(s: Summary): string {
  if (s.total === 0) return s.ignored ? `No open findings (${s.ignored} ignored)` : "No findings";
  const parts = [`${s.total} finding${s.total === 1 ? "" : "s"}`];
  for (const sev of SEVERITIES) if (s[sev]) parts.push(`${s[sev]} ${sev}`);
  if (s.ignored) parts.push(`${s.ignored} ignored`);
  return parts.join(" · ");
}
