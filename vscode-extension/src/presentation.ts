import * as vscode from "vscode";
import { isPlaceholder } from "./core/report";
import { Category, Severity, SEVERITY_LABEL, CATEGORY_LABEL, TrackedFinding } from "./core/types";

/** Shared look of severities and categories across the tree, diagnostics and status bar. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "charts.red",
  high: "charts.orange",
  medium: "charts.yellow",
  low: "charts.blue",
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "error",
  high: "warning",
  medium: "warning",
  low: "info",
};

export const CATEGORY_ICON: Record<Category, string> = {
  code: "code",
  dependency: "package",
  secret: "key",
};

export const severityIcon = (s: Severity) => new vscode.ThemeIcon(SEVERITY_ICON[s], new vscode.ThemeColor(SEVERITY_COLOR[s]));
export const severityDot = (s: Severity) => new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor(SEVERITY_COLOR[s]));

export function findingTooltip(t: TrackedFinding): vscode.MarkdownString {
  const d = t.data;
  const md = new vscode.MarkdownString(undefined, true);
  md.supportThemeIcons = true;
  md.appendMarkdown(`**${escapeMd(d.title)}**\n\n`);
  md.appendMarkdown(`$(${SEVERITY_ICON[d.severity]}) ${SEVERITY_LABEL[d.severity]} · $(${CATEGORY_ICON[d.category]}) ${CATEGORY_LABEL[d.category]}`);
  md.appendMarkdown(` · ${codeSpan(`${d.file}:${t.line}`)}\n\n`);
  if (d.rule_id) md.appendMarkdown(`Rule: ${codeSpan(d.rule_id)}\n\n`);
  if (!isPlaceholder(d.ai_explanation)) md.appendMarkdown(`${escapeMd(truncate(d.ai_explanation, 400))}\n\n`);
  if (t.ignored) md.appendMarkdown(`$(eye-closed) _Ignored_\n\n`);
  if (t.fixed) md.appendMarkdown(`$(check) _Fix applied, re-scan to confirm_\n\n`);
  else if (t.stale) md.appendMarkdown(`$(history) _Code changed since the scan_\n\n`);
  md.appendMarkdown(`_Click to open · details in the panel below_`);
  return md;
}

export function truncate(s: string, n: number): string {
  const t = s.trim();
  return t.length > n ? t.slice(0, n).replace(/\s+\S*$/, "") + "…" : t;
}

const codeSpan = (s: string) => "`" + s.replace(/`/g, "'") + "`";

function escapeMd(s: string): string {
  return s.replace(/[\\`*_{}[\]()#+\-.!|<>]/g, (c) => `\\${c}`);
}

/** Plain-text summary of a finding, for "Copy Finding Details". */
export function findingAsText(t: TrackedFinding): string {
  const d = t.data;
  const lines = [
    `[${d.severity.toUpperCase()}] ${d.title}`,
    `${d.file}:${t.line}`,
    d.rule_id && `Rule: ${d.rule_id}`,
    !isPlaceholder(d.ai_explanation) && `\n${d.ai_explanation.trim()}`,
    !isPlaceholder(d.attack_scenario) && `\nAttack scenario:\n${d.attack_scenario.trim()}`,
    !isPlaceholder(d.vulnerable_code) && `\nVulnerable code:\n${d.vulnerable_code}`,
    !isPlaceholder(d.fixed_code) && `\nSuggested fix:\n${d.fixed_code}`,
    d.references.length > 0 && `\nReferences:\n${d.references.join("\n")}`,
  ];
  return lines.filter(Boolean).join("\n");
}
