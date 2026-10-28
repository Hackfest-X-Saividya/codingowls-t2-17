import * as vscode from "vscode";
import { severityRank } from "./core/grouping";
import { Severity, TrackedFinding } from "./core/types";
import { FindingsStore } from "./findingsStore";

const SOURCE = "AI Security";

const TO_DIAGNOSTIC_SEVERITY: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};

/** Squiggles in the editor and entries in the Problems panel, rebuilt from the store. */
export class DiagnosticsManager implements vscode.Disposable {
  private readonly collection = vscode.languages.createDiagnosticCollection("aiSecurity");
  private readonly disposables: vscode.Disposable[] = [this.collection];

  constructor(private readonly store: FindingsStore) {
    this.disposables.push(
      store.onDidChange(() => this.refresh()),
      vscode.workspace.onDidChangeConfiguration((e) => e.affectsConfiguration("aiSecurity.minSeverity") && this.refresh()),
    );
    this.refresh();
  }

  dispose() {
    for (const d of this.disposables) d.dispose();
  }

  refresh() {
    this.collection.clear();
    if (!this.store.hasResults) return;
    const min = vscode.workspace.getConfiguration("aiSecurity").get<Severity>("minSeverity", "low");
    const byFile = new Map<string, { uri: vscode.Uri; items: vscode.Diagnostic[] }>();
    for (const t of this.store.all) {
      if (t.ignored || t.fixed || severityRank(t.data.severity) > severityRank(min)) continue;
      const uri = this.store.uriFor(t);
      if (!uri) continue;
      const entry = byFile.get(uri.toString()) ?? { uri, items: [] };
      entry.items.push(this.toDiagnostic(t));
      byFile.set(uri.toString(), entry);
    }
    for (const { uri, items } of byFile.values()) this.collection.set(uri, items);
  }

  private toDiagnostic(t: TrackedFinding): vscode.Diagnostic {
    const d = t.data;
    // End of the last line is clamped by VS Code, so a large character is fine here.
    const range = new vscode.Range(t.line - 1, 0, t.endLine - 1, Number.MAX_SAFE_INTEGER);
    // Code edited since the scan: keep a faint hint instead of a red/yellow squiggle until re-scanned.
    const severity = t.stale ? vscode.DiagnosticSeverity.Hint : TO_DIAGNOSTIC_SEVERITY[d.severity];
    const diag = new vscode.Diagnostic(range, t.stale ? `${d.title} (code changed, re-scan to verify)` : d.title, severity);
    diag.source = SOURCE;
    const ref = d.references.find((r) => /^https?:\/\//i.test(r));
    diag.code = ref ? { value: d.rule_id || d.severity, target: vscode.Uri.parse(ref) } : d.rule_id || undefined;
    if (t.stale) diag.tags = [vscode.DiagnosticTag.Unnecessary];
    return diag;
  }
}
