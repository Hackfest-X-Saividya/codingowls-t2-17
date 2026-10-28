import * as vscode from "vscode";
import { summaryText } from "./core/grouping";
import { FindingsStore } from "./findingsStore";

/** "🛡 1 critical · 6 high" in the status bar; click to open the sidebar. */
export class StatusBar implements vscode.Disposable {
  private readonly item = vscode.window.createStatusBarItem("aiSecurity.status", vscode.StatusBarAlignment.Left, 50);
  private scanning = false;

  constructor(private readonly store: FindingsStore) {
    this.item.name = "Security Scanner";
    this.item.command = "workbench.view.extension.aiSecurity";
    store.onDidChange(() => this.render());
    this.render();
  }

  setScanning(on: boolean) {
    this.scanning = on;
    this.render();
  }

  dispose() {
    this.item.dispose();
  }

  private render() {
    if (this.scanning) {
      this.item.text = "$(sync~spin) Scanning…";
      this.item.tooltip = "Security Scanner: scan in progress";
      this.item.backgroundColor = undefined;
      this.item.show();
      return;
    }
    if (!this.store.hasResults) {
      this.item.text = "$(shield) Scan";
      this.item.tooltip = "Security Scanner: no scan yet. Click to open.";
      this.item.backgroundColor = undefined;
      this.item.show();
      return;
    }
    const s = this.store.summary();
    const top = s.critical ? `${s.critical} critical` : s.high ? `${s.high} high` : s.total ? `${s.total}` : "0";
    this.item.text = `$(shield) ${top}`;
    this.item.tooltip = `Security Scanner: ${summaryText(s)}`;
    this.item.backgroundColor = s.critical ? new vscode.ThemeColor("statusBarItem.errorBackground") : undefined;
    this.item.show();
  }
}
