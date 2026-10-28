import * as crypto from "crypto";
import * as vscode from "vscode";
import { fixKind, stripFences } from "../core/fixes";
import { planFor } from "../fixProvider";
import { isPlaceholder } from "../core/report";
import { CATEGORY_LABEL, SEVERITY_LABEL, TrackedFinding } from "../core/types";
import { FindingsStore } from "../findingsStore";

/** Data sent to the webview. Everything is rendered with textContent there (never as HTML). */
interface DetailsPayload {
  uid: string;
  title: string;
  severity: string;
  severityLabel: string;
  category: string;
  categoryLabel: string;
  location: string;
  rule: string;
  source: string;
  confidence: number;
  fixTime: string;
  explanation: string;
  attack: string;
  impact: string;
  vulnerable: string;
  fix: string;
  fixLabel: string;
  canApply: boolean;
  canDiff: boolean;
  ignored: boolean;
  fixed: boolean;
  stale: boolean;
  references: string[];
  aiMissing: boolean;
}

type FromWebview =
  | { type: "ready" }
  | { type: "command"; command: "applyFix" | "showDiff" | "ignore" | "unignore" | "open" | "copy"; uid: string }
  | { type: "openLink"; url: string };

const COMMANDS: Record<string, string> = {
  applyFix: "aiSecurity.applyFix",
  showDiff: "aiSecurity.showDiff",
  ignore: "aiSecurity.ignore",
  unignore: "aiSecurity.unignore",
  open: "aiSecurity.openFinding",
  copy: "aiSecurity.copyDetails",
};

export class DetailsViewProvider implements vscode.WebviewViewProvider {
  static readonly viewId = "aiSecurity.details";
  private view: vscode.WebviewView | undefined;
  private currentUid: string | undefined;

  constructor(private readonly extensionUri: vscode.Uri, private readonly store: FindingsStore) {
    // Re-render on any change (ignore/fix/rescan); clear if the finding is gone after a re-scan.
    store.onDidChange(() => this.render());
  }

  show(uid: string | undefined) {
    this.currentUid = uid;
    this.render();
  }

  resolveWebviewView(view: vscode.WebviewView) {
    this.view = view;
    const media = vscode.Uri.joinPath(this.extensionUri, "media");
    view.webview.options = { enableScripts: true, localResourceRoots: [media] };
    view.webview.html = this.html(view.webview, media);
    view.webview.onDidReceiveMessage((m: FromWebview) => this.onMessage(m));
    view.onDidChangeVisibility(() => view.visible && this.render());
    view.onDidDispose(() => (this.view = undefined));
  }

  private onMessage(m: FromWebview) {
    if (m.type === "ready") this.render();
    else if (m.type === "command" && COMMANDS[m.command]) void vscode.commands.executeCommand(COMMANDS[m.command], m.uid);
    else if (m.type === "openLink" && /^https?:\/\//i.test(m.url)) void vscode.env.openExternal(vscode.Uri.parse(m.url));
  }

  private render() {
    if (!this.view) return;
    const t = this.currentUid ? this.store.get(this.currentUid) : undefined;
    void this.view.webview.postMessage({ type: "show", payload: t ? this.payload(t) : null, hasResults: this.store.hasResults });
  }

  private payload(t: TrackedFinding): DetailsPayload {
    const d = t.data;
    const kind = fixKind(d);
    const clean = (s: string) => (isPlaceholder(s) ? "" : s.trim());
    let fix = "";
    let fixLabel = "Suggested fix";
    if (d.category === "dependency") {
      fixLabel = "How to fix";
      const dep = planFor(this.store, t);
      fix = dep
        ? `Upgrade ${d.package} from ${d.installed_version} to ${dep.upgrade.target} or later.` +
          (dep.upgrade.covered.length > 1 ? ` This fixes all ${dep.upgrade.covered.length} advisories for ${d.package} at once.` : "") +
          (dep.plan.kind === "edit" ? "" : `\n\nApply fix: ${dep.plan.summary}`)
        : "No fixed version is published yet. Consider an alternative package or the mitigations in the advisory.";
    } else if (d.category === "secret") {
      fixLabel = "How to fix";
      fix = clean(d.fixed_code).replace(/^#\s?/gm, "");
    } else {
      fix = clean(stripFences(d.fixed_code));
    }
    return {
      uid: t.uid,
      title: d.title,
      severity: d.severity,
      severityLabel: SEVERITY_LABEL[d.severity],
      category: d.category,
      categoryLabel: CATEGORY_LABEL[d.category],
      location: `${d.file}:${t.line}`,
      rule: d.rule_id,
      source: d.source,
      confidence: d.confidence,
      fixTime: d.fix_time_estimate && d.fix_time_estimate !== "Varies" ? d.fix_time_estimate : "",
      explanation: clean(d.ai_explanation),
      attack: clean(d.attack_scenario),
      impact: clean(d.business_impact),
      vulnerable: clean(d.vulnerable_code),
      fix,
      fixLabel,
      canApply: !!kind && !t.fixed,
      canDiff: !!kind,
      ignored: t.ignored,
      fixed: t.fixed,
      stale: t.stale,
      references: d.references.filter((r) => /^https?:\/\//i.test(r)),
      aiMissing: d.category === "code" && (isPlaceholder(d.ai_explanation) || isPlaceholder(d.fixed_code)),
    };
  }

  private html(webview: vscode.Webview, media: vscode.Uri): string {
    const nonce = crypto.randomBytes(16).toString("base64");
    const css = webview.asWebviewUri(vscode.Uri.joinPath(media, "details.css"));
    const js = webview.asWebviewUri(vscode.Uri.joinPath(media, "details.js"));
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${css}">
<title>Finding Details</title>
</head>
<body>
<div id="root"><p class="empty">Select a finding in the list above to see its details.</p></div>
<script nonce="${nonce}" src="${js}"></script>
</body>
</html>`;
  }
}
