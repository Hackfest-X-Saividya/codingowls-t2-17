import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { isFilterActive, summaryText } from "./core/grouping";
import { CATEGORIES, CATEGORY_LABEL, Category, GroupBy, SEVERITIES, SEVERITY_LABEL, Severity, TrackedFinding } from "./core/types";
import { DetailsViewProvider } from "./details/detailsViewProvider";
import { DiagnosticsManager } from "./diagnostics";
import { FindingsStore } from "./findingsStore";
import { applyFix, FindingCodeActionProvider, FIX_SCHEME, FixContentProvider, showDiff } from "./fixProvider";
import { findingAsText } from "./presentation";
import { ScanCancelled, ScanError, ScannerService } from "./scannerService";
import { StatusBar } from "./statusBar";
import { FindingNode, FindingsTreeProvider } from "./tree/findingsTreeProvider";

/** Returned for the integration tests; not a public API. */
export interface ExtensionApi {
  store: FindingsStore;
  tree: FindingsTreeProvider;
}

export function activate(context: vscode.ExtensionContext): ExtensionApi {
  const output = vscode.window.createOutputChannel("Security Scanner");
  const store = new FindingsStore(context.workspaceState);
  const scanner = new ScannerService(output, context.globalState);
  const tree = new FindingsTreeProvider(store);
  const details = new DetailsViewProvider(context.extensionUri, store);
  const statusBar = new StatusBar(store);
  const diagnostics = new DiagnosticsManager(store);

  const treeView = vscode.window.createTreeView("aiSecurity.findings", { treeDataProvider: tree, showCollapseAll: true });
  const highlight = vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor("editor.findMatchHighlightBackground"),
    isWholeLine: true,
  });

  context.subscriptions.push(
    output,
    store,
    statusBar,
    diagnostics,
    treeView,
    highlight,
    vscode.window.registerWebviewViewProvider(DetailsViewProvider.viewId, details),
    vscode.workspace.registerTextDocumentContentProvider(FIX_SCHEME, new FixContentProvider(store)),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, new FindingCodeActionProvider(store), {
      providedCodeActionKinds: FindingCodeActionProvider.kinds,
    }),
  );

  // ----- sidebar header: summary message + badge -----
  const updateHeader = () => {
    if (!store.hasResults) {
      treeView.message = undefined;
      treeView.badge = undefined;
      return;
    }
    const s = store.summary();
    const parts = [summaryText(s)];
    if (isFilterActive(store.filter)) {
      const shown = store.groups().reduce((n, g) => n + g.findings.length, 0);
      parts.unshift(`Filtered: ${shown} shown`);
    }
    if (store.scannedAt) parts.push(timeAgo(store.scannedAt) + (store.fromPreviousSession ? " (previous session)" : ""));
    if (!store.usedAI) parts.push("AI off");
    treeView.message = parts.join(" · ");
    treeView.badge = s.total ? { value: s.total, tooltip: summaryText(s) } : undefined;
  };
  store.onDidChange(updateHeader);
  updateHeader();
  const headerTimer = setInterval(updateHeader, 60_000); // keep "2 min ago" fresh
  context.subscriptions.push({ dispose: () => clearInterval(headerTimer) });

  treeView.onDidChangeSelection((e) => {
    const node = e.selection[0];
    if (node instanceof FindingNode) details.show(node.finding.uid);
  });

  // ----- helpers -----
  /** Commands get a uid (from webview / code actions / tree click) or a node (from tree menus). */
  const resolve = (arg: unknown): TrackedFinding | undefined => {
    if (typeof arg === "string") return store.get(arg);
    if (arg instanceof FindingNode) return store.get(arg.finding.uid);
    const sel = treeView.selection[0];
    return sel instanceof FindingNode ? store.get(sel.finding.uid) : undefined;
  };

  const revealInTree = async (uid: string, focus: boolean) => {
    const node = tree.nodeFor(uid);
    if (!node) return;
    try {
      await treeView.reveal(node, { select: true, focus, expand: true });
    } catch {
      // view not visible yet; selection is a nicety
    }
  };

  const openFinding = async (t: TrackedFinding) => {
    details.show(t.uid);
    const uri = store.uriFor(t);
    if (!uri || !fs.existsSync(uri.fsPath)) {
      void vscode.window.showWarningMessage(`${t.data.file} no longer exists.`);
      return;
    }
    const doc = await vscode.workspace.openTextDocument(uri);
    const start = Math.min(t.line - 1, doc.lineCount - 1);
    const end = Math.min(t.endLine - 1, doc.lineCount - 1);
    const range = new vscode.Range(start, 0, end, doc.lineAt(end).text.length);
    const editor = await vscode.window.showTextDocument(doc, { preserveFocus: true, preview: true });
    const firstChar = doc.lineAt(start).firstNonWhitespaceCharacterIndex;
    editor.selection = new vscode.Selection(start, firstChar, start, firstChar);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    editor.setDecorations(highlight, [range]);
    setTimeout(() => editor.setDecorations(highlight, []), 1500);
  };

  // ----- scanning -----
  let saveTimer: NodeJS.Timeout | undefined;

  const runScan = async (root: string, opts: { quiet?: boolean } = {}) => {
    if (scanner.isScanning) {
      void vscode.window.showInformationMessage("A scan is already running.");
      return;
    }
    if (!opts.quiet) void vscode.commands.executeCommand("workbench.view.extension.aiSecurity");
    void vscode.commands.executeCommand("setContext", "aiSecurity.scanning", true);
    statusBar.setScanning(true);
    const started = Date.now();
    try {
      const outcome = await vscode.window.withProgress(
        { location: { viewId: "aiSecurity.findings" } },
        () =>
          opts.quiet
            ? scanner.scan(root)
            : vscode.window.withProgress(
                { location: vscode.ProgressLocation.Notification, title: `Security scan: ${path.basename(root)}`, cancellable: true },
                (progress, token) => {
                  const ai = vscode.workspace.getConfiguration("aiSecurity").get<boolean>("useAI", true);
                  const tick = setInterval(() => {
                    const secs = Math.round((Date.now() - started) / 1000);
                    progress.report({ message: `code, dependencies, secrets${ai ? " + AI explanations" : ""}… ${secs}s` });
                  }, 1000);
                  return scanner.scan(root, token).finally(() => clearInterval(tick));
                },
              ),
      );
      store.load(outcome.report, outcome.root, outcome.usedAI);
      details.show(undefined);
      const s = store.summary();
      const secs = Math.round((Date.now() - started) / 1000);
      void vscode.window.setStatusBarMessage(`$(shield) Scan finished in ${secs}s: ${summaryText(s)}`, 8000);
      if (outcome.report.warnings.length && !opts.quiet) {
        void vscode.window
          .showWarningMessage(`Scan finished with warnings: ${outcome.report.warnings.join(" · ")}`, "Show Output")
          .then((c) => c && output.show());
      }
    } catch (err) {
      if (err instanceof ScanCancelled) {
        void vscode.window.setStatusBarMessage("$(circle-slash) Security scan cancelled", 4000);
      } else if (err instanceof ScanError) {
        const pick = await vscode.window.showErrorMessage(err.message, ...err.actions.map((a) => a.title));
        const action = err.actions.find((a) => a.title === pick);
        if (action) void vscode.commands.executeCommand(action.command, ...(action.args ?? []));
      } else {
        output.appendLine(String(err instanceof Error ? err.stack : err));
        const pick = await vscode.window.showErrorMessage(`Security scan failed: ${err instanceof Error ? err.message : err}`, "Show Output");
        if (pick) output.show();
      }
    } finally {
      void vscode.commands.executeCommand("setContext", "aiSecurity.scanning", false);
      statusBar.setScanning(false);
    }
  };

  const pickRoot = async (): Promise<string | undefined> => {
    const folders = vscode.workspace.workspaceFolders ?? [];
    if (!folders.length) {
      const picked = await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, openLabel: "Scan Folder" });
      return picked?.[0]?.fsPath;
    }
    if (folders.length === 1) return folders[0].uri.fsPath;
    const pick = await vscode.window.showQuickPick(
      folders.map((f) => ({ label: f.name, description: f.uri.fsPath, fsPath: f.uri.fsPath })),
      { placeHolder: "Which folder should be scanned?" },
    );
    return pick?.fsPath;
  };

  // ----- commands -----
  const register = (id: string, fn: (...args: any[]) => unknown) => context.subscriptions.push(vscode.commands.registerCommand(id, fn));

  register("aiSecurity.scan", async () => {
    const root = await pickRoot();
    if (root) await runScan(root);
  });
  register("aiSecurity.scanFolder", async (uri?: vscode.Uri) => {
    const root = uri?.fsPath ?? (await pickRoot());
    if (root) await runScan(root);
  });
  register("aiSecurity.cancelScan", () => scanner.cancel());
  register("aiSecurity.rescan", async () => {
    const root = store.root ?? (await pickRoot());
    if (root) await runScan(root);
  });
  register("aiSecurity.locateScanner", async () => {
    const picked = await vscode.window.showOpenDialog({
      canSelectFiles: true,
      canSelectFolders: false,
      canSelectMany: false,
      filters: { "Scanner CLI": ["py"] },
      openLabel: "Use this cli.py",
      title: "Select backend/cli.py from your ai-security-scanner folder",
    });
    const file = picked?.[0]?.fsPath;
    if (!file) return;
    if (path.basename(file).toLowerCase() !== "cli.py") {
      void vscode.window.showWarningMessage("Please pick the file named cli.py inside the backend folder.");
      return;
    }
    // User (global) setting, so every project can be scanned with it.
    await vscode.workspace.getConfiguration("aiSecurity").update("scannerPath", file, vscode.ConfigurationTarget.Global);
    const again = await vscode.window.showInformationMessage(`Scanner set to ${file}.`, "Scan Now");
    if (again) await vscode.commands.executeCommand("aiSecurity.scan");
  });

  register("aiSecurity.openFinding", async (arg) => {
    const t = resolve(arg);
    if (t) await openFinding(t);
  });
  register("aiSecurity.revealFinding", async (arg) => {
    const t = resolve(arg);
    if (!t) return;
    details.show(t.uid);
    await vscode.commands.executeCommand("workbench.view.extension.aiSecurity");
    await revealInTree(t.uid, false);
  });
  register("aiSecurity.applyFix", async (arg) => {
    const t = resolve(arg);
    return t ? applyFix(store, t) : false;
  });
  register("aiSecurity.showDiff", async (arg) => {
    const t = resolve(arg);
    if (t) await showDiff(store, t);
  });
  register("aiSecurity.ignore", (arg) => {
    const t = resolve(arg);
    if (!t) return;
    store.setIgnored(t, true);
    void vscode.window.setStatusBarMessage(`$(eye-closed) Ignored: ${t.data.title}`, 4000);
  });
  register("aiSecurity.unignore", (arg) => {
    const t = resolve(arg);
    if (t) store.setIgnored(t, false);
  });
  register("aiSecurity.copyDetails", async (arg) => {
    const t = resolve(arg);
    if (!t) return;
    await vscode.env.clipboard.writeText(findingAsText(t));
    void vscode.window.setStatusBarMessage("$(copy) Finding copied to clipboard", 3000);
  });
  register("aiSecurity.openReference", async (arg) => {
    const t = resolve(arg);
    const refs = t?.data.references.filter((r) => /^https?:\/\//i.test(r)) ?? [];
    const url = refs.length > 1 ? await vscode.window.showQuickPick(refs, { placeHolder: "Open which reference?" }) : refs[0];
    if (url) await vscode.env.openExternal(vscode.Uri.parse(url));
  });

  register("aiSecurity.groupBy", async () => {
    const options: { label: string; description: string; value: GroupBy }[] = [
      { label: "$(warning) Severity", description: "Critical → High → Medium → Low", value: "severity" },
      { label: "$(file) File", description: "One group per file", value: "file" },
      { label: "$(symbol-class) Type", description: "Code · Dependencies · Secrets", value: "category" },
    ];
    const pick = await vscode.window.showQuickPick(
      options.map((o) => ({ ...o, picked: o.value === store.groupBy, detail: o.value === store.groupBy ? "Current" : undefined })),
      { placeHolder: "Group findings by…" },
    );
    if (pick) store.setGroupBy(pick.value);
  });

  register("aiSecurity.filter", async () => {
    type Item = vscode.QuickPickItem & { sev?: Severity; cat?: Category };
    const counts = (pred: (t: TrackedFinding) => boolean) => store.all.filter((t) => !t.ignored && pred(t)).length;
    const f = store.filter;
    const items: Item[] = [
      { label: "Severity", kind: vscode.QuickPickItemKind.Separator },
      ...SEVERITIES.map((sev) => ({
        label: SEVERITY_LABEL[sev],
        description: String(counts((t) => t.data.severity === sev)),
        sev,
        picked: f.severities.includes(sev),
      })),
      { label: "Type", kind: vscode.QuickPickItemKind.Separator },
      ...CATEGORIES.map((cat) => ({
        label: CATEGORY_LABEL[cat],
        description: String(counts((t) => t.data.category === cat)),
        cat,
        picked: f.categories.includes(cat),
      })),
    ];
    const picked = await vscode.window.showQuickPick(items, {
      canPickMany: true,
      placeHolder: "Show only… (nothing ticked in a section = show all of it)",
    });
    if (!picked) return;
    store.setFilter({
      severities: picked.flatMap((i) => (i.sev ? [i.sev] : [])),
      categories: picked.flatMap((i) => (i.cat ? [i.cat] : [])),
    });
  });
  register("aiSecurity.clearFilter", () => store.clearFilter());
  register("aiSecurity.search", async () => {
    const text = await vscode.window.showInputBox({
      prompt: "Search findings by title, file, rule or package (empty clears the search)",
      value: store.filter.text,
      placeHolder: "e.g. sql, app.py, lodash",
    });
    if (text !== undefined) store.setFilter({ text });
  });
  register("aiSecurity.toggleShowIgnored", () => {
    const show = !store.filter.showIgnored;
    store.setFilter({ showIgnored: show });
    const n = store.summary().ignored;
    void vscode.window.setStatusBarMessage(show ? `$(eye) Showing ${n} ignored finding(s)` : "$(eye-closed) Ignored findings hidden", 3000);
  });
  register("aiSecurity.clearResults", () => {
    store.clear();
    details.show(undefined);
  });
  register("aiSecurity.openSettings", () => vscode.commands.executeCommand("workbench.action.openSettings", "aiSecurity"));
  register("aiSecurity.showOutput", () => output.show());

  // ----- keep results in sync with the editor -----
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => store.applyDocumentChange(e)),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("aiSecurity");
      const root = store.root;
      if (!cfg.get<boolean>("scanOnSave", false) || !root || doc.uri.scheme !== "file") return;
      if (path.relative(root, doc.uri.fsPath).startsWith("..")) return;
      if (saveTimer) clearTimeout(saveTimer);
      saveTimer = setTimeout(() => void runScan(root, { quiet: true }), 2000);
    }),
    { dispose: () => saveTimer && clearTimeout(saveTimer) },
  );

  return { store, tree };
}

export function deactivate() {}

function timeAgo(ts: number): string {
  const mins = Math.round((Date.now() - ts) / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(ts).toLocaleDateString();
}
