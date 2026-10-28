import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { applyEdit, computeFix, dependencyUpgrade, DependencyUpgrade, fixKind, FixResult, stripFences } from "./core/fixes";
import { applyPackageJsonPatch, PackageJson, planUpgrade, UpgradePlan } from "./core/packageManagers";
import { TrackedFinding } from "./core/types";
import { FindingsStore } from "./findingsStore";

export const FIX_SCHEME = "ai-security-fix";

const docLines = (doc: vscode.TextDocument) => doc.getText().split(/\r?\n/);
const eolOf = (doc: vscode.TextDocument) => (doc.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n");

/** Upgrade target for a dependency finding: the version that fixes all of the package's advisories. */
export function upgradeFor(store: FindingsStore, t: TrackedFinding) {
  return dependencyUpgrade(t.data, store.all.map((o) => o.data));
}

/** The fix for `t` against the file's current lines (dependency fixes upgrade the whole package). */
export function fixFor(store: FindingsStore, t: TrackedFinding, lines: string[]): FixResult {
  return computeFix(t.data, lines, t.line, upgradeFor(store, t)?.target);
}

function readPackageJson(dir: string): PackageJson | null {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")) as PackageJson;
  } catch {
    return null;
  }
}

/** How a dependency finding gets fixed: edit the manifest line, run the package manager, or a manual command. */
export function planFor(store: FindingsStore, t: TrackedFinding): { plan: UpgradePlan; upgrade: DependencyUpgrade } | undefined {
  const upgrade = upgradeFor(store, t);
  const uri = store.uriFor(t);
  if (!upgrade || !uri) return undefined;
  const plan = planUpgrade(t.data.file, t.data.package!, upgrade.target, readPackageJson(path.dirname(uri.fsPath)));
  return { plan, upgrade };
}

const advisories = (n: number) => `${n} advisor${n === 1 ? "y" : "ies"}`;

/**
 * Lockfile-based dependency fix: runs npm/yarn as a VS Code task (visible in the terminal) so that
 * package.json, the lockfile and node_modules are updated together, as the package manager intends.
 */
async function runPackageManager(
  store: FindingsStore,
  t: TrackedFinding,
  plan: Extract<UpgradePlan, { kind: "run" }>,
  upgrade: DependencyUpgrade,
): Promise<boolean> {
  const lockUri = store.uriFor(t)!;
  const cwd = path.dirname(lockUri.fsPath);
  const pkg = t.data.package!;

  if (vscode.workspace.getConfiguration("aiSecurity").get<boolean>("confirmPackageManager", true)) {
    const run = `Run ${plan.tool}`;
    const choice = await vscode.window.showWarningMessage(
      `Upgrade ${pkg} ${t.data.installed_version} → ${upgrade.target} with ${plan.tool}?`,
      { modal: true, detail: `${plan.summary}\n\nFolder: ${cwd}\nFixes ${advisories(upgrade.covered.length)}.` },
      run,
    );
    if (choice !== run) return false;
  }

  // The package manager reads package.json from disk: save pending edits, apply the override if any.
  const pkgJsonUri = vscode.Uri.file(path.join(cwd, "package.json"));
  const openPkgJson = vscode.workspace.textDocuments.find((d) => d.uri.fsPath === pkgJsonUri.fsPath);
  if (openPkgJson?.isDirty) await openPkgJson.save();
  if (plan.patch) {
    const doc = await vscode.workspace.openTextDocument(pkgJsonUri);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(pkgJsonUri, new vscode.Range(0, 0, doc.lineCount, 0), applyPackageJsonPatch(doc.getText(), plan.patch));
    if (!(await vscode.workspace.applyEdit(edit)) || !(await doc.save())) {
      void vscode.window.showErrorMessage(`Could not update ${plan.patch.field} in package.json.`);
      return false;
    }
  }

  const id = `upgrade-${pkg}-${Date.now()}`;
  const scope = vscode.workspace.getWorkspaceFolder(lockUri) ?? vscode.TaskScope.Workspace;
  // Strong quoting keeps "^" literal in cmd.exe and PowerShell.
  const args = plan.argv.map((value) => ({ value, quoting: vscode.ShellQuoting.Strong }));
  const task = new vscode.Task(
    { type: "aiSecurity", id },
    scope,
    `upgrade ${pkg} to ${upgrade.target}`,
    "Security Scanner",
    new vscode.ShellExecution(plan.tool, args, { cwd }),
  );
  task.presentationOptions = { reveal: vscode.TaskRevealKind.Always, panel: vscode.TaskPanelKind.Dedicated, clear: true, focus: false };

  const exitCode = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `${plan.tool}: upgrading ${pkg} to ${upgrade.target}…` },
    () =>
      new Promise<number | undefined>((resolve) => {
        const sub = vscode.tasks.onDidEndTaskProcess((e) => {
          if (e.execution.task.definition.id === id) {
            sub.dispose();
            resolve(e.exitCode);
          }
        });
        vscode.tasks.executeTask(task).then(undefined, (err) => {
          sub.dispose();
          void vscode.window.showErrorMessage(`Could not start ${plan.tool}: ${err instanceof Error ? err.message : err}`);
          resolve(-1);
        });
      }),
  );
  if (exitCode !== 0) {
    if (exitCode !== -1) {
      void vscode.window.showErrorMessage(
        `${plan.tool} exited with code ${exitCode}; see the terminal.` +
          (plan.patch ? ` The ${plan.patch.field} entry was added to package.json; undo it with git if needed.` : ""),
      );
    }
    return false;
  }

  const covered = new Set(upgrade.covered);
  const resolved = store.all.filter((o) => covered.has(o.data));
  store.markFixed(resolved);
  const lock = path.basename(lockUri.fsPath);
  const changed = plan.patch ? `package.json (${plan.patch.field}), ${lock}` : `package.json, ${lock}`;
  void vscode.window
    .showInformationMessage(
      `Upgraded ${pkg} to ${upgrade.target}: ${changed} and node_modules updated, ${advisories(resolved.length)} fixed. Re-scan to confirm.`,
      "Re-scan",
    )
    .then((c) => c && vscode.commands.executeCommand("aiSecurity.rescan"));
  return true;
}

/** Ecosystems we don't drive: type the command into a terminal in the right folder, for the user to run. */
function openManualCommand(store: FindingsStore, t: TrackedFinding, plan: Extract<UpgradePlan, { kind: "manual" }>): boolean {
  const cwd = path.dirname(store.uriFor(t)!.fsPath);
  const terminal = vscode.window.createTerminal({ name: `Security fix: ${t.data.package}`, cwd });
  terminal.show();
  terminal.sendText(plan.command, false);
  void vscode.window.showInformationMessage(`${plan.summary} The command is ready in the terminal: press Enter to run it, then re-scan.`);
  return false;
}

/**
 * Applies a finding's suggested fix as one undoable edit, and marks every finding the edit
 * resolves as fixed (pending a re-scan): all advisories of an upgraded package, or every finding
 * on the replaced code lines. Returns false (with a message) if it can't.
 */
export async function applyFix(store: FindingsStore, t: TrackedFinding): Promise<boolean> {
  const uri = store.uriFor(t);
  if (!uri) return false;
  const dep = planFor(store, t);
  if (dep?.plan.kind === "run") return runPackageManager(store, t, dep.plan, dep.upgrade);
  if (dep?.plan.kind === "manual") return openManualCommand(store, t, dep.plan);

  const doc = await vscode.workspace.openTextDocument(uri);
  const result = fixFor(store, t, docLines(doc));
  if (!result.ok) {
    const choice = await vscode.window.showWarningMessage(result.reason, "Show Diff");
    if (choice) await showDiff(store, t);
    return false;
  }
  const { startLine, endLine, lines } = result.edit;

  // Work out what the edit resolves before applying it (positions shift afterwards).
  let resolved: TrackedFinding[];
  let summary: string;
  const upgrade = upgradeFor(store, t);
  if (upgrade) {
    const keys = new Set(upgrade.covered);
    resolved = store.all.filter((o) => keys.has(o.data));
    const left = upgrade.siblings.length - upgrade.covered.length;
    summary =
      `Upgraded ${t.data.package} ${t.data.installed_version} → ${upgrade.target}: fixes ${resolved.length} advisor${resolved.length === 1 ? "y" : "ies"}` +
      (left ? ` (${left} more have no published fix)` : "") +
      ".";
  } else {
    resolved = store.inFile(uri.fsPath).filter((o) => !o.fixed && o.line - 1 <= endLine && o.endLine - 1 >= startLine);
    if (!resolved.includes(t)) resolved.push(t);
    const others = resolved.length - 1;
    summary = `Fix applied to ${path.basename(uri.fsPath)}` + (others ? `; it also covers ${others} other finding${others === 1 ? "" : "s"} on the same lines.` : ".");
  }

  const range = new vscode.Range(startLine, 0, endLine, doc.lineAt(endLine).text.length);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(uri, range, lines.join(eolOf(doc)), { label: `Fix: ${t.data.title}`, needsConfirmation: false });
  if (!(await vscode.workspace.applyEdit(edit))) {
    void vscode.window.showErrorMessage("Could not apply the fix.");
    return false;
  }
  store.markFixed(resolved);

  const editor = await vscode.window.showTextDocument(doc, { preserveFocus: false });
  const newEnd = startLine + lines.length - 1;
  editor.selection = new vscode.Selection(startLine, 0, newEnd, doc.lineAt(Math.min(newEnd, doc.lineCount - 1)).text.length);
  editor.revealRange(editor.selection, vscode.TextEditorRevealType.InCenterIfOutsideViewport);

  // Not awaited: the command finishes now, the buttons work whenever the user clicks them.
  void vscode.window.showInformationMessage(`${summary} Save and re-scan to confirm (Ctrl+Z undoes it).`, "Save & Re-scan").then(async (choice) => {
    if (choice && (await doc.save())) await vscode.commands.executeCommand("aiSecurity.rescan");
  });
  return true;
}

/** Diff of the current file against the file with the fix applied (or just the snippets, if the code moved). */
export async function showDiff(store: FindingsStore, t: TrackedFinding) {
  const uri = store.uriFor(t);
  if (!uri) return;
  const dep = planFor(store, t);
  if (dep && dep.plan.kind !== "edit") {
    // Lockfile changes come from the package manager, so there is no text diff to preview.
    const pick = await vscode.window.showInformationMessage(
      dep.plan.kind === "run" ? `Apply fix runs: ${dep.plan.summary}` : dep.plan.summary,
      "Apply Fix",
    );
    if (pick) await vscode.commands.executeCommand("aiSecurity.applyFix", t.uid);
    return;
  }
  const name = path.basename(uri.fsPath);
  const query = `uid=${encodeURIComponent(t.uid)}`;
  const doc = await vscode.workspace.openTextDocument(uri);
  const result = fixKind(t.data) ? fixFor(store, t, docLines(doc)) : undefined;
  if (result?.ok) {
    const after = vscode.Uri.from({ scheme: FIX_SCHEME, path: `/after/${name}`, query });
    await vscode.commands.executeCommand("vscode.diff", uri, after, `${name} ↔ Suggested fix`);
  } else {
    const before = vscode.Uri.from({ scheme: FIX_SCHEME, path: `/snippet-before/${name}`, query });
    const after = vscode.Uri.from({ scheme: FIX_SCHEME, path: `/snippet-after/${name}`, query });
    await vscode.commands.executeCommand("vscode.diff", before, after, `${name}: vulnerable ↔ suggested (snippet)`);
  }
}

/** Serves the virtual "after fix" documents shown in the diff editor. */
export class FixContentProvider implements vscode.TextDocumentContentProvider {
  constructor(private readonly store: FindingsStore) {}

  async provideTextDocumentContent(uri: vscode.Uri): Promise<string> {
    const uid = new URLSearchParams(uri.query).get("uid") ?? "";
    const t = this.store.get(uid);
    if (!t) return "(finding no longer available, re-run the diff)";
    if (uri.path.startsWith("/snippet-before/")) return t.data.vulnerable_code;
    if (uri.path.startsWith("/snippet-after/")) return stripFences(t.data.fixed_code);
    const fileUri = this.store.uriFor(t)!;
    const doc = await vscode.workspace.openTextDocument(fileUri);
    const lines = docLines(doc);
    const result = fixFor(this.store, t, lines);
    return (result.ok ? applyEdit(lines, result.edit) : lines).join(eolOf(doc));
  }
}

/** Lightbulb actions on lines that have findings. */
export class FindingCodeActionProvider implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly store: FindingsStore) {}

  provideCodeActions(doc: vscode.TextDocument, range: vscode.Range | vscode.Selection): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const t of this.store.inFile(doc.uri.fsPath)) {
      if (t.ignored) continue;
      if (t.line - 1 > range.end.line || t.endLine - 1 < range.start.line) continue;
      const short = t.data.title.length > 60 ? t.data.title.slice(0, 57) + "…" : t.data.title;
      if (fixKind(t.data) && !t.fixed) {
        const dep = planFor(this.store, t);
        const title =
          dep && dep.plan.kind !== "edit"
            ? `Upgrade ${t.data.package} to ${dep.upgrade.target} (${dep.plan.tool}): fixes ${advisories(dep.upgrade.covered.length)}`
            : `Apply suggested fix: ${short}`;
        const fix = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
        fix.command = { title: "Apply Suggested Fix", command: "aiSecurity.applyFix", arguments: [t.uid] };
        fix.isPreferred = true;
        actions.push(fix);
      }
      const details = new vscode.CodeAction(`Show security finding details: ${short}`, vscode.CodeActionKind.QuickFix);
      details.command = { title: "Show Details", command: "aiSecurity.revealFinding", arguments: [t.uid] };
      actions.push(details);
      const ignore = new vscode.CodeAction(`Ignore security finding: ${short}`, vscode.CodeActionKind.QuickFix);
      ignore.command = { title: "Ignore", command: "aiSecurity.ignore", arguments: [t.uid] };
      actions.push(ignore);
    }
    return actions;
  }
}
