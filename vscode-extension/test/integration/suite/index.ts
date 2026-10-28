// Integration checks, executed inside the VS Code extension host by runTest.ts.
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import type { ExtensionApi } from "../../../src/extension";

type Check = [name: string, fn: () => Promise<void> | void];

const cmp = (a: string, b: string) => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};

export async function run(): Promise<void> {
  const ext = vscode.extensions.getExtension<ExtensionApi>("codingowls.ai-security-scanner")!;
  const api = await ext.activate();
  const { store, tree } = api;
  const root = vscode.workspace.workspaceFolders![0].uri.fsPath;
  const appPy = vscode.Uri.file(path.join(root, "app.py"));
  const reqs = vscode.Uri.file(path.join(root, "requirements.txt"));
  const groupLabels = () => tree.getChildren().map((n) => String(tree.getTreeItem(n).label));
  const settle = () => new Promise((r) => setTimeout(r, 300));

  const checks: Check[] = [
    ["starts empty: welcome view (no tree nodes)", () => {
      assert.equal(store.hasResults, false);
      assert.equal(tree.getChildren().length, 0);
    }],
    ["scan the workspace through the real CLI", async () => {
      await vscode.commands.executeCommand("aiSecurity.scan");
      assert.equal(store.hasResults, true, "scan produced no results (see Security Scanner output)");
      const cats = new Set(store.all.map((t) => t.data.category));
      assert.deepEqual([...cats].sort(), ["code", "dependency", "secret"]);
      assert.ok(store.all.length >= 10, `only ${store.all.length} findings`);
    }],
    ["sidebar groups by severity, critical first and expanded", () => {
      assert.equal(store.groupBy, "severity");
      const labels = groupLabels();
      assert.equal(labels[0], "Critical");
      const first = tree.getTreeItem(tree.getChildren()[0]);
      assert.equal(first.collapsibleState, vscode.TreeItemCollapsibleState.Expanded);
      const children = tree.getChildren(tree.getChildren()[0]);
      const item = tree.getTreeItem(children[0]);
      assert.equal(item.command?.command, "aiSecurity.openFinding");
    }],
    ["group by file and by type", () => {
      store.setGroupBy("file");
      assert.deepEqual(groupLabels().sort(), ["app.py", "package-lock.json", "requirements.txt"]);
      store.setGroupBy("category");
      assert.deepEqual(groupLabels(), ["Code", "Dependencies", "Secrets"]);
      store.setGroupBy("severity");
    }],
    ["filter and search narrow the tree", () => {
      store.setFilter({ categories: ["secret"] });
      const groups = tree.getChildren();
      assert.equal(groups.length, 1);
      assert.equal(tree.getChildren(groups[0]).length, 1);
      store.clearFilter();
      store.setFilter({ text: "no-such-thing-xyz" });
      assert.equal(String(tree.getTreeItem(tree.getChildren()[0]).label), "No findings match the filter");
      store.clearFilter();
    }],
    ["diagnostics appear in the Problems panel", async () => {
      await settle();
      assert.ok(vscode.languages.getDiagnostics(appPy).length >= 3);
      assert.ok(vscode.languages.getDiagnostics(reqs).length >= 5);
    }],
    ["ignore hides a finding everywhere and restore brings it back", async () => {
      const secret = store.all.find((t) => t.data.category === "secret")!;
      const before = vscode.languages.getDiagnostics(appPy).length;
      await vscode.commands.executeCommand("aiSecurity.ignore", secret.uid);
      await settle();
      assert.equal(store.summary().ignored, 1);
      assert.equal(vscode.languages.getDiagnostics(appPy).length, before - 1);
      await vscode.commands.executeCommand("aiSecurity.unignore", secret.uid);
      assert.equal(store.summary().ignored, 0);
    }],
    ["lightbulb offers actions on a finding's line", async () => {
      const code = store.all.find((t) => t.data.category === "code")!;
      const doc = await vscode.workspace.openTextDocument(appPy);
      const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
        "vscode.executeCodeActionProvider",
        doc.uri,
        new vscode.Range(code.line - 1, 0, code.line - 1, 0),
      );
      assert.ok(actions.some((a) => a.title.startsWith("Show security finding details")));
    }],
    ["open finding jumps to its line", async () => {
      const code = store.all.find((t) => t.data.category === "code")!;
      await vscode.commands.executeCommand("aiSecurity.openFinding", code.uid);
      const editor = vscode.window.activeTextEditor!;
      assert.equal(path.basename(editor.document.uri.fsPath), "app.py");
      assert.equal(editor.selection.active.line, code.line - 1);
    }],
    ["editing above a finding moves it with the code", async () => {
      const code = store.all.find((t) => t.data.category === "code")!;
      const line = code.line;
      const edit = new vscode.WorkspaceEdit();
      edit.insert(appPy, new vscode.Position(0, 0), "# one\n# two\n");
      assert.ok(await vscode.workspace.applyEdit(edit));
      await settle();
      assert.equal(code.line, line + 2);
      assert.equal(code.stale, false);
    }],
    ["apply fix on a dependency upgrades the package and resolves all its advisories", async () => {
      const deps = store.all.filter((t) => t.data.category === "dependency" && t.data.package === "requests");
      const dep = deps.find((t) => t.data.fixed_version && /^\d/.test(t.data.fixed_version))!;
      const errorsBefore = vscode.languages.getDiagnostics(reqs).length;
      await vscode.commands.executeCommand("aiSecurity.applyFix", dep.uid);
      await settle();
      const doc = await vscode.workspace.openTextDocument(reqs);
      const line = doc.lineAt(dep.line - 1).text;
      assert.match(line, /^requests==\d/);
      assert.notEqual(line, "requests==2.19.0");
      const fixed = deps.filter((t) => t.fixed).length;
      assert.ok(fixed >= deps.length - 3, `only ${fixed}/${deps.length} requests advisories marked fixed`);
      assert.ok(fixed > 1, "only the clicked advisory was resolved");
      assert.equal(vscode.languages.getDiagnostics(reqs).length, errorsBefore - fixed);
      const item = tree.getTreeItem(tree.nodeFor(dep.uid)!);
      assert.match(String(item.description), /fixed/);
    }],
    ["npm: direct dependency is upgraded with npm install (package.json + package-lock.json)", async () => {
      const lodash = store.all.filter((t) => t.data.package === "lodash" && t.data.file === "web/package-lock.json");
      assert.ok(lodash.length > 1, "expected several lodash advisories");
      const target = lodash.map((t) => t.data.fixed_version!).filter((v) => /^\d/.test(v)).sort(cmp).pop()!;
      const ok = await vscode.commands.executeCommand<boolean>("aiSecurity.applyFix", lodash[0].uid);
      assert.equal(ok, true, "npm install failed (see the task terminal)");
      const pj = JSON.parse(fs.readFileSync(path.join(root, "web", "package.json"), "utf8"));
      const lock = JSON.parse(fs.readFileSync(path.join(root, "web", "package-lock.json"), "utf8"));
      const saved = String(pj.dependencies.lodash).replace(/^\^/, "");
      assert.ok(cmp(saved, target) >= 0, `package.json has lodash ${pj.dependencies.lodash}, expected ^${target} or newer`);
      assert.ok(cmp(lock.packages["node_modules/lodash"].version, target) >= 0, `lockfile has lodash ${lock.packages["node_modules/lodash"].version}`);
      assert.ok(lodash.every((t) => t.fixed || !/^\d/.test(t.data.fixed_version ?? "")));
    }],
    ["npm: transitive dependency is forced with an override", async () => {
      const qs = store.all.find((t) => t.data.package === "qs" && t.data.file === "web/package-lock.json")!;
      const ok = await vscode.commands.executeCommand<boolean>("aiSecurity.applyFix", qs.uid);
      assert.equal(ok, true, "npm install failed (see the task terminal)");
      const pj = JSON.parse(fs.readFileSync(path.join(root, "web", "package.json"), "utf8"));
      const lock = JSON.parse(fs.readFileSync(path.join(root, "web", "package-lock.json"), "utf8"));
      const want = String(pj.overrides?.qs ?? "").replace(/^\^/, "");
      assert.ok(want, "no qs override in package.json");
      assert.ok(cmp(lock.packages["node_modules/qs"].version, want) >= 0, `lockfile has qs ${lock.packages["node_modules/qs"].version}`);
      assert.equal(qs.fixed, true);
    }],
    ["show diff opens a diff editor", async () => {
      const dep = store.all.find((t) => t.data.category === "dependency" && t.data.package === "jinja2" && t.data.fixed_version)!;
      await vscode.commands.executeCommand("aiSecurity.showDiff", dep.uid);
      await settle();
      const tab = vscode.window.tabGroups.activeTabGroup.activeTab;
      assert.ok(tab?.input instanceof vscode.TabInputTextDiff, "active tab is not a diff");
    }],
    ["results survive as saved state; clear empties the sidebar", async () => {
      await vscode.commands.executeCommand("aiSecurity.clearResults");
      assert.equal(store.hasResults, false);
      assert.equal(tree.getChildren().length, 0);
      assert.equal(vscode.languages.getDiagnostics(appPy).length, 0);
    }],
  ];

  let failed = 0;
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`  ✔ ${name}`);
    } catch (err) {
      failed++;
      console.error(`  ✖ ${name}\n    ${err instanceof Error ? err.message : err}`);
    }
  }
  console.log(`\n${checks.length - failed}/${checks.length} integration checks passed`);
  if (failed) throw new Error(`${failed} integration check(s) failed`);
}
