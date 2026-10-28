import * as vscode from "vscode";
import { fixKind } from "../core/fixes";
import { Group, isFilterActive } from "../core/grouping";
import { CATEGORY_LABEL, Category, Severity, TrackedFinding } from "../core/types";
import { FindingsStore } from "../findingsStore";
import { CATEGORY_ICON, findingTooltip, SEVERITY_COLOR, severityDot, severityIcon } from "../presentation";

export type Node = GroupNode | FindingNode | MessageNode;

export class GroupNode {
  readonly type = "group";
  constructor(readonly group: Group) {}
}

export class FindingNode {
  readonly type = "finding";
  constructor(readonly finding: TrackedFinding, readonly parent: GroupNode) {}
}

/** Shown instead of the welcome view when a scan ran but nothing is visible. */
export class MessageNode {
  readonly type = "message";
  constructor(readonly label: string, readonly icon: string, readonly command?: vscode.Command) {}
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<Node> {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;

  private roots: Node[] = [];
  /** uid → node, so a finding can be revealed/selected from outside the tree. */
  private nodesByUid = new Map<string, FindingNode>();

  constructor(private readonly store: FindingsStore) {
    this.rebuild();
    store.onDidChange(() => {
      this.rebuild();
      this.emitter.fire(undefined);
    });
  }

  nodeFor(uid: string): FindingNode | undefined {
    return this.nodesByUid.get(uid);
  }

  private rebuild() {
    this.nodesByUid.clear();
    if (!this.store.hasResults) {
      this.roots = []; // → welcome view with the "Scan Workspace" button
      return;
    }
    const groups = this.store.groups();
    if (!groups.length) {
      const s = this.store.summary();
      this.roots = isFilterActive(this.store.filter)
        ? [new MessageNode("No findings match the filter", "filter", { title: "Clear Filter", command: "aiSecurity.clearFilter" })]
        : s.ignored
          ? [new MessageNode(`No open findings (${s.ignored} ignored)`, "pass", { title: "Show Ignored", command: "aiSecurity.toggleShowIgnored" })]
          : [new MessageNode("No security issues found", "pass-filled")];
      return;
    }
    this.roots = groups.map((g) => {
      const node = new GroupNode(g);
      for (const f of g.findings) this.nodesByUid.set(f.uid, new FindingNode(f, node));
      return node;
    });
  }

  getChildren(element?: Node): Node[] {
    if (!element) return this.roots;
    if (element instanceof GroupNode) return element.group.findings.map((f) => this.nodesByUid.get(f.uid)!);
    return [];
  }

  getParent(element: Node): Node | undefined {
    return element instanceof FindingNode ? element.parent : undefined;
  }

  getTreeItem(element: Node): vscode.TreeItem {
    if (element instanceof GroupNode) return this.groupItem(element.group);
    if (element instanceof FindingNode) return this.findingItem(element);
    const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon(element.icon);
    item.command = element.command;
    return item;
  }

  private groupItem(g: Group): vscode.TreeItem {
    // Critical/high groups (and every file/category group with critical/high in it) start expanded.
    const expanded = g.topSeverity === "critical" || g.topSeverity === "high";
    const item = new vscode.TreeItem(
      g.label,
      expanded ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed,
    );
    item.id = `${this.store.groupBy}|${g.id}`;
    item.contextValue = `group.${g.kind}`;
    const n = g.findings.length;
    if (g.kind === "severity") {
      item.iconPath = severityDot(g.value as Severity);
      item.description = String(n);
    } else if (g.kind === "category") {
      item.iconPath = new vscode.ThemeIcon(CATEGORY_ICON[g.value as Category], new vscode.ThemeColor(colorFor(g.topSeverity)));
      item.description = String(n);
    } else {
      const uri = this.store.uriFor({ file: g.value } as TrackedFinding["data"]);
      item.resourceUri = uri; // file-type icon from the user's icon theme
      item.iconPath = vscode.ThemeIcon.File;
      const dir = g.value.includes("/") ? g.value.slice(0, g.value.lastIndexOf("/")) : "";
      item.description = `${n}${dir ? `  ${dir}` : ""}`;
      item.tooltip = `${g.value}: ${n} finding${n === 1 ? "" : "s"}`;
    }
    return item;
  }

  private findingItem(node: FindingNode): vscode.TreeItem {
    const t = node.finding;
    const d = t.data;
    const item = new vscode.TreeItem(d.title, vscode.TreeItemCollapsibleState.None);
    item.id = `${this.store.groupBy}|${node.parent.group.id}|${t.uid}`;

    const where = this.store.groupBy === "file" ? `line ${t.line}` : `${d.file.split("/").pop()}:${t.line}`;
    const extra =
      this.store.groupBy === "category" || d.category === "code" ? "" : ` · ${CATEGORY_LABEL[d.category].replace(/s$/, "").toLowerCase()}`;
    const state = t.fixed ? "✓ fixed · " : t.ignored ? "ignored · " : t.stale ? "changed · " : "";
    item.description = `${state}${where}${extra}`;

    item.iconPath = t.fixed
      ? new vscode.ThemeIcon("pass", new vscode.ThemeColor("charts.green"))
      : t.ignored
        ? new vscode.ThemeIcon("eye-closed", new vscode.ThemeColor("disabledForeground"))
        : this.store.groupBy === "severity"
          ? new vscode.ThemeIcon(CATEGORY_ICON[d.category], new vscode.ThemeColor(colorFor(d.severity)))
          : severityIcon(d.severity);

    item.tooltip = findingTooltip(t);
    const flags = [
      "finding",
      fixKind(d) && !t.fixed ? "fixable" : "",
      fixKind(d) ? "hasfix" : "",
      t.ignored ? "ignored" : "",
      d.references.length ? "ref" : "",
    ].filter(Boolean);
    item.contextValue = flags.join(" ");
    item.command = { title: "Open Finding", command: "aiSecurity.openFinding", arguments: [t.uid] };
    item.accessibilityInformation = { label: `${d.severity} severity: ${d.title}, ${d.file} line ${t.line}` };
    return item;
  }
}

const colorFor = (s: Severity) => SEVERITY_COLOR[s];
