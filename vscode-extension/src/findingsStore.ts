import * as path from "path";
import * as vscode from "vscode";
import { groupFindings, Group, isFilterActive, summarize, Summary } from "./core/grouping";
import { shiftForChange } from "./core/lineTracking";
import { track } from "./core/report";
import { EMPTY_FILTER, FilterState, Finding, GroupBy, GROUP_BYS, ScanReport, TrackedFinding } from "./core/types";

const STATE_LAST_SCAN = "aiSecurity.lastScan";
const STATE_IGNORED = "aiSecurity.ignored";
const STATE_GROUP_BY = "aiSecurity.groupBy";

interface SavedScan {
  root: string;
  scannedAt: number;
  usedAI: boolean;
  report: ScanReport;
}

/**
 * Single source of truth for scan results and sidebar state. Every view (tree, details,
 * diagnostics, status bar) listens to `onDidChange` and re-renders from here.
 */
export class FindingsStore implements vscode.Disposable {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChange = this.emitter.event;

  private findings: TrackedFinding[] = [];
  private ignored: Set<string>;
  private _filter: FilterState = { ...EMPTY_FILTER };
  private _groupBy: GroupBy;
  private _root: string | undefined;
  private _scannedAt: number | undefined;
  private _usedAI = false;
  private _warnings: string[] = [];
  private _fromPreviousSession = false;

  constructor(private readonly state: vscode.Memento) {
    this.ignored = new Set(state.get<string[]>(STATE_IGNORED, []));
    const savedGroupBy = state.get<GroupBy>(STATE_GROUP_BY);
    const configured = vscode.workspace.getConfiguration("aiSecurity").get<GroupBy>("groupBy", "severity");
    this._groupBy = savedGroupBy && GROUP_BYS.includes(savedGroupBy) ? savedGroupBy : configured;

    const saved = state.get<SavedScan>(STATE_LAST_SCAN);
    if (saved?.report?.vulnerabilities) {
      this.load(saved.report, saved.root, saved.usedAI, saved.scannedAt, false);
      this._fromPreviousSession = true;
    }
    this.syncContext();
  }

  dispose() {
    this.emitter.dispose();
  }

  // ----- reads -----
  get all(): readonly TrackedFinding[] {
    return this.findings;
  }
  get root() {
    return this._root;
  }
  get scannedAt() {
    return this._scannedAt;
  }
  get usedAI() {
    return this._usedAI;
  }
  get warnings(): readonly string[] {
    return this._warnings;
  }
  get fromPreviousSession() {
    return this._fromPreviousSession;
  }
  get hasResults() {
    return this._root !== undefined;
  }
  get filter(): FilterState {
    return this._filter;
  }
  get groupBy(): GroupBy {
    return this._groupBy;
  }

  groups(): Group[] {
    return groupFindings(this.findings, this._groupBy, this._filter);
  }

  summary(): Summary {
    return summarize(this.findings);
  }

  get(uid: string): TrackedFinding | undefined {
    return this.findings.find((t) => t.uid === uid);
  }

  uriFor(t: TrackedFinding | Finding): vscode.Uri | undefined {
    if (!this._root) return undefined;
    const file = "data" in t ? t.data.file : t.file;
    return vscode.Uri.file(path.join(this._root, ...file.split("/")));
  }

  /** Findings in a given file (by absolute fsPath). */
  inFile(fsPath: string): TrackedFinding[] {
    if (!this._root) return [];
    const rel = path.relative(this._root, fsPath).split(path.sep).join("/");
    if (rel.startsWith("..")) return [];
    const norm = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
    return this.findings.filter((t) => norm(t.data.file) === norm(rel));
  }

  // ----- writes -----
  load(report: ScanReport, root: string, usedAI: boolean, scannedAt = Date.now(), persist = true) {
    this.findings = track(report.vulnerabilities, this.ignored);
    this._root = root;
    this._scannedAt = scannedAt;
    this._usedAI = usedAI;
    this._warnings = report.warnings;
    this._fromPreviousSession = false;
    if (persist) void this.state.update(STATE_LAST_SCAN, { root, scannedAt, usedAI, report } satisfies SavedScan);
    this.changed();
  }

  clear() {
    this.findings = [];
    this._root = undefined;
    this._scannedAt = undefined;
    this._warnings = [];
    void this.state.update(STATE_LAST_SCAN, undefined);
    this.changed();
  }

  setGroupBy(g: GroupBy) {
    this._groupBy = g;
    void this.state.update(STATE_GROUP_BY, g);
    this.changed();
  }

  setFilter(patch: Partial<FilterState>) {
    this._filter = { ...this._filter, ...patch };
    this.changed();
  }

  clearFilter() {
    this._filter = { ...EMPTY_FILTER, showIgnored: this._filter.showIgnored };
    this.changed();
  }

  setIgnored(t: TrackedFinding, ignored: boolean) {
    if (ignored) this.ignored.add(t.key);
    else this.ignored.delete(t.key);
    // Same key = same issue (e.g. reported twice); keep them in sync.
    for (const other of this.findings) if (other.key === t.key) other.ignored = ignored;
    void this.state.update(STATE_IGNORED, [...this.ignored]);
    this.changed();
  }

  markFixed(items: TrackedFinding | TrackedFinding[]) {
    for (const t of Array.isArray(items) ? items : [items]) {
      t.fixed = true;
      t.stale = false;
    }
    this.changed();
  }

  /** Keeps finding positions in sync with edits made after the scan. */
  applyDocumentChange(e: vscode.TextDocumentChangeEvent) {
    if (!e.contentChanges.length || e.document.uri.scheme !== "file") return;
    const affected = this.inFile(e.document.uri.fsPath);
    if (!affected.length) return;
    let changed = false;
    // VS Code reports changes in one event against the pre-edit document, ordered bottom-up
    // for multi-cursor edits; applying them in reverse document order keeps positions valid.
    const changes = [...e.contentChanges].sort((a, b) => b.range.start.compareTo(a.range.start));
    for (const c of changes) {
      const lc = {
        startLine: c.range.start.line,
        endLine: c.range.end.line,
        endCharacter: c.range.end.character,
        insertedLineBreaks: (c.text.match(/\n/g) ?? []).length,
      };
      for (const t of affected) {
        const r = shiftForChange(t.line, t.endLine, lc);
        if (r.kind === "shifted") {
          t.line = r.line;
          t.endLine = r.endLine;
          changed = true;
        } else if (r.kind === "overlap" && !t.stale && !t.fixed) {
          t.stale = true;
          changed = true;
        }
      }
    }
    if (changed) this.changed();
  }

  private changed() {
    this.syncContext();
    this.emitter.fire();
  }

  private syncContext() {
    void vscode.commands.executeCommand("setContext", "aiSecurity.hasFilter", isFilterActive(this._filter));
    void vscode.commands.executeCommand("setContext", "aiSecurity.hasResults", this.hasResults);
  }
}
