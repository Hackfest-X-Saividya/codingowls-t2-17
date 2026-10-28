import { isPlaceholder } from "./report";
import { Finding } from "./types";

export type FixKind = "code" | "dependency";

/** Replace lines startLine..endLine (0-based, inclusive) with `lines`. */
export interface FixEdit {
  startLine: number;
  endLine: number;
  lines: string[];
}

export type FixResult = { ok: true; edit: FixEdit } | { ok: false; reason: string };

/** How far (in lines) from the reported position we look for the vulnerable code. */
const SEARCH_WINDOW = 60;

/**
 * Whether a finding carries a fix that can be applied to the file automatically:
 * - code: an AI-written replacement for `vulnerable_code`
 * - dependency: bump `installed_version` to `fixed_version` on the manifest line
 * Secret findings only carry instructions (rotate the key), so they are never auto-fixable.
 */
export function fixKind(f: Finding): FixKind | null {
  if (f.category === "dependency") {
    return f.package && f.installed_version && isVersion(f.fixed_version) && f.installed_version !== f.fixed_version ? "dependency" : null;
  }
  if (f.category === "code") {
    if (isPlaceholder(f.fixed_code) || isPlaceholder(f.vulnerable_code)) return null;
    const fix = stripFences(f.fixed_code).trim();
    return fix && fix !== f.vulnerable_code.trim() ? "code" : null;
  }
  return null;
}

/** An installable version like 2.32.4 or 1.0.0-rc1, not a git commit hash. */
export function isVersion(v: string | null | undefined): v is string {
  return !!v && /^v?\d+(\.\d+)*([.+-]?[0-9A-Za-z.]+)?$/.test(v) && !/^[0-9a-f]{12,}$/i.test(v);
}

/** Compares dotted versions numerically (2.10 > 2.9); non-numeric parts compare as text. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.+-]/);
  const pb = b.replace(/^v/, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    const d = !isNaN(nx) && !isNaN(ny) ? nx - ny : x.localeCompare(y);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

export interface DependencyUpgrade {
  /** Version that fixes every advisory with a known fix. */
  target: string;
  /** All advisories for this package on this manifest (including `f`). */
  siblings: Finding[];
  /** Advisories the upgrade fixes. */
  covered: Finding[];
}

/**
 * One package line usually has many advisories, each with its own fixed version. Upgrading to the
 * highest of them fixes them all at once, instead of one advisory per click.
 */
export function dependencyUpgrade(f: Finding, all: readonly Finding[]): DependencyUpgrade | null {
  if (fixKind(f) !== "dependency") return null;
  const pkg = normPkg(f.package!);
  const siblings = all.filter(
    (o) => o.category === "dependency" && o.file === f.file && o.package && normPkg(o.package) === pkg && o.installed_version === f.installed_version,
  );
  const target = siblings
    .map((o) => o.fixed_version)
    .filter(isVersion)
    .reduce((best, v) => (compareVersions(v, best) > 0 ? v : best), f.fixed_version!);
  const covered = siblings.filter((o) => isVersion(o.fixed_version) && compareVersions(o.fixed_version, target) <= 0);
  return { target, siblings, covered };
}

/** Removes a surrounding ```lang ... ``` block if the model wrapped the code in one. */
export function stripFences(code: string): string {
  const m = code.trim().match(/^```[\w+-]*\s*\n([\s\S]*?)\n?```$/);
  return m ? m[1] : code;
}

const splitLines = (s: string) => s.replace(/\r\n?/g, "\n").split("\n");

function trimBlankEdges(lines: string[]): string[] {
  let a = 0;
  let b = lines.length;
  while (a < b && !lines[a].trim()) a++;
  while (b > a && !lines[b - 1].trim()) b--;
  return lines.slice(a, b);
}

const indentOf = (line: string) => line.match(/^[ \t]*/)![0];

function minIndent(lines: string[]): string {
  let best: string | null = null;
  for (const l of lines) {
    if (!l.trim()) continue;
    const ind = indentOf(l);
    if (best === null || ind.length < best.length) best = ind;
  }
  return best ?? "";
}

/** Re-indents `fixLines` so their least-indented line lines up with the code being replaced. */
export function reindent(fixLines: string[], targetLines: string[]): string[] {
  const target = minIndent(targetLines);
  const strip = minIndent(fixLines).length;
  return fixLines.map((l) => (l.trim() ? target + l.slice(strip) : ""));
}

/** Finds `needle` (compared trimmed, line by line) in `doc`, closest to `near` (0-based). */
export function findBlock(doc: string[], needle: string[], near: number): number {
  if (!needle.length) return -1;
  const want = needle.map((l) => l.trim());
  const lo = Math.max(0, near - SEARCH_WINDOW);
  const hi = Math.min(doc.length - needle.length, near + SEARCH_WINDOW);
  let best = -1;
  for (let s = lo; s <= hi; s++) {
    let ok = true;
    for (let i = 0; i < want.length && ok; i++) ok = doc[s + i].trim() === want[i];
    if (ok && (best < 0 || Math.abs(s - near) < Math.abs(best - near))) best = s;
  }
  return best;
}

const normPkg = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");

function computeDependencyFix(f: Finding, doc: string[], line0: number, target?: string): FixResult {
  const pkg = normPkg(f.package!);
  const from = f.installed_version!;
  const to = target ?? f.fixed_version!;
  const lineFits = (i: number) => {
    const l = doc[i];
    return l !== undefined && normPkg(l).includes(pkg) && l.includes(from);
  };
  let idx = lineFits(line0) ? line0 : -1;
  for (let d = 1; idx < 0 && d <= SEARCH_WINDOW; d++) {
    if (lineFits(line0 - d)) idx = line0 - d;
    else if (lineFits(line0 + d)) idx = line0 + d;
  }
  if (idx < 0) {
    return { ok: false, reason: `Could not find ${f.package} ${from} in ${f.file} any more. Re-scan, or upgrade it manually to ${to}.` };
  }
  const l = doc[idx];
  const pkgAt = normPkg(l).indexOf(pkg); // same length as the original, so indexes line up
  const at = l.indexOf(from, Math.max(0, pkgAt));
  const pos = at >= 0 ? at : l.indexOf(from);
  return { ok: true, edit: { startLine: idx, endLine: idx, lines: [l.slice(0, pos) + to + l.slice(pos + from.length)] } };
}

/**
 * Works out the edit for a finding's suggested fix against the file's current lines.
 * The vulnerable code must still be present (near the reported line): we never overwrite code
 * that changed since the scan.
 */
export function computeFix(f: Finding, doc: string[], currentLine = f.line, dependencyTarget?: string): FixResult {
  const kind = fixKind(f);
  if (!kind) return { ok: false, reason: "This finding has no fix that can be applied automatically." };
  const line0 = Math.max(0, currentLine - 1);
  if (kind === "dependency") return computeDependencyFix(f, doc, line0, dependencyTarget);

  const vuln = trimBlankEdges(splitLines(f.vulnerable_code));
  const fix = trimBlankEdges(splitLines(stripFences(f.fixed_code)));
  // The snippet may start up to 2 lines above the finding (backend adds context lines).
  const start = findBlock(doc, vuln, line0);
  if (start < 0) {
    return { ok: false, reason: "The code at this location has changed since the scan. Re-scan, or apply the fix manually from the diff." };
  }
  const end = start + vuln.length - 1;
  return { ok: true, edit: { startLine: start, endLine: end, lines: reindent(fix, doc.slice(start, end + 1)) } };
}

/** Returns the whole document with the edit applied (for the diff preview). */
export function applyEdit(doc: string[], edit: FixEdit): string[] {
  return [...doc.slice(0, edit.startLine), ...edit.lines, ...doc.slice(edit.endLine + 1)];
}
