/** One text change, as VS Code reports it (all 0-based). */
export interface LineChange {
  startLine: number;
  endLine: number;
  endCharacter: number;
  /** Number of line breaks in the inserted text. */
  insertedLineBreaks: number;
}

export type ShiftResult = { kind: "unchanged" } | { kind: "shifted"; line: number; endLine: number } | { kind: "overlap" };

/**
 * Keeps a finding's 1-based [line, endLine] pointing at the same code while the user edits.
 * Edits entirely above the finding shift it; edits touching its lines mark it as overlapping (stale).
 */
export function shiftForChange(line: number, endLine: number, c: LineChange): ShiftResult {
  const start0 = line - 1;
  const end0 = endLine - 1;
  if (c.startLine > end0) return { kind: "unchanged" };
  // Ends before the finding's first line (or exactly at its column 0, e.g. Enter pressed above it).
  if (c.endLine < start0 || (c.endLine === start0 && c.endCharacter === 0)) {
    const delta = c.insertedLineBreaks - (c.endLine - c.startLine);
    return delta === 0 ? { kind: "unchanged" } : { kind: "shifted", line: line + delta, endLine: endLine + delta };
  }
  return { kind: "overlap" };
}
