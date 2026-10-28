"use client";

import { useEffect, useState } from "react";
import { ValidationStartError, startValidation, type FixEdit, type FixValidation, type WeaknessChain } from "@/lib/api";
import { FixCode, NewInvestigationButton, ValidationResult, usePolledValidation } from "./FixValidationView";

export { EVIDENCE_LABELS, ValidationBadge } from "./FixValidationView";

// What each kind of fix does, in everyday words
export const PLAIN_FIX: Record<string, string> = {
  sql_injection: "Send the user's input to the database separately from the query, so it can never change the query.",
  command_injection: "Run the command without a shell and pass the input as a single argument, so it can't add extra commands.",
  code_injection: "Only accept plain values (numbers, text, lists) instead of running the input as code.",
  deserialization: "Read the data as JSON instead of pickle, so it can only contain plain data.",
  path_traversal: "Strip folder names from the file name the user sends, so only files in the intended folder can be opened.",
  template_injection: "Keep the page template fixed and pass the user's text in as a value, so it's shown, not executed.",
  xss: "Let the template engine escape the user's text, so it's shown as text instead of running in the browser.",
  ssrf: "Only allow the server to contact an approved list of websites.",
  open_redirect: "Only redirect to pages on your own site.",
};

const CLOSED = ["investigation_passed", "investigation_exhausted"];

export default function ChainFixPanel({
  scanId,
  chain,
  initialValidation,
}: {
  scanId: string;
  chain: WeaknessChain;
  initialValidation: FixValidation | null;
}) {
  const [validation, setValidation] = usePolledValidation(scanId, initialValidation);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState("");
  const [closed, setClosed] = useState(false); // current investigation passed or used its attempts

  // Edits start from what is shown: the final code after a validation, else the suggestion
  const finished = validation && validation.state !== "running";
  const shownFix = (finished && validation?.final_fix) || chain.fix;
  const [drafts, setDrafts] = useState<string[]>(() => shownFix?.edits.map((e) => e.replacement) ?? []);
  useEffect(() => {
    setDrafts(shownFix?.edits.map((e) => e.replacement) ?? []);
    setEditing(false);
  }, [shownFix]);

  const run = async (edits?: FixEdit[], newInvestigation = false) => {
    setError("");
    setClosed(false);
    try {
      setValidation(await startValidation(scanId, chain.id, edits, newInvestigation));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start validation");
      setClosed(err instanceof ValidationStartError && CLOSED.includes(err.code ?? ""));
    }
  };

  const running = validation?.state === "running";
  const edited = (): FixEdit[] => (shownFix?.edits ?? []).map((e, i) => ({ ...e, replacement: drafts[i] ?? e.replacement }));

  return (
    <div className="space-y-4">
      {editing ? (
        <div>
          <h4 className="text-sm font-medium text-slate-300 mb-1">Edit the fix</h4>
          {shownFix?.edits.map((e, i) => (
            <div key={`${e.file}:${e.start_line}`} className="mt-3">
              <p className="text-xs font-mono text-slate-500">
                {e.file}, line {e.start_line}
                {e.end_line !== e.start_line ? `–${e.end_line}` : ""}
              </p>
              <textarea
                value={drafts[i]}
                onChange={(ev) => setDrafts(drafts.map((d, j) => (j === i ? ev.target.value : d)))}
                rows={Math.max(2, drafts[i]?.split("\n").length ?? 2)}
                spellCheck={false}
                aria-label={`New code for ${e.file} line ${e.start_line}`}
                className="mt-1 w-full font-mono text-xs bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-400"
              />
            </div>
          ))}
        </div>
      ) : (
        <FixCode validation={validation} suggestion={chain.fix} explanation={PLAIN_FIX[chain.kind]} language="python" />
      )}
      {!shownFix?.edits.length && (
        <p className="text-xs text-amber-300">
          We can&apos;t rewrite this code automatically. Validating will try to write a fix with AI, or you can review it
          by hand.
        </p>
      )}
      {(chain.fix?.remaining_paths.length ?? 0) > 0 && (
        <p className="text-xs text-amber-300/90">
          Heads-up: the same input also reaches other risky code. Those are listed as separate problems.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => run(editing ? edited() : undefined)}
          disabled={running}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 disabled:cursor-wait"
        >
          {running ? "Validating…" : editing ? "Validate my edited fix" : "Validate fix"}
        </button>
        {(shownFix?.edits.length ?? 0) > 0 && (
          <button
            onClick={() => setEditing(!editing)}
            disabled={running}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
          >
            {editing ? "Cancel editing" : "Edit before validating"}
          </button>
        )}
        <span className="text-[11px] text-slate-500">Runs on a copy of your code. Your repository isn&apos;t changed.</span>
      </div>
      {error && (
        <div className="flex flex-wrap items-center gap-2">
          <p role="alert" className="text-xs text-red-300">
            {error}
          </p>
          {closed && <NewInvestigationButton onClick={() => run(undefined, true)} />}
        </div>
      )}

      {validation && <ValidationResult validation={validation} onNewInvestigation={() => run(undefined, true)} />}
    </div>
  );
}
