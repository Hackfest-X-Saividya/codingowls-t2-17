"use client";

import { useEffect, useState } from "react";
import {
  getInvestigation,
  getValidation,
  type AttemptRecord,
  type AttemptStatus,
  type ChainFix,
  type FixValidation,
  type Investigation,
  type ValidationAttempt,
} from "@/lib/api";
import CodeDiff from "./CodeDiff";

export const EVIDENCE_LABELS: Record<string, string> = {
  static_dataflow: "Data flow",
  scanner_finding: "Scanner",
  code_pattern: "Code",
  inferred: "Inferred",
  test_observation: "Test",
  manual: "Manual",
};

const STATUS_STYLES: Record<string, string> = {
  pass: "bg-green-500/10 text-green-300 border-green-500/30",
  fail: "bg-red-500/10 text-red-300 border-red-500/30",
  new_vulnerability: "bg-violet-500/10 text-violet-300 border-violet-500/30",
  inconclusive: "bg-amber-500/10 text-amber-300 border-amber-500/30",
};

const STATUS_LABELS: Record<string, string> = {
  pass: "Verified",
  fail: "Not safe yet",
  new_vulnerability: "New problem",
  inconclusive: "Needs review",
};

export function ValidationBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded border text-[11px] font-medium uppercase tracking-wide ${STATUS_STYLES[status] ?? ""}`}>
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}

const RESULT_STYLES: Record<AttemptStatus, string> = {
  RUNNING: "bg-indigo-500/10 text-indigo-300 border-indigo-500/30",
  PASSED: "bg-green-500/10 text-green-300 border-green-500/30",
  FAILED: "bg-red-500/10 text-red-300 border-red-500/30",
  INCONCLUSIVE: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  ERROR: "bg-slate-500/10 text-slate-300 border-slate-500/40",
  SKIPPED: "bg-slate-800/60 text-slate-400 border-slate-700 border-dashed",
};

/** RUNNING / PASSED / FAILED / INCONCLUSIVE / ERROR / SKIPPED, for persisted attempts and runs. */
export function ResultBadge({ status }: { status: AttemptStatus }) {
  return (
    <span className={`px-2 py-0.5 rounded border text-[11px] font-mono font-medium ${RESULT_STYLES[status] ?? ""}`}>
      {status}
    </span>
  );
}

const SCOPE_NOTE =
  "A pass means these checks found no remaining problem for this finding. It is not proof that the whole application is secure.";

// Plain wording for each check: [when it passes, when it fails]
const CHECKS: Record<string, [string, string]> = {
  apply_patch: ["The fix fits the code", "The code has changed, so the fix no longer fits"],
  syntax: ["The changed code is valid", "The changed code has a syntax error"],
  reproduce_original: ["The problem is gone", "The problem is still there"],
  alternative_paths: ["No other way to cause the same problem", "There is still another way to cause the same problem"],
  regression_static: ["Nothing else in the code broke", "The change breaks something else in the code"],
  scanner_recheck: ["The security scanner agrees", "The security scanner still flags this code"],
  project_tests: ["Your project's tests still pass", "Your project's tests fail after the change"],
};

/** One plain sentence for why an attempt ended the way it did. */
function attemptReason(a: ValidationAttempt): string {
  if (a.record_status === "ERROR") {
    const c = a.checks.find((c) => c.infrastructure && (c.status === "error" || c.status === "skipped"));
    return `A check couldn't run (${c?.detail || "infrastructure problem"}), so nothing is known about this fix.`;
  }
  if (a.status === "pass") return "Passed every check.";
  if (a.status === "new_vulnerability") return "Fixed the problem, but added a new one.";
  const failed = a.checks.find((c) => c.status === "failed");
  if (failed) return `${CHECKS[failed.name]?.[1] ?? failed.detail}.`;
  const errored = a.checks.find((c) => c.status === "error");
  if (errored?.name === "apply_patch") return "The fix no longer fits the code.";
  if (errored) return "A check couldn't run, so this attempt couldn't be confirmed.";
  return a.summary;
}

function verdict(v: FixValidation): { title: string; text: string; tone: string } {
  const last = v.attempts[v.attempts.length - 1];
  if (v.state === "running") {
    const n = (v.first_attempt ?? 1) + v.attempts.length;
    return {
      title: `Attempt ${n}: ${v.attempts.length ? "improving the fix…" : "checking the fix…"}`,
      text: v.attempts.length
        ? "The last attempt wasn't fully safe, so the code is being corrected and checked again."
        : "Applying the fix to a copy of your code and checking it. This usually takes under a minute.",
      tone: "text-slate-200",
    };
  }
  if (v.state === "failed")
    return {
      title: "The check couldn't run",
      text: `${v.message} This is a problem on our side, not a verdict on the fix. Every attempt so far is kept.`,
      tone: "text-slate-300",
    };
  if (v.result === "ERROR")
    return {
      title: "A check couldn't run",
      text: `${last ? attemptReason(last) : v.message} Try again later; this attempt is kept in the history.`,
      tone: "text-slate-300",
    };
  if (v.result === "SKIPPED")
    return { title: "Already validated", text: v.message, tone: "text-amber-300" };
  switch (v.status) {
    case "pass":
      return {
        title: "Fix verified",
        text:
          v.attempts.length > 1
            ? `Earlier attempts weren't fully safe, so the fix was corrected. The final code below passed every check. ${SCOPE_NOTE}`
            : `The problem is gone and nothing else broke. You can apply the code below to your project. ${SCOPE_NOTE}`,
        tone: "text-green-300",
      };
    case "fail":
      return {
        title: "This fix isn't safe yet",
        text: `${last ? attemptReason(last) : ""} The best version so far is shown below; review it before using it.`,
        tone: "text-red-300",
      };
    case "new_vulnerability":
      return {
        title: "The fix works, but adds a new problem",
        text: "It removes this problem but creates a new risk. Review the code below before using it.",
        tone: "text-violet-300",
      };
    default: {
      const checks = last?.checks ?? [];
      let text = "We couldn't confirm this fix automatically. Please check it by hand.";
      if (checks.some((c) => c.name === "apply_patch" && c.status === "error"))
        text = "The code has changed since the scan. Re-scan the repository and try again.";
      else if (checks.some((c) => c.name === "scanner_recheck" && c.status === "failed"))
        text = "Our analysis says the problem is fixed, but the security scanner still flags this code. Please check it by hand.";
      else if (checks.some((c) => c.status === "error"))
        text = "A check couldn't run (for example the scanner or the vulnerability database was unreachable). Try again later.";
      else if (v.stop_reason === "no_fix")
        text = "We couldn't write a fix for this code automatically. Fix it by hand using the explanation above.";
      else if (v.stop_reason === "not_reproducible")
        text = "This problem no longer shows up in the code. Re-scan to refresh the results.";
      return { title: "Needs your review", text, tone: "text-amber-300" };
    }
  }
}

/** Polls a running validation every 2 seconds. */
export function usePolledValidation(scanId: string, initial: FixValidation | null) {
  const [validation, setValidation] = useState<FixValidation | null>(initial);
  useEffect(() => {
    if (!validation || validation.state !== "running") return;
    const timer = setTimeout(async () => {
      try {
        setValidation(await getValidation(scanId, validation.id));
      } catch {
        setValidation({ ...validation }); // transient: try again on the next tick
      }
    }, 2000);
    return () => clearTimeout(timer);
  }, [scanId, validation]);
  return [validation, setValidation] as const;
}

/** The code to show: the final code once validated, otherwise the suggestion. */
export function FixCode({
  validation,
  suggestion,
  explanation,
  language,
  fallback,
}: {
  validation: FixValidation | null;
  suggestion: ChainFix | null;
  explanation?: string;
  language: string;
  fallback?: { original: string; replacement: string };
}) {
  const finished = validation && validation.state !== "running";
  const final = finished ? validation?.final_fix : null;
  const passed = finished && validation?.status === "pass";
  const fix = final ?? suggestion;
  const heading = !final ? "Suggested fix" : passed ? "Verified fix" : "Best fix so far — not verified";

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <h4 className={`text-sm font-medium ${passed ? "text-green-300" : "text-slate-300"}`}>{heading}</h4>
        {passed && <ValidationBadge status="pass" />}
      </div>
      {explanation && <p className="text-sm text-slate-400">{explanation}</p>}
      {fix?.edits.length ? (
        fix.edits.map((e) => (
          <div key={`${e.file}:${e.start_line}`} className="mt-3">
            <p className="text-xs font-mono text-slate-500">
              {e.file}, line {e.start_line}
              {e.end_line !== e.start_line ? `–${e.end_line}` : ""}
            </p>
            <CodeDiff vulnerableCode={e.original} fixedCode={e.replacement} language={language} />
          </div>
        ))
      ) : fallback ? (
        <CodeDiff vulnerableCode={fallback.original} fixedCode={fallback.replacement} language={language} />
      ) : null}
    </div>
  );
}

export function ValidationResult({
  validation,
  onNewInvestigation,
}: {
  validation: FixValidation;
  onNewInvestigation?: () => void;
}) {
  const { title, text, tone } = verdict(validation);
  const last = validation.attempts[validation.attempts.length - 1];
  const checks = (last?.checks ?? []).filter((c) => c.status === "passed" || c.status === "failed");

  return (
    <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-3 space-y-3" aria-live="polite">
      <div className="flex items-start gap-2">
        {validation.state === "running" && (
          <span className="mt-1 w-3 h-3 shrink-0 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" aria-hidden="true" />
        )}
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className={`text-sm font-medium ${tone}`}>{title}</p>
            {validation.result && <ResultBadge status={validation.result} />}
          </div>
          <p className="text-sm text-slate-400">{text}</p>
        </div>
      </div>

      {validation.state !== "running" && checks.length > 0 && (
        <ul className="space-y-1">
          {checks.map((c) => (
            <li key={c.name} className="text-sm">
              <span className={`font-mono mr-2 ${c.status === "passed" ? "text-green-400" : "text-red-400"}`}>
                {c.status === "passed" ? "✓" : "✗"}
              </span>
              <span className="text-slate-300">{CHECKS[c.name]?.[c.status === "passed" ? 0 : 1] ?? c.name}</span>
            </li>
          ))}
        </ul>
      )}

      {validation.attempts.length > 0 && (
        <div>
          <p className="text-xs font-medium text-slate-400 mb-1.5">This run</p>
          <ol className="space-y-1.5">
            {validation.attempts.map((a) => (
              <AttemptRow key={a.attempt} attempt={a} />
            ))}
          </ol>
        </div>
      )}

      {validation.investigation_id && (
        <AttemptHistory validation={validation} onNewInvestigation={onNewInvestigation} />
      )}
    </div>
  );
}

function AttemptRow({ attempt: a }: { attempt: ValidationAttempt }) {
  return (
    <li className="border border-slate-800 rounded-md px-2.5 py-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-medium text-slate-200">Attempt {a.attempt}</span>
        {a.record_status ? <ResultBadge status={a.record_status} /> : <ValidationBadge status={a.status} />}
        <span className="text-slate-400">{attemptReason(a)}</span>
      </div>
      <p className="mt-1 text-xs text-slate-500">
        {a.fix.strategy}
        {a.code_hash && <span className="ml-2 font-mono text-slate-600" title={a.code_hash}>code {a.code_hash.slice(0, 10)}</span>}
      </p>
      <details className="mt-1">
        <summary className="text-[11px] text-slate-400 cursor-pointer">View code change</summary>
        {a.diff ? (
          <pre className="mt-1 text-[11px] font-mono bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-slate-300">
            {a.diff}
          </pre>
        ) : (
          <p className="mt-1 text-[11px] text-slate-500">No change was applied.</p>
        )}
        <div className="mt-2 space-y-1 text-[11px] text-slate-500">
          {a.checks.map((c) => (
            <p key={c.name}>
              {c.name} ({c.status}): {c.detail}
              {c.evidence.slice(0, 5).map((ev, i) => (
                <span key={i} className="block ml-3 break-words">
                  [{EVIDENCE_LABELS[ev.kind] ?? ev.kind}] {ev.line != null && `${ev.file}:${ev.line} `}
                  {ev.description}
                </span>
              ))}
            </p>
          ))}
        </div>
      </details>
    </li>
  );
}

/** Every persisted attempt for this problem, across Validate Fix runs. Refreshes as the run progresses. */
function AttemptHistory({
  validation: v,
  onNewInvestigation,
}: {
  validation: FixValidation;
  onNewInvestigation?: () => void;
}) {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [error, setError] = useState("");
  const done = v.attempts.length;

  useEffect(() => {
    if (!v.investigation_id) return;
    let cancelled = false;
    getInvestigation(v.scan_id, v.investigation_id)
      .then((inv) => !cancelled && (setInvestigation(inv), setError("")))
      .catch((e: unknown) => !cancelled && setError(e instanceof Error ? e.message : "Failed to load attempt history"));
    return () => {
      cancelled = true;
    };
  }, [v.scan_id, v.investigation_id, v.state, done, v.message]);

  if (error) return <p className="text-[11px] text-slate-500">{error}</p>;
  if (!investigation || investigation.attempts.length === 0) return null;
  const used = investigation.attempts.length;
  const closed = v.state !== "running" && (investigation.status === "exhausted" || investigation.status === "passed");

  return (
    <div>
      <p className="text-xs font-medium text-slate-400 mb-1.5">
        Attempt history{" "}
        <span className="font-normal text-slate-500">
          ({used} of {investigation.max_attempts} attempts used{investigation.status === "passed" ? ", passed" : ""})
        </span>
      </p>
      <ol className="space-y-1" aria-label="Attempt history">
        {investigation.attempts.map((r) => (
          <HistoryRow key={r.attempt_id} record={r} />
        ))}
      </ol>
      {closed && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <p className="text-[11px] text-amber-300/90">
            {investigation.status === "passed"
              ? "This fix passed validation. To validate this problem again, start a new investigation."
              : `All ${investigation.max_attempts} attempts for this problem are used. Review the history above before trying again.`}
          </p>
          {onNewInvestigation && <NewInvestigationButton onClick={onNewInvestigation} />}
        </div>
      )}
    </div>
  );
}

/** What a persisted attempt's status means, in one line. */
function recordReason(r: AttemptRecord): string {
  switch (r.status) {
    case "PASSED":
      return "Passed these checks (not proof that the whole application is secure).";
    case "RUNNING":
      return `Running (${r.phase ?? "starting"})…`;
    case "ERROR":
      return `Couldn't be checked, so this says nothing about the fix: ${r.failure_reason ?? "unknown error"}`;
    case "SKIPPED":
      return `Not validated again: ${r.failure_reason ?? "same code as an earlier attempt"}`;
    default:
      return r.failure_reason ?? "";
  }
}

function HistoryRow({ record: r }: { record: AttemptRecord }) {
  const hasDetails = r.diff || r.patch.length > 0 || r.checks.length > 0;
  return (
    <li className="text-xs border-l-2 border-slate-800 pl-2" data-attempt={r.attempt_number} data-status={r.status}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-slate-300">#{r.attempt_number}</span>
        <ResultBadge status={r.status} />
        <span className="text-slate-500">{r.strategy || (r.status === "RUNNING" ? "generating a fix" : "no fix")}</span>
        {r.strategy_id && <span className="font-mono text-[11px] text-slate-500">[{r.strategy_id}]</span>}
        {r.code_hash && (
          <span className="font-mono text-[11px] text-slate-600" title={`SHA-256 of the validated code: ${r.code_hash}`}>
            {r.code_hash.slice(0, 10)}
          </span>
        )}
      </div>
      <p className="text-slate-500 break-words">{recordReason(r)}</p>
      {r.selection_note && <p className="text-[11px] text-indigo-300/80 break-words">History: {r.selection_note}</p>}
      {hasDetails && (
        <details className="mt-0.5">
          <summary className="text-[11px] text-slate-400 cursor-pointer">Patch and check results</summary>
          {r.diff ? (
            <pre className="mt-1 text-[11px] font-mono bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-slate-300">
              {r.diff}
            </pre>
          ) : (
            r.patch.map((e) => (
              <pre
                key={`${e.file}:${e.start_line}`}
                className="mt-1 text-[11px] font-mono bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-slate-300"
              >
                {`${e.file}:${e.start_line}-${e.end_line}\n${e.replacement}`}
              </pre>
            ))
          )}
          {r.checks.map((c) => (
            <p key={c.name} className="text-[11px] text-slate-500">
              {c.name} ({c.status}
              {c.infrastructure ? ", infrastructure" : ""}): {c.detail}
            </p>
          ))}
        </details>
      )}
    </li>
  );
}

export function NewInvestigationButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-2.5 py-1 text-[11px] font-medium rounded-md bg-slate-800 text-slate-300 hover:bg-slate-700"
    >
      Start a new investigation
    </button>
  );
}
