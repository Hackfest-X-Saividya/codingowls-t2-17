"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { getScanStatus, type ScanStatusResponse } from "@/lib/api";

const STEP_LABELS: Record<string, string> = {
  clone_repo: "Clone repository",
  detect_language: "Detect languages",
  analyze: "Run static code analysis",
  parse_results: "Parse results",
  scan_dependencies: "Check dependencies",
  scan_secrets: "Scan for secrets",
  chain_analysis: "Connect attack chains",
  ai_enhance: "AI enhancement",
};

const STEP_DETAILS: Record<string, string> = {
  clone_repo: "Shallow-cloning target repository (depth=1) for faster startup.",
  detect_language: "Detecting every language in the repo to select the right analysis rules.",
  analyze: "Running static security rules including OWASP-focused checks.",
  parse_results: "Parsing SARIF output into normalized vulnerability findings.",
  scan_dependencies: "Matching pinned package versions against the OSV.dev vulnerability database.",
  scan_secrets: "Looking for hardcoded API keys, tokens, private keys and passwords.",
  chain_analysis: "Tracing untrusted input to sensitive operations and linking the findings on each path.",
  ai_enhance: "Generating attack context and fix guidance in parallel.",
};

const ALL_STEPS = [
  "clone_repo",
  "detect_language",
  "analyze",
  "parse_results",
  "scan_dependencies",
  "scan_secrets",
  "chain_analysis",
  "ai_enhance",
];

interface ProgressTrackerProps {
  scanId: string;
  onComplete: () => void;
  onError: (error: string) => void;
}

const formatDuration = (seconds: number): string => {
  const safe = Math.max(0, Math.floor(seconds));
  const mins = Math.floor(safe / 60);
  const secs = safe % 60;
  return `${mins}:${secs.toString().padStart(2, "0")}`;
};

const formatClock = (timestampMs: number): string =>
  new Date(timestampMs).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

export default function ProgressTracker({ scanId, onComplete, onError }: ProgressTrackerProps) {
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [scanStartedAt, setScanStartedAt] = useState<number | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [stepStartedAt, setStepStartedAt] = useState<Record<string, number>>({});
  const [stepCompletedAt, setStepCompletedAt] = useState<Record<string, number>>({});
  const [now, setNow] = useState(Date.now());

  const pollStatus = useCallback(async () => {
    try {
      const data = await getScanStatus(scanId);
      const fetchedAt = Date.now();

      setStatus(data);
      setLastUpdatedAt(fetchedAt);
      setScanStartedAt((prev) => prev ?? fetchedAt);

      if (data.status === "complete") {
        onComplete();
        return false; // stop polling
      }
      if (data.status === "failed") {
        onError(data.error || "Scan failed");
        return false;
      }
      return true; // continue polling
    } catch {
      return true; // retry on network error
    }
  }, [scanId, onComplete, onError]);

  useEffect(() => {
    let timer: NodeJS.Timeout;

    const poll = async () => {
      const shouldContinue = await pollStatus();
      if (shouldContinue) {
        timer = setTimeout(poll, 2000);
      }
    };

    poll();
    return () => clearTimeout(timer);
  }, [pollStatus]);

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const progress = status?.progress ?? 0;
  const completedSteps = useMemo(() => status?.steps_completed ?? [], [status?.steps_completed]);
  const currentStepKey = useMemo(() => {
    if (!status) return null;

    const explicitKey = ALL_STEPS.find(
      (step) => step === status.current_step || STEP_LABELS[step] === status.current_step
    );
    if (explicitKey && !completedSteps.includes(explicitKey)) {
      return explicitKey;
    }

    const remainingKey = status.steps_remaining?.find((step) => ALL_STEPS.includes(step));
    if (remainingKey) {
      return remainingKey;
    }

    return ALL_STEPS.find((step) => !completedSteps.includes(step)) ?? null;
  }, [status, completedSteps]);

  useEffect(() => {
    if (!status) return;

    const observedAt = Date.now();

    setStepCompletedAt((prev) => {
      const next = { ...prev };
      for (const step of completedSteps) {
        if (!next[step]) {
          next[step] = observedAt;
        }
      }
      return next;
    });

    setStepStartedAt((prev) => {
      const next = { ...prev };

      for (const step of completedSteps) {
        if (!next[step]) {
          next[step] = observedAt;
        }
      }

      if (currentStepKey && !next[currentStepKey]) {
        next[currentStepKey] = observedAt;
      }

      return next;
    });
  }, [status, completedSteps, currentStepKey]);

  const elapsedSeconds = scanStartedAt ? Math.floor((now - scanStartedAt) / 1000) : 0;
  const etaSeconds =
    progress > 0 && progress < 100
      ? Math.max(0, Math.round(elapsedSeconds / (progress / 100) - elapsedSeconds))
      : null;
  const activeStepSeconds =
    currentStepKey && stepStartedAt[currentStepKey]
      ? Math.floor((now - stepStartedAt[currentStepKey]) / 1000)
      : 0;

  return (
    <div className="max-w-3xl mx-auto mt-12 px-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-100">Scanning Repository</h2>
          <span className="text-sm text-slate-400">{progress}%</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <div className="rounded-lg bg-slate-800/50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Elapsed</p>
            <p className="text-lg font-semibold text-slate-100">{formatDuration(elapsedSeconds)}</p>
          </div>
          <div className="rounded-lg bg-slate-800/50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">ETA</p>
            <p className="text-lg font-semibold text-slate-100">
              {etaSeconds === null ? "--:--" : formatDuration(etaSeconds)}
            </p>
          </div>
          <div className="rounded-lg bg-slate-800/50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Completed</p>
            <p className="text-lg font-semibold text-slate-100">
              {completedSteps.length}/{ALL_STEPS.length}
            </p>
          </div>
          <div className="rounded-lg bg-slate-800/50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Current Step</p>
            <p className="text-sm font-semibold text-slate-100">
              {currentStepKey ? STEP_LABELS[currentStepKey] : "Waiting"}
            </p>
          </div>
        </div>

        <div className="w-full bg-slate-700 rounded-full h-2 mb-6 overflow-hidden">
          <div
            className="h-full bg-indigo-600 rounded-full transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="space-y-3">
          {ALL_STEPS.map((step) => {
            const isCompleted = completedSteps.includes(step);
            const isCurrent = !isCompleted && currentStepKey === step;
            const stepRuntime =
              isCurrent && stepStartedAt[step] ? Math.floor((now - stepStartedAt[step]) / 1000) : 0;

            return (
              <div
                key={step}
                className={`rounded-lg border p-3 transition-colors ${
                  isCurrent
                    ? "border-slate-700 bg-slate-800/50"
                    : isCompleted
                    ? "border-slate-800 bg-slate-900"
                    : "border-slate-800 bg-slate-900"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="w-6 h-6 flex items-center justify-center shrink-0">
                    {isCompleted ? (
                      <svg className="w-5 h-5 text-slate-100" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : isCurrent ? (
                      <div className="w-4 h-4 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border-2 border-slate-700" />
                    )}
                  </div>
                  <span
                    className={`text-sm ${
                      isCompleted
                        ? "text-slate-100"
                        : isCurrent
                        ? "text-slate-100 font-medium"
                        : "text-slate-500"
                    }`}
                  >
                    {STEP_LABELS[step]}
                  </span>
                  {isCompleted && stepCompletedAt[step] && (
                    <span className="text-xs text-slate-400 ml-auto">
                      done {formatClock(stepCompletedAt[step])}
                    </span>
                  )}
                  {isCurrent && (
                    <span className="text-xs text-slate-400 ml-auto">
                      active {formatDuration(stepRuntime)}
                    </span>
                  )}
                </div>

                {(isCurrent || isCompleted) && (
                  <p className="mt-2 text-xs text-slate-400">{STEP_DETAILS[step]}</p>
                )}
              </div>
            );
          })}
        </div>

        <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
          <span>
            Active stage duration:{" "}
            <span className="font-medium text-slate-300">{formatDuration(activeStepSeconds)}</span>
          </span>
          <span>
            Last update:{" "}
            <span className="font-medium text-slate-300">
              {lastUpdatedAt ? formatClock(lastUpdatedAt) : "--:--:--"}
            </span>
          </span>
        </div>

        {status?.status === "failed" && status.error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
            <p className="text-sm text-red-400">{status.error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
