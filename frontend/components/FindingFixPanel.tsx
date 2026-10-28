"use client";

import { useState } from "react";
import { startFindingValidation, type FixValidation, type Vulnerability } from "@/lib/api";
import { FixCode, ValidationResult, usePolledValidation } from "./FixValidationView";

const EXPLANATIONS: Record<Vulnerability["category"], string> = {
  code: "Suggested change for the flagged code. Validate it to apply it to a copy of your code and check that the problem is really gone.",
  dependency: "Upgrade the package to a version without this advisory. Validating checks the new version against the vulnerability database.",
  secret: "Load the value from an environment variable instead of the code. The exposed credential must still be rotated with its provider.",
};

export default function FindingFixPanel({
  scanId,
  vuln,
  language,
  initialValidation,
}: {
  scanId: string;
  vuln: Vulnerability;
  language: string;
  initialValidation: FixValidation | null;
}) {
  const [validation, setValidation] = usePolledValidation(scanId, initialValidation);
  const [error, setError] = useState("");
  const running = validation?.state === "running";
  const category = vuln.category ?? "code";

  const run = async () => {
    setError("");
    try {
      setValidation(await startFindingValidation(scanId, vuln.id));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start validation");
    }
  };

  return (
    <div className="space-y-4">
      <FixCode
        validation={validation}
        suggestion={null}
        explanation={EXPLANATIONS[category]}
        language={category === "code" ? language : "text"}
        fallback={
          vuln.vulnerable_code || vuln.fixed_code
            ? { original: vuln.vulnerable_code, replacement: vuln.fixed_code }
            : undefined
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={run}
          disabled={running}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 disabled:cursor-wait"
        >
          {running ? "Validating…" : "Validate fix"}
        </button>
        <span className="text-[11px] text-slate-500">Runs on a copy of your code. Your repository isn&apos;t changed.</span>
      </div>
      {error && <p role="alert" className="text-xs text-red-300">{error}</p>}

      {validation && <ValidationResult validation={validation} />}
    </div>
  );
}
