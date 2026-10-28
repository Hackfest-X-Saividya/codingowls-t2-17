"use client";

import { useState, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  downloadScanPdf,
  getScanResults,
  getScanSarifUrl,
  type FindingCategory,
  type ScanResultsResponse,
  type Vulnerability,
} from "@/lib/api";
import ProgressTracker from "@/components/ProgressTracker";
import SummaryStats from "@/components/SummaryStats";
import VulnerabilityCard from "@/components/VulnerabilityCard";
import SeverityBadge from "@/components/SeverityBadge";
import FindingsOverview, { type OverviewSelection } from "@/components/FindingsOverview";
import AttackChains from "@/components/AttackChains";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type CategoryFilter = "all" | FindingCategory;

const CATEGORY_TABS: { key: CategoryFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "code", label: "Code" },
  { key: "dependency", label: "Dependencies" },
  { key: "secret", label: "Secrets" },
];

export default function ResultsPage() {
  const params = useParams();
  const scanId = params.scanId as string;

  const [phase, setPhase] = useState<"loading" | "error" | "results">("loading");
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportError, setExportError] = useState("");

  const fetchResults = useCallback(async () => {
    try {
      const data = await getScanResults(scanId);
      setResults(data);
      setPhase("results");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load results");
      setPhase("error");
    }
  }, [scanId]);

  const handleComplete = useCallback(() => {
    fetchResults();
  }, [fetchResults]);

  const handleError = useCallback((msg: string) => {
    setError(msg);
    setPhase("error");
  }, []);

  const filteredVulns = results?.vulnerabilities.filter((v: Vulnerability) => {
    if (categoryFilter !== "all" && (v.category ?? "code") !== categoryFilter) return false;
    if (severityFilter !== "all" && v.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        v.title.toLowerCase().includes(q) ||
        v.file.toLowerCase().includes(q) ||
        v.rule_id.toLowerCase().includes(q) ||
        (v.package ?? "").toLowerCase().includes(q) ||
        v.ai_explanation.toLowerCase().includes(q)
      );
    }
    return true;
  }) ?? [];

  // A click in the overview charts sets the same filters as the controls above the list
  const applyOverviewSelection = ({ category, severity, query }: OverviewSelection) => {
    setCategoryFilter(category ?? "all");
    setSeverityFilter(severity ?? "all");
    setSearchQuery(query ?? "");
    document.getElementById("findings-list")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const categoryCount = (key: CategoryFilter) =>
    key === "all" ? results?.summary.total ?? 0 : results?.summary.by_category?.[key] ?? 0;

  // PDF with every finding, rendered by the backend
  const exportPdfReport = async () => {
    setExportingPdf(true);
    setExportError("");
    try {
      const { blob, filename } = await downloadScanPdf(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : "Failed to generate PDF report");
    } finally {
      setExportingPdf(false);
    }
  };

  if (phase === "loading") {
    return (
      <ProgressTracker
        scanId={scanId}
        onComplete={handleComplete}
        onError={handleError}
      />
    );
  }

  if (phase === "error") {
    return (
      <div className="max-w-2xl mx-auto mt-12 px-4">
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 text-center">
          <svg className="w-12 h-12 text-red-400 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2 className="text-xl font-semibold text-red-300 mb-2">Scan Failed</h2>
          <p className="text-slate-400">{error}</p>
          <a href="/" className="inline-block mt-4 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700 transition-colors">
            Try Again
          </a>
        </div>
      </div>
    );
  }

  if (!results) return null;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold">{results.repo_name}</h1>
          <p className="text-sm text-slate-400 mt-1">
            Scanned {new Date(results.scanned_at).toLocaleString()} &middot;{" "}
            {results.languages?.length ? results.languages.join(", ") : results.language}
          </p>
        </div>
        <div className="flex items-center gap-2 self-start">
          <a
            href="/"
            className="px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-300 hover:bg-slate-800/50 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10 19l-7-7m0 0l7-7m-7 7h18"
              />
            </svg>
            Back to Home
          </a>
          <a
            href="#attack-chains"
            className="px-4 py-2 bg-indigo-600/20 border border-indigo-500/40 rounded-lg text-sm text-indigo-200 hover:bg-indigo-600/30 transition-colors"
          >
            Attack chains ({results.chains?.length ?? 0})
          </a>
          <button
            onClick={exportPdfReport}
            disabled={exportingPdf}
            title="PDF with every finding: summary, index and full details"
            className="px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-300 hover:bg-slate-800/50 transition-colors flex items-center gap-2 disabled:opacity-60 disabled:cursor-wait"
          >
            {exportingPdf ? (
              <span className="w-4 h-4 rounded-full border-2 border-slate-600 border-t-transparent animate-spin" aria-hidden="true" />
            ) : (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            )}
            {exportingPdf ? "Generating PDF…" : "Export Report (PDF)"}
          </button>
          <a
            href={getScanSarifUrl(scanId)}
            download={`scan-${scanId}.sarif`}
            title="SARIF 2.1.0 — upload to GitHub code scanning or other security tools"
            className="px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-300 hover:bg-slate-800/50 transition-colors"
          >
            Export SARIF
          </a>
        </div>
      </div>

      {exportError && (
        <div role="alert" className="mb-6 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-300">
          {exportError}
        </div>
      )}

      {/* Summary */}
      <SummaryStats summary={results.summary} />

      {/* How findings relate: type x severity, and hotspots */}
      <FindingsOverview vulnerabilities={results.vulnerabilities} onSelect={applyOverviewSelection} />

      {/* Coverage warnings (unpinned dependencies, unreachable services, ...) */}
      {results.warnings?.length > 0 && (
        <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
          <p className="text-sm font-medium text-amber-200 mb-1">Coverage notes</p>
          <ul className="list-disc list-inside space-y-0.5">
            {results.warnings.map((w) => (
              <li key={w} className="text-sm text-amber-300">{w}</li>
            ))}
          </ul>
        </div>
      )}

      {/* How findings connect into exploitable chains, with fix validation */}
      <AttackChains
        scanId={scanId}
        chains={results.chains ?? []}
        validations={results.validations ?? []}
        vulnerabilities={results.vulnerabilities}
        chainStats={results.chain_stats ?? null}
        languages={results.languages ?? []}
        repoUrl={results.repo_url}
      />

      {/* Category tabs */}
      <div id="findings-list" className="flex gap-1 mt-8 border-b border-slate-800 overflow-x-auto scroll-mt-4">
        {CATEGORY_TABS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setCategoryFilter(key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
              categoryFilter === key
                ? "border-indigo-400 text-indigo-300"
                : "border-transparent text-slate-400 hover:text-slate-300"
            }`}
          >
            {label} <span className="ml-1 text-xs text-slate-500">{categoryCount(key)}</span>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mt-4 mb-6">
        <div className="flex gap-2 flex-wrap">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                severityFilter === sev
                  ? "bg-indigo-600 text-white"
                  : "bg-slate-800 text-slate-400 hover:text-slate-300"
              }`}
            >
              {sev === "all" ? "All" : <SeverityBadge severity={sev} />}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search vulnerabilities..."
          className="flex-1 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-400"
        />
      </div>

      {/* Vulnerability list */}
      <div className="space-y-3">
        {filteredVulns.length === 0 ? (
          <div className="text-center py-12 text-slate-400">
            {results.vulnerabilities.length === 0
              ? "No vulnerabilities found. The repository looks clean!"
              : "No vulnerabilities match your filters."}
          </div>
        ) : (
          filteredVulns.map((vuln) => (
            <VulnerabilityCard
              key={vuln.id}
              scanId={scanId}
              vulnerability={vuln}
              language={results.language}
              chains={(results.chains ?? []).filter((c) => c.finding_ids.includes(vuln.id))}
              validations={results.validations ?? []}
            />
          ))
        )}
      </div>
    </div>
  );
}
