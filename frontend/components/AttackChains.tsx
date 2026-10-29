"use client";

import { useEffect, useMemo, useState } from "react";
import {
  startScan,
  type ChainEdge,
  type ChainNode,
  type FixValidation,
  type ScanResultsResponse,
  type Vulnerability,
  type WeaknessChain,
} from "@/lib/api";
import SeverityBadge from "./SeverityBadge";
import ChainFixPanel, { EVIDENCE_LABELS, ValidationBadge } from "./ChainFixPanel";

const ROLE_STYLES: Record<ChainNode["role"], string> = {
  direct: "border-red-500/40 bg-red-500/10 text-red-200",
  contributing: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  control: "border-green-500/40 bg-green-500/10 text-green-200",
  context: "border-slate-700 bg-slate-800/60 text-slate-200",
  impact: "border-rose-500/50 bg-rose-500/15 text-rose-200",
};

const KIND_LABELS: Record<string, string> = {
  entry_point: "Entry point",
  untrusted_input: "Untrusted input",
  weakness: "Weakness",
  security_control: "Control",
  condition: "Condition",
  sensitive_operation: "Sensitive operation",
  impact: "Impact",
};

const EXPLOITABILITY_STYLES: Record<WeaknessChain["exploitability"], string> = {
  likely: "bg-red-500/10 text-red-300 border-red-500/30",
  possible: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  mitigated: "bg-green-500/10 text-green-300 border-green-500/30",
};

interface AttackChainsProps {
  scanId: string;
  chains: WeaknessChain[];
  validations: FixValidation[];
  vulnerabilities: Vulnerability[];
  chainStats: ScanResultsResponse["chain_stats"];
  languages: string[];
  repoUrl: string;
}

export default function AttackChains({
  scanId,
  chains,
  validations,
  vulnerabilities,
  chainStats,
  languages,
  repoUrl,
}: AttackChainsProps) {
  const [showAll, setShowAll] = useState(false);
  const findings = useMemo(() => Object.fromEntries(vulnerabilities.map((v) => [v.id, v])), [vulnerabilities]);
  const latest = useMemo(() => {
    const byChain: Record<string, FixValidation> = {};
    for (const v of validations) {
      if (!v.chain_id) continue;
      if (!byChain[v.chain_id] || byChain[v.chain_id].started_at < v.started_at) byChain[v.chain_id] = v;
    }
    return byChain;
  }, [validations]);

  // A chain linked from a finding (#chain-<id>) must be in the visible list to open
  useEffect(() => {
    const reveal = () => {
      const id = window.location.hash.replace("#chain-", "");
      if (chains.findIndex((c) => c.id === id) >= 5) setShowAll(true);
    };
    reveal();
    window.addEventListener("hashchange", reveal);
    return () => window.removeEventListener("hashchange", reveal);
  }, [chains]);

  const visible = showAll ? chains : chains.slice(0, 5);
  const count = (e: WeaknessChain["exploitability"]) => chains.filter((c) => c.exploitability === e).length;
  const verified = Object.values(latest).filter((v) => v.status === "pass").length;

  return (
    <section id="attack-chains" className="mt-8 scroll-mt-4" aria-labelledby="chains-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
        <h2 id="chains-heading" className="text-lg font-semibold">
          Attack chains &amp; fix verification{" "}
          <span className="text-sm font-normal text-slate-500">{chains.length}</span>
        </h2>
        <p className="text-xs text-slate-500">
          Places where several weaknesses combine into a real attack, most urgent first.
        </p>
      </div>

      {chains.length === 0 ? (
        <EmptyChains chainStats={chainStats} languages={languages} repoUrl={repoUrl} />
      ) : (
        <>
          <p className="text-sm text-slate-400 mb-3">
            <span className="text-red-300">{count("likely")} high risk</span>
            {" · "}
            <span className="text-amber-300">{count("possible")} medium risk</span>
            {" · "}
            <span className="text-green-300">{count("mitigated")} low risk</span>
            {" · "}
            <span className={verified ? "text-green-300" : "text-slate-500"}>
              {verified} fix{verified === 1 ? "" : "es"} verified
            </span>
          </p>
          <div className="space-y-3">
            {visible.map((chain, i) => (
              <ChainCard
                key={chain.id}
                scanId={scanId}
                chain={chain}
                findings={findings}
                validation={latest[chain.id] ?? null}
                defaultExpanded={i === 0}
              />
            ))}
          </div>
        </>
      )}
      {chains.length > 5 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-3 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
        >
          {showAll ? "Show top 5" : `Show all ${chains.length} chains`}
        </button>
      )}
    </section>
  );
}

function EmptyChains({
  chainStats,
  languages,
  repoUrl,
}: {
  chainStats: ScanResultsResponse["chain_stats"];
  languages: string[];
  repoUrl: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const rescan = async () => {
    setBusy(true);
    setError("");
    try {
      const { scan_id } = await startScan(repoUrl);
      window.location.assign(`/results/${scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setBusy(false);
    }
  };

  let message: string;
  if (!chainStats) {
    message =
      "This scan was made before attack-chain analysis existed. Re-scan the repository to see how its weaknesses connect and to verify fixes.";
  } else if (chainStats.failed) {
    message = "Attack-chain analysis failed for this scan; findings are shown individually below.";
  } else if (!chainStats.python_files) {
    message =
      `Attack-chain analysis and fix verification currently support Python code. This repository is ` +
      `${languages.join(", ") || "in another language"}, so its findings are shown individually below, and ` +
      `their suggested fixes are unverified.`;
  } else {
    message =
      `No path from untrusted input to a sensitive operation was found in ${chainStats.python_files} Python ` +
      `file(s) (${chainStats.endpoints ?? 0} routes analysed). Findings are shown individually below.`;
  }

  return (
    <div className="bg-slate-900 border border-dashed border-slate-700 rounded-xl p-5">
      <p className="text-sm text-slate-400">{message}</p>
      {!chainStats && (
        <button
          onClick={rescan}
          disabled={busy}
          className="mt-3 px-3 py-1.5 text-xs font-medium rounded-lg bg-indigo-600 text-snow hover:bg-indigo-700 disabled:opacity-60 disabled:cursor-wait"
        >
          {busy ? "Starting…" : "Re-scan now"}
        </button>
      )}
      {error && <p role="alert" className="mt-2 text-xs text-red-300">{error}</p>}
    </div>
  );
}

const RISK_LABELS: Record<WeaknessChain["exploitability"], string> = {
  likely: "High risk",
  possible: "Medium risk",
  mitigated: "Low risk",
};

function ChainCard({
  scanId,
  chain,
  findings,
  validation,
  defaultExpanded,
}: {
  scanId: string;
  chain: WeaknessChain;
  findings: Record<string, Vulnerability>;
  validation: FixValidation | null;
  defaultExpanded: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [showChain, setShowChain] = useState(false);

  // Open when a finding links here (#chain-<id>)
  useEffect(() => {
    const open = () => {
      if (window.location.hash === `#chain-${chain.id}`) {
        setExpanded(true);
        setTimeout(() => document.getElementById(`chain-${chain.id}`)?.scrollIntoView({ block: "start" }), 0);
      }
    };
    open();
    window.addEventListener("hashchange", open);
    return () => window.removeEventListener("hashchange", open);
  }, [chain.id]);

  return (
    <div id={`chain-${chain.id}`} className="bg-slate-900 border border-white/10 rounded-2xl overflow-hidden scroll-mt-4">
      <button onClick={() => setExpanded(!expanded)} className="w-full text-left px-5 py-4 flex items-start gap-4">
        <div className="mt-0.5 flex flex-col items-start gap-1.5">
          <SeverityBadge severity={chain.severity} />
          <span className={`px-2 py-0.5 rounded border text-[11px] font-medium ${EXPLOITABILITY_STYLES[chain.exploitability]}`}>
            {RISK_LABELS[chain.exploitability]}
          </span>
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="font-medium text-slate-100 break-words">{chain.title}</h3>
          <p className="text-sm text-slate-500 mt-0.5">{chain.impact}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {validation?.status && <ValidationBadge status={validation.status} />}
          <svg
            className={`w-5 h-5 text-slate-500 transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="px-5 pb-5 border-t border-slate-800 pt-4 space-y-5">
          <div>
            <h4 className="text-sm font-medium text-slate-300 mb-1">What&apos;s wrong</h4>
            <p className="text-sm text-slate-400 leading-relaxed">{chain.summary || chain.exploitability_reason}</p>
          </div>

          <ChainFixPanel scanId={scanId} chain={chain} initialValidation={validation} />

          <div className="border-t border-slate-800 pt-4">
            <button
              onClick={() => setShowChain(!showChain)}
              aria-expanded={showChain}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 inline-flex items-center gap-1.5"
            >
              <svg
                className={`w-3.5 h-3.5 transition-transform duration-200 ${showChain ? "rotate-90" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              {showChain ? "Hide attack chain" : "Show attack chain"}
            </button>

            {showChain && (
              <div className="mt-4 space-y-5">
                <ChainGraph chain={chain} />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <TextList title="What makes this possible" items={chain.conditions} />
                  <TextList title="Protections found" items={chain.controls} empty="None on these paths" />
                </div>
                {chain.finding_ids.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-slate-300 mb-2">Related findings</h4>
                    <ul className="space-y-1">
                      {chain.finding_ids.map((id) => (
                        <li key={id} className="text-xs text-slate-400">
                          {findings[id] ? `${findings[id].title} (${findings[id].file}, line ${findings[id].line})` : id}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <TextList title="Limits of this analysis" items={chain.uncertainty} muted />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ChainGraph({ chain }: { chain: WeaknessChain }) {
  const [selected, setSelected] = useState<string | null>(null);
  const nodes = useMemo(() => Object.fromEntries(chain.nodes.map((n) => [n.id, n])), [chain.nodes]);
  const edges = useMemo(
    () => Object.fromEntries(chain.edges.map((e) => [`${e.source}>${e.target}`, e])),
    [chain.edges],
  );
  // Edges off the input-to-impact paths: missing auth, auth controls, session keys, dependencies
  const pathEdges = new Set(chain.paths.flatMap((p) => p.slice(1).map((id, i) => `${p[i]}>${id}`)));
  const side = chain.edges.filter((e) => !pathEdges.has(`${e.source}>${e.target}`));
  const active = selected ? edges[selected] : null;

  return (
    <div>
      <h4 className="text-sm font-medium text-slate-300 mb-2">How the attack works</h4>
      <div className="space-y-2">
        {chain.paths.map((path, i) => (
          <div key={i} className="flex flex-wrap items-center gap-1.5 bg-slate-950/40 border border-slate-800 rounded-lg p-2">
            {path.map((id, j) => (
              <span key={id} className="contents">
                {j > 0 && (
                  <EdgeArrow
                    edge={edges[`${path[j - 1]}>${id}`]}
                    selected={selected === `${path[j - 1]}>${id}`}
                    onSelect={() => setSelected(selected === `${path[j - 1]}>${id}` ? null : `${path[j - 1]}>${id}`)}
                  />
                )}
                {nodes[id] && <NodeChip node={nodes[id]} />}
              </span>
            ))}
          </div>
        ))}
      </div>

      {side.length > 0 && (
        <div className="mt-3">
          <p className="text-xs text-slate-500 mb-1.5">Feeding into the chain</p>
          <div className="space-y-1.5">
            {side.map((e) => {
              const key = `${e.source}>${e.target}`;
              return (
                <div key={key} className="flex flex-wrap items-center gap-1.5">
                  {nodes[e.source] && <NodeChip node={nodes[e.source]} />}
                  <EdgeArrow edge={e} selected={selected === key} onSelect={() => setSelected(selected === key ? null : key)} />
                  {nodes[e.target] && <NodeChip node={nodes[e.target]} />}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <p className="mt-2 text-[11px] text-slate-500">
        Select an arrow to see its evidence. Solid: confirmed by evidence. Dashed: hypothesis, needs investigation.
      </p>
      {active && <EdgeEvidence edge={active} nodes={nodes} />}
    </div>
  );
}

function NodeChip({ node }: { node: ChainNode }) {
  return (
    <span
      className={`inline-flex flex-col max-w-[16rem] px-2.5 py-1.5 rounded-md border ${ROLE_STYLES[node.role]}`}
      title={node.detail}
    >
      <span className="text-[10px] uppercase tracking-wide opacity-70">{KIND_LABELS[node.kind] ?? node.kind}</span>
      <span className="text-xs font-medium break-words">{node.label}</span>
      {node.line != null && (
        <span className="text-[10px] font-mono opacity-60">
          {node.file}:{node.line}
        </span>
      )}
    </span>
  );
}

function EdgeArrow({ edge, selected, onSelect }: { edge?: ChainEdge; selected: boolean; onSelect: () => void }) {
  if (!edge) return <span className="text-slate-600 px-1" aria-hidden="true">&rarr;</span>;
  const hypothesis = edge.status === "hypothesis";
  return (
    <button
      onClick={onSelect}
      aria-pressed={selected}
      title={`${edge.relation} (${edge.status}, ${Math.round(edge.confidence * 100)}% confidence)`}
      className={`inline-flex flex-col items-center px-1.5 py-0.5 rounded text-[10px] leading-tight transition-colors ${
        selected ? "bg-indigo-500/20 text-indigo-200" : "text-slate-400 hover:bg-slate-800"
      }`}
    >
      <span className="max-w-[9rem] truncate">{edge.relation}</span>
      <span className={`w-full border-t ${hypothesis ? "border-dashed border-amber-400" : "border-slate-400"} my-0.5`} />
      <span className={hypothesis ? "text-amber-300" : "text-slate-500"}>
        {hypothesis ? "hypothesis" : "confirmed"} · {Math.round(edge.confidence * 100)}% &rarr;
      </span>
    </button>
  );
}

function EdgeEvidence({ edge, nodes }: { edge: ChainEdge; nodes: Record<string, ChainNode> }) {
  return (
    <div className="mt-3 bg-slate-800/50 border border-slate-800 rounded-lg p-3">
      <p className="text-xs text-slate-300 mb-2">
        <span className="font-medium">{nodes[edge.source]?.label}</span>{" "}
        <span className="text-slate-500">{edge.relation}</span>{" "}
        <span className="font-medium">{nodes[edge.target]?.label}</span>
      </p>
      <ul className="space-y-1.5">
        {edge.evidence.map((ev, i) => (
          <li key={i} className="text-xs text-slate-400 flex flex-wrap gap-x-2 gap-y-0.5">
            <span className="px-1.5 rounded bg-slate-900 text-slate-300 text-[10px] uppercase tracking-wide">
              {EVIDENCE_LABELS[ev.kind] ?? ev.kind}
            </span>
            {ev.line != null && <span className="font-mono text-slate-500">{ev.file}:{ev.line}</span>}
            <span>{ev.description}</span>
            {ev.code && <code className="basis-full font-mono text-[11px] text-slate-300 break-all">{ev.code}</code>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function TextList({ title, items, empty, muted }: { title: string; items: string[]; empty?: string; muted?: boolean }) {
  if (!items.length && !empty) return null;
  return (
    <div>
      <h4 className="text-sm font-medium text-slate-300 mb-2">{title}</h4>
      {items.length ? (
        <ul className={`list-disc list-inside space-y-1 text-sm ${muted ? "text-slate-500" : "text-slate-400"}`}>
          {items.map((item) => (
            <li key={item} className="break-words">{item}</li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500">{empty}</p>
      )}
    </div>
  );
}

