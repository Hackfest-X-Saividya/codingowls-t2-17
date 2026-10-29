"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { FindingCategory, Vulnerability } from "@/lib/api";
import { useTheme, type Theme } from "@/lib/theme";

/*
 * "How findings relate", drawn like a neural network:
 *
 *   input layer   hidden layer          output layer
 *   finding type  file / package        severity
 *      (o) ─────── (o) app/app.py ───── (o) Critical
 *      (o) ─────── (o) PyYAML ───────── (o) High ...
 *
 * Edge thickness = number of findings on that connection. Hovering a node
 * highlights only the findings that actually pass through it (computed from
 * type x location x severity triples, so the highlight is exact).
 */

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof SEVERITIES)[number];


const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const TYPES: { key: FindingCategory; label: string }[] = [
  { key: "code", label: "Code" },
  { key: "dependency", label: "Dependencies" },
  { key: "secret", label: "Secrets" },
];

// Severity is ordered, so it gets one ordinal ramp: the most severe step has the most contrast
// with the panel (lightest on dark, darkest on light). Both validated with the dataviz validator
// (--ordinal; dark on #151515, light on #ffffff): all checks pass.
// The rest is chart chrome (text tokens / neutrals; colour only ever encodes severity).
interface ChartPalette {
  severity: Record<Severity, string>;
  ink: string;
  ink2: string;
  muted: string;
  node: string;
  edge: string;
  surface: string;
}

const PALETTES: Record<Theme, ChartPalette> = {
  dark: {
    severity: { critical: "#e9dcfb", high: "#bf94f2", medium: "#9a5ce6", low: "#7a35d4" },
    ink: "#f5f5f5",
    ink2: "#d4d4d4",
    muted: "#a3a3a3",
    node: "#737373",
    edge: "#4a4a4a",
    surface: "#151515",
  },
  light: {
    severity: { critical: "#350e63", high: "#5616a3", medium: "#7f33d6", low: "#a874ea" },
    ink: "#17171a",
    ink2: "#3a3a40",
    muted: "#6b6b72",
    node: "#8a8a91",
    edge: "#c2c2c7",
    surface: "#ffffff",
  },
};

const MAX_HIDDEN = 8;
const OTHER = "__other__";
const MIN_WIDTH = 640;
const ROW = 52;
const PAD_Y = 56;

type Counts = Record<Severity, number>;
type Layer = "type" | "loc" | "sev";

interface Triple {
  type: FindingCategory;
  loc: string;
  sev: Severity;
  n: number;
}

interface LocInfo {
  key: string;
  label: string;
  detail: string;
  query: string;
  counts: Counts;
  total: number;
}

interface NodeRef {
  layer: Layer;
  id: string;
}

export interface OverviewSelection {
  category?: FindingCategory;
  severity?: Severity;
  query?: string;
}

interface Tooltip {
  x: number;
  y: number;
  title: string;
  subtitle?: string;
  rows: { label: string; value: number; swatch?: string }[];
  total: number;
}

const emptyCounts = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

function asSeverity(s: string): Severity {
  return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "low";
}

/** File paths keep their tail (the file name); other labels keep their head. */
function truncate(text: string, max: number, keepTail: boolean): string {
  if (text.length <= max) return text;
  return keepTail ? `…${text.slice(-(max - 1))}` : `${text.slice(0, max - 1)}…`;
}

/** Where a finding "lives": the package for dependencies, otherwise the file. */
function locationOf(v: Vulnerability): Omit<LocInfo, "counts" | "total"> {
  if (v.category === "dependency" && v.package) {
    return { key: `pkg:${v.package}`, label: v.package, detail: `package in ${v.file}`, query: v.package };
  }
  return {
    key: `file:${v.file}`,
    label: v.file,
    detail: v.category === "secret" ? "file with secrets" : "source file",
    query: v.file,
  };
}

function edgePath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = (x2 - x1) / 2;
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
}

function SeverityLegend() {
  const { severity: SEVERITY_FILL, edge: NEUTRAL_EDGE } = PALETTES[useTheme()];
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1" aria-label="Severity legend">
      {SEVERITIES.map((s) => (
        <li key={s} className="flex items-center gap-1.5 text-xs text-slate-400">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_FILL[s] }} aria-hidden="true" />
          {SEVERITY_LABEL[s]}
        </li>
      ))}
      <li className="flex items-center gap-1.5 text-xs text-slate-400">
        <span className="inline-block w-5 h-[3px] rounded" style={{ background: NEUTRAL_EDGE }} aria-hidden="true" />
        thicker = more findings
      </li>
    </ul>
  );
}

function TableView({ locations, triples }: { locations: LocInfo[]; triples: Triple[] }) {
  const byType = TYPES.map(({ key, label }) => {
    const counts = emptyCounts();
    for (const t of triples) if (t.type === key) counts[t.sev] += t.n;
    return { key, label, counts, total: SEVERITIES.reduce((n, s) => n + counts[s], 0) };
  });
  const rows = [
    ...byType.map((r) => ({ ...r, group: "Type" })),
    ...locations.map((l) => ({ key: l.key, label: l.label, counts: l.counts, total: l.total, group: "Location" })),
  ];
  return (
    <details className="mt-3">
      <summary className="text-xs text-slate-400 cursor-pointer hover:text-slate-300 select-none">View as table</summary>
      <div className="mt-2 overflow-x-auto">
        <table className="w-full text-xs tabular-nums">
          <caption className="sr-only">Findings by type and by location, split by severity</caption>
          <thead>
            <tr className="text-slate-400 border-b border-slate-800">
              <th scope="col" className="text-left font-medium py-1 pr-2">Group</th>
              <th scope="col" className="text-left font-medium py-1 pr-2">Name</th>
              {SEVERITIES.map((s) => (
                <th key={s} scope="col" className="text-right font-medium py-1 px-2">{SEVERITY_LABEL[s]}</th>
              ))}
              <th scope="col" className="text-right font-medium py-1 pl-2">Total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.group}-${r.key}`} className="border-b border-slate-800 text-slate-300">
                <td className="py-1 pr-2 text-slate-400">{r.group}</td>
                <th scope="row" className="text-left font-normal py-1 pr-2 max-w-[18rem] truncate" title={r.label}>
                  {r.label}
                </th>
                {SEVERITIES.map((s) => (
                  <td key={s} className="text-right py-1 px-2">{r.counts[s]}</td>
                ))}
                <td className="text-right py-1 pl-2 font-medium text-slate-100">{r.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export default function FindingsOverview({
  vulnerabilities,
  onSelect,
}: {
  vulnerabilities: Vulnerability[];
  onSelect: (selection: OverviewSelection) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const plotRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(960);
  const [active, setActive] = useState<NodeRef | null>(null);
  const [tooltip, setTooltip] = useState<Tooltip | null>(null);
  const {
    severity: SEVERITY_FILL,
    ink: INK,
    ink2: INK_2,
    muted: MUTED,
    node: NEUTRAL_NODE,
    edge: NEUTRAL_EDGE,
    surface: SURFACE,
  } = PALETTES[useTheme()];

  // Draw in real pixels (viewBox = rendered width) so text stays at its true size
  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(entry.contentRect.width, MIN_WIDTH)));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const model = useMemo(() => {
    const locMap = new Map<string, LocInfo>();
    const tripleMap = new Map<string, Triple>();

    for (const v of vulnerabilities) {
      const sev = asSeverity(v.severity);
      const type = v.category ?? "code";
      const loc = locationOf(v);
      const info = locMap.get(loc.key) ?? { ...loc, counts: emptyCounts(), total: 0 };
      info.counts[sev] += 1;
      info.total += 1;
      locMap.set(loc.key, info);
      const k = `${type}|${loc.key}|${sev}`;
      const t = tripleMap.get(k) ?? { type, loc: loc.key, sev, n: 0 };
      t.n += 1;
      tripleMap.set(k, t);
    }

    // Hidden layer: the most severe locations; everything else folds into "Other"
    const ranked = Array.from(locMap.values()).sort(
      (a, b) => b.counts.critical - a.counts.critical || b.counts.high - a.counts.high || b.total - a.total,
    );
    const shown = ranked.slice(0, ranked.length > MAX_HIDDEN + 1 ? MAX_HIDDEN : ranked.length);
    const shownKeys = new Set(shown.map((l) => l.key));
    const rest = ranked.filter((l) => !shownKeys.has(l.key));
    const hidden: LocInfo[] = [...shown];
    if (rest.length) {
      const counts = emptyCounts();
      for (const l of rest) for (const s of SEVERITIES) counts[s] += l.counts[s];
      hidden.push({
        key: OTHER,
        label: `Other (${rest.length})`,
        detail: `${rest.length} more files and packages`,
        query: "",
        counts,
        total: rest.reduce((n, l) => n + l.total, 0),
      });
    }

    const triples: Triple[] = [];
    const folded = new Map<string, Triple>();
    for (const t of tripleMap.values()) {
      const loc = shownKeys.has(t.loc) ? t.loc : OTHER;
      const k = `${t.type}|${loc}|${t.sev}`;
      const f = folded.get(k) ?? { ...t, loc, n: 0 };
      f.n += t.n;
      folded.set(k, f);
    }
    triples.push(...folded.values());

    return { hidden, triples, ranked };
  }, [vulnerabilities]);

  if (vulnerabilities.length === 0) return null;

  const { hidden, triples } = model;
  const types = TYPES.filter(({ key }) => triples.some((t) => t.type === key));

  // ---- layout (pixels)
  const height = Math.max(hidden.length, 4) * ROW + PAD_Y * 2 - ROW;
  const xType = 150;
  const xLoc = Math.round(width * 0.42);
  const xSev = width - 170;
  // ~7px per character at 13px; leave room for the node and the output layer
  const hiddenLabelChars = Math.max(12, Math.min(40, Math.floor((xSev - xLoc - 70) / 7)));
  const column = (count: number, i: number) => {
    const span = (count - 1) * ROW;
    return height / 2 - span / 2 + i * ROW;
  };
  const pos: Record<string, { x: number; y: number }> = {};
  types.forEach((t, i) => (pos[`type:${t.key}`] = { x: xType, y: column(types.length, i) }));
  hidden.forEach((l, i) => (pos[`loc:${l.key}`] = { x: xLoc, y: column(hidden.length, i) }));
  SEVERITIES.forEach((s, i) => (pos[`sev:${s}`] = { x: xSev, y: column(SEVERITIES.length, i) }));

  // ---- edges from triples (optionally restricted to the active node's findings)
  const matches = (t: Triple) =>
    !active ||
    (active.layer === "type" && t.type === active.id) ||
    (active.layer === "loc" && t.loc === active.id) ||
    (active.layer === "sev" && t.sev === active.id);

  const edgesFrom = (list: Triple[]) => {
    const inEdges = new Map<string, { from: string; to: string; n: number }>();
    const outEdges = new Map<string, { from: string; to: string; n: number; sev: Severity }>();
    for (const t of list) {
      const a = `type:${t.type}|loc:${t.loc}`;
      const e1 = inEdges.get(a) ?? { from: `type:${t.type}`, to: `loc:${t.loc}`, n: 0 };
      e1.n += t.n;
      inEdges.set(a, e1);
      const b = `loc:${t.loc}|sev:${t.sev}`;
      const e2 = outEdges.get(b) ?? { from: `loc:${t.loc}`, to: `sev:${t.sev}`, n: 0, sev: t.sev };
      e2.n += t.n;
      outEdges.set(b, e2);
    }
    return { inEdges: Array.from(inEdges.values()), outEdges: Array.from(outEdges.values()) };
  };

  const base = edgesFrom(triples);
  const focus = active ? edgesFrom(triples.filter(matches)) : null;
  const maxEdge = Math.max(...base.inEdges.map((e) => e.n), ...base.outEdges.map((e) => e.n), 1);
  const strokeW = (n: number) => 1.25 + 9 * Math.sqrt(n / maxEdge);

  // node totals (radius encodes volume, kept >= 8px diameter)
  const totals: Record<string, number> = {};
  for (const t of triples) {
    totals[`type:${t.type}`] = (totals[`type:${t.type}`] ?? 0) + t.n;
    totals[`loc:${t.loc}`] = (totals[`loc:${t.loc}`] ?? 0) + t.n;
    totals[`sev:${t.sev}`] = (totals[`sev:${t.sev}`] ?? 0) + t.n;
  }
  const maxNode = Math.max(...Object.values(totals), 1);
  const radius = (id: string) => 6 + 8 * Math.sqrt((totals[id] ?? 0) / maxNode);

  const focusNodes = new Set<string>();
  for (const e of focus ? [...focus.inEdges, ...focus.outEdges] : []) {
    focusNodes.add(e.from);
    focusNodes.add(e.to);
  }
  const dimmed = (id: string) => focus !== null && !focusNodes.has(id);

  // ---- interaction
  const nodeTooltip = (layer: Layer, id: string): Omit<Tooltip, "x" | "y"> => {
    const subset = triples.filter((t) => (layer === "type" ? t.type === id : layer === "loc" ? t.loc === id : t.sev === id));
    const total = subset.reduce((n, t) => n + t.n, 0);
    if (layer === "sev") {
      return {
        title: `${SEVERITY_LABEL[id as Severity]} findings`,
        rows: TYPES.map(({ key, label }) => ({
          label,
          value: subset.filter((t) => t.type === key).reduce((n, t) => n + t.n, 0),
        })),
        total,
      };
    }
    const loc = layer === "loc" ? hidden.find((l) => l.key === id) : undefined;
    return {
      title: layer === "type" ? TYPES.find((t) => t.key === id)?.label ?? id : loc?.label ?? id,
      subtitle: loc?.detail,
      rows: SEVERITIES.map((s) => ({
        label: SEVERITY_LABEL[s],
        value: subset.filter((t) => t.sev === s).reduce((n, t) => n + t.n, 0),
        swatch: SEVERITY_FILL[s],
      })),
      total,
    };
  };

  const activate = (node: NodeRef, target: Element) => {
    setActive(node);
    const box = containerRef.current?.getBoundingClientRect();
    const r = target.getBoundingClientRect();
    if (!box) return;
    const x = Math.min(Math.max(r.left - box.left + r.width / 2, 132), box.width - 132);
    setTooltip({ x, y: r.top - box.top, ...nodeTooltip(node.layer, node.id) });
  };
  const deactivate = () => {
    setActive(null);
    setTooltip(null);
  };
  const select = (node: NodeRef) => {
    if (node.layer === "type") onSelect({ category: node.id as FindingCategory });
    else if (node.layer === "sev") onSelect({ severity: node.id as Severity });
    else if (node.id !== OTHER) onSelect({ query: hidden.find((l) => l.key === node.id)?.query });
  };

  const renderNode = (layer: Layer, id: string, fill: string, label: string, sub: string, side: "left" | "right") => {
    const key = `${layer}:${id}`;
    const { x, y } = pos[key];
    const r = radius(key);
    const clickable = !(layer === "loc" && id === OTHER);
    const tx = side === "left" ? x - r - 10 : x + r + 10;
    return (
      <g
        key={key}
        role={clickable ? "button" : "img"}
        tabIndex={0}
        aria-label={`${label}: ${totals[key] ?? 0} findings${clickable ? ". Activate to filter the list." : ""}`}
        onMouseEnter={(e) => activate({ layer, id }, e.currentTarget)}
        onMouseLeave={deactivate}
        onFocus={(e) => activate({ layer, id }, e.currentTarget)}
        onBlur={deactivate}
        onClick={() => clickable && select({ layer, id })}
        onKeyDown={(e) => {
          if (clickable && (e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            select({ layer, id });
          }
        }}
        className={`outline-none ${clickable ? "cursor-pointer" : "cursor-default"}`}
        style={{ opacity: dimmed(key) ? 0.25 : 1, transition: "opacity 150ms" }}
      >
        {/* generous invisible hit target */}
        <circle cx={x} cy={y} r={Math.max(r + 8, 16)} fill={SURFACE} fillOpacity={0} />
        {/* 2px surface ring keeps the node legible over edges */}
        <circle cx={x} cy={y} r={r} fill={fill} stroke={SURFACE} strokeWidth={2} />
        {active?.layer === layer && active.id === id && (
          <circle cx={x} cy={y} r={r + 4} fill="none" stroke={INK} strokeWidth={1.5} />
        )}
        <text
          x={tx}
          y={y - 2}
          textAnchor={side === "left" ? "end" : "start"}
          fontSize={13}
          fill={INK}
          stroke={SURFACE}
          strokeWidth={4}
          paintOrder="stroke"
          strokeLinejoin="round"
        >
          {label}
        </text>
        <text
          x={tx}
          y={y + 13}
          textAnchor={side === "left" ? "end" : "start"}
          fontSize={11}
          fill={INK_2}
          stroke={SURFACE}
          strokeWidth={4}
          paintOrder="stroke"
          strokeLinejoin="round"
          style={{ fontVariantNumeric: "tabular-nums" }}
        >
          {sub}
        </text>
      </g>
    );
  };

  const drawEdges = (
    edges: { from: string; to: string; n: number; sev?: Severity }[],
    opacity: number,
    keyPrefix: string,
  ) =>
    edges.map((e) => {
      const a = pos[e.from];
      const b = pos[e.to];
      if (!a || !b) return null;
      return (
        <path
          key={`${keyPrefix}${e.from}->${e.to}`}
          d={edgePath(a.x, a.y, b.x, b.y)}
          fill="none"
          stroke={e.sev ? SEVERITY_FILL[e.sev] : NEUTRAL_EDGE}
          strokeWidth={strokeW(e.n)}
          strokeLinecap="round"
          opacity={opacity}
        />
      );
    });

  return (
    <section
      ref={containerRef}
      className="relative mt-6 bg-slate-900 border border-white/10 rounded-2xl p-5"
      aria-labelledby="findings-overview-title"
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2 mb-2">
        <div>
          <h2 id="findings-overview-title" className="text-base font-semibold text-slate-100">
            How findings relate
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Each finding flows from its type, through the file or package it lives in, to its severity. Hover a
            node to trace its findings; click to filter the list.
          </p>
        </div>
        <SeverityLegend />
      </div>

      <div className="overflow-x-auto -mx-1 px-1">
        <div ref={plotRef} style={{ minWidth: MIN_WIDTH }}>
          <svg
            width={width}
            height={height}
            viewBox={`0 0 ${width} ${height}`}
            role="group"
            aria-label="Network of finding types, locations and severities"
            className="block"
          >
            {/* layer captions */}
            {[
              { x: xType, title: "Input layer", sub: "finding type" },
              { x: xLoc, title: "Hidden layer", sub: "file / package" },
              { x: xSev, title: "Output layer", sub: "severity" },
            ].map((c) => (
              <g key={c.title}>
                <text x={c.x} y={16} textAnchor="middle" fontSize={11} fontWeight={600} fill={INK_2}>
                  {c.title}
                </text>
                <text x={c.x} y={30} textAnchor="middle" fontSize={11} fill={MUTED}>
                  {c.sub}
                </text>
              </g>
            ))}

            {/* edges: full network, dimmed while a node is active; focus overlay on top */}
            <g>
              {drawEdges(base.inEdges, focus ? 0.12 : 0.85, "b-in-")}
              {drawEdges(base.outEdges, focus ? 0.1 : 0.55, "b-out-")}
            </g>
            {focus && (
              <g>
                {drawEdges(focus.inEdges, 1, "f-in-")}
                {drawEdges(focus.outEdges, 0.9, "f-out-")}
              </g>
            )}

            {/* nodes */}
            {types.map((t) => renderNode("type", t.key, NEUTRAL_NODE, t.label, `${totals[`type:${t.key}`]} findings`, "left"))}
            {hidden.map((l) =>
              renderNode(
                "loc",
                l.key,
                l.key === OTHER ? MUTED : NEUTRAL_NODE,
                truncate(l.label, hiddenLabelChars, l.key.startsWith("file:")),
                `${l.total} · ${l.key === OTHER ? "more locations" : l.key.startsWith("pkg:") ? "package" : "file"}`,
                "right",
              ),
            )}
            {SEVERITIES.map((s) =>
              renderNode("sev", s, SEVERITY_FILL[s], SEVERITY_LABEL[s], `${totals[`sev:${s}`] ?? 0} findings`, "right"),
            )}
          </svg>
        </div>
      </div>

      <TableView locations={model.ranked} triples={triples} />

      {tooltip && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 w-64 -translate-x-1/2 -translate-y-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 shadow-lg"
          style={{ left: tooltip.x, top: tooltip.y - 10 }}
        >
          <p className="text-xs font-medium text-slate-100 break-all">{tooltip.title}</p>
          {tooltip.subtitle && <p className="text-[11px] text-slate-400 break-all">{tooltip.subtitle}</p>}
          <ul className="mt-1.5 space-y-0.5">
            {tooltip.rows.map((r) => (
              <li key={r.label} className="flex items-center gap-2 text-xs text-slate-400">
                {r.swatch && <span className="w-2 h-2 rounded-full" style={{ background: r.swatch }} aria-hidden="true" />}
                <span className="flex-1">{r.label}</span>
                <span className="tabular-nums text-slate-100">{r.value}</span>
              </li>
            ))}
          </ul>
          <p className="mt-1 pt-1 border-t border-slate-800 flex text-xs text-slate-400">
            <span className="flex-1">Total</span>
            <span className="tabular-nums font-medium text-slate-100">{tooltip.total}</span>
          </p>
        </div>
      )}
    </section>
  );
}
