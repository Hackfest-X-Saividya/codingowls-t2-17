"use client";

import { useEffect, useState } from "react";
import { listScans, type ScanHistoryItem } from "@/lib/api";

const STATUS_STYLES: Record<ScanHistoryItem["status"], string> = {
  complete: "bg-green-500/10 text-green-300",
  failed: "bg-red-500/10 text-red-300",
  running: "bg-indigo-500/15 text-indigo-200",
  pending: "bg-slate-800 text-slate-400",
};

export default function RecentScans() {
  const [scans, setScans] = useState<ScanHistoryItem[] | null>(null);

  useEffect(() => {
    listScans(8)
      .then(setScans)
      .catch(() => setScans([])); // history is optional; hide on error
  }, []);

  if (!scans || scans.length === 0) return null;

  return (
    <section className="mt-16 w-full rounded-2xl border border-white/10 bg-slate-900/90 backdrop-blur shadow-[0_30px_80px_-20px_rgba(104,28,197,0.6)] overflow-hidden">
      <div className="flex items-center gap-3 border-b border-white/5 px-4 py-3">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="w-2.5 h-2.5 rounded-full bg-slate-700" />
          <span className="w-2.5 h-2.5 rounded-full bg-slate-700" />
          <span className="w-2.5 h-2.5 rounded-full bg-slate-700" />
        </span>
        <h2 className="text-sm font-medium text-slate-300">Recent scans</h2>
      </div>
      <ul className="divide-y divide-white/5 text-left">
        {scans.map((s) => (
          <li key={s.scan_id}>
            <a
              href={`/results/${s.scan_id}`}
              className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.03] transition-colors"
            >
              <span className="flex-1 min-w-0 truncate font-mono text-sm text-slate-100">{s.repo_name}</span>
              {s.status === "complete" && (
                <span className="text-xs text-slate-400 whitespace-nowrap">
                  {s.total} issues
                  {s.critical > 0 && <span className="text-red-400"> &middot; {s.critical} critical</span>}
                  {s.high > 0 && <span className="text-orange-400"> &middot; {s.high} high</span>}
                </span>
              )}
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${STATUS_STYLES[s.status]}`}>
                {s.status}
              </span>
              <span className="hidden sm:inline text-xs text-slate-500 whitespace-nowrap">
                {new Date(s.started_at).toLocaleDateString()}
              </span>
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}
