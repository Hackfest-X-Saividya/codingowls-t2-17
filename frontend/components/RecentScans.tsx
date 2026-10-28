"use client";

import { useEffect, useState } from "react";
import { listScans, type ScanHistoryItem } from "@/lib/api";

const STATUS_STYLES: Record<ScanHistoryItem["status"], string> = {
  complete: "bg-green-500/10 text-green-300",
  failed: "bg-red-500/10 text-red-300",
  running: "bg-blue-500/10 text-blue-300",
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
    <section className="mt-12 w-full max-w-2xl">
      <h2 className="text-sm font-medium text-slate-400 mb-3">Recent scans</h2>
      <ul className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
        {scans.map((s) => (
          <li key={s.scan_id}>
            <a
              href={`/results/${s.scan_id}`}
              className="flex items-center gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors"
            >
              <span className="flex-1 min-w-0 truncate font-mono text-sm text-slate-100">{s.repo_name}</span>
              {s.status === "complete" && (
                <span className="text-xs text-slate-400 whitespace-nowrap">
                  {s.total} issues
                  {s.critical > 0 && <span className="text-red-400"> &middot; {s.critical} critical</span>}
                  {s.high > 0 && <span className="text-orange-400"> &middot; {s.high} high</span>}
                </span>
              )}
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[s.status]}`}>
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
