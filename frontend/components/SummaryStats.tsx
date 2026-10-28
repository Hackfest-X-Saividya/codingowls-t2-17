"use client";

import type { ScanSummary } from "@/lib/api";

const STAT_CARDS = [
  { key: "critical" as const, label: "Critical", accentColor: "bg-red-500", textColor: "text-red-700" },
  { key: "high" as const, label: "High", accentColor: "bg-orange-500", textColor: "text-orange-700" },
  { key: "medium" as const, label: "Medium", accentColor: "bg-amber-500", textColor: "text-amber-700" },
  { key: "low" as const, label: "Low", accentColor: "bg-blue-500", textColor: "text-blue-700" },
];

export default function SummaryStats({ summary }: { summary: ScanSummary }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <p className="text-sm text-gray-500">Total Issues</p>
        <p className="text-3xl font-bold mt-1 text-gray-900">{summary.total}</p>
      </div>
      {STAT_CARDS.map(({ key, label, accentColor, textColor }) => (
        <div key={key} className="bg-white border border-gray-200 rounded-xl p-5 relative overflow-hidden">
          <div className={`absolute top-0 left-0 w-1 h-full ${accentColor}`} />
          <p className="text-sm text-gray-500">{label}</p>
          <p className={`text-3xl font-bold mt-1 ${textColor}`}>{summary[key]}</p>
        </div>
      ))}
    </div>
  );
}
