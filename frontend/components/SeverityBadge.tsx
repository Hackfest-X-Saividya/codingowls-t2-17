"use client";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/30",
  high: "bg-orange-500/10 text-orange-300 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  low: "bg-blue-500/10 text-blue-300 border-blue-500/30",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.low;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${style} uppercase tracking-wide`}
    >
      {severity}
    </span>
  );
}
