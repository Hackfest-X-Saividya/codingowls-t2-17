"use client";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  low: "bg-blue-50 text-blue-700 border-blue-200",
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
