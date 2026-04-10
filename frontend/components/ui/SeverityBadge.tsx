import { Severity } from "@/lib/types";

const severityStyles: Record<Severity, string> = {
  critical: "border-red-500/30 bg-red-500/12 text-red-300",
  high: "border-orange-500/30 bg-orange-500/12 text-orange-300",
  medium: "border-amber-500/30 bg-amber-500/12 text-amber-300",
  low: "border-blue-500/30 bg-blue-500/12 text-blue-300",
  info: "border-slate-500/30 bg-slate-500/12 text-slate-300"
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-1 font-[family-name:var(--font-mono)] text-[11px] uppercase tracking-[0.24em] ${severityStyles[severity]}`}
    >
      {severity}
    </span>
  );
}
