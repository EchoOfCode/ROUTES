import { Loader2 } from "lucide-react";

import type { AssessmentStatus, Finding, Severity } from "@/lib/api";
import { cn } from "@/lib/utils";

const STATUS: Record<AssessmentStatus, { label: string; dot: string; text: string; spin?: boolean }> = {
  queued: { label: "Queued", dot: "bg-faint", text: "text-muted" },
  running: { label: "Processing", dot: "bg-accent", text: "text-accent", spin: true },
  discovering: { label: "Discovering", dot: "bg-accent", text: "text-accent", spin: true },
  analysing: { label: "Analysing", dot: "bg-accent", text: "text-accent", spin: true },
  completed: { label: "Completed", dot: "bg-ok", text: "text-ok" },
  partially_completed: { label: "Partially completed", dot: "bg-warn", text: "text-warn" },
  failed: { label: "Failed", dot: "bg-bad", text: "text-bad" },
  cancelled: { label: "Cancelled", dot: "bg-faint", text: "text-muted" },
};

export function StatusBadge({ status, className }: { status: AssessmentStatus; className?: string }) {
  const s = STATUS[status] ?? STATUS.queued;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[12.5px] font-medium", s.text, className)}>
      {s.spin ? <Loader2 className="size-3.5 animate-spin" /> : <span className={cn("size-1.5 rounded-full", s.dot)} />}
      {s.label}
    </span>
  );
}

const SEVERITY: Record<Severity, { label: string; bar: string; text: string }> = {
  critical: { label: "Critical", bar: "bg-sev-critical", text: "text-sev-critical" },
  high: { label: "High", bar: "bg-sev-high", text: "text-sev-high" },
  medium: { label: "Medium", bar: "bg-sev-medium", text: "text-sev-medium" },
  low: { label: "Low", bar: "bg-sev-low", text: "text-sev-low" },
  info: { label: "Info", bar: "bg-sev-info", text: "text-sev-info" },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityTag({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity] ?? SEVERITY.info;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[12.5px] font-semibold", s.text)}>
      <span className={cn("h-3 w-[3px] rounded-[1px]", s.bar)} />
      {s.label}
    </span>
  );
}

/** Potential vs confirmed must never be visually confused. */
export function FindingStatusTag({ status }: { status: Finding["status"] }) {
  if (status === "confirmed") {
    return <span className="rounded-sm bg-ink px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-white">Confirmed</span>;
  }
  return (
    <span className="rounded-sm border border-dashed border-line-strong px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">
      {status === "inconclusive" ? "Inconclusive" : "Potential"}
    </span>
  );
}

export function SeverityBreakdown({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (!present.length) return <span className="text-muted">None</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
      {present.map((s) => (
        <span key={s} className="inline-flex items-center gap-1 text-[12.5px]">
          <span className={cn("h-2.5 w-[3px] rounded-[1px]", SEVERITY[s].bar)} />
          <span className="tabular font-medium text-ink">{counts[s]}</span>
          <span className="text-muted">{SEVERITY[s].label.toLowerCase()}</span>
        </span>
      ))}
    </span>
  );
}

export function MethodTag({ method }: { method: string | null }) {
  if (!method) return null;
  return <span className="mono rounded-sm bg-sunken px-1 py-px text-[11px] font-semibold text-ink-2">{method}</span>;
}
