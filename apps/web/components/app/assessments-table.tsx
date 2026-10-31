"use client";

import { useRouter } from "next/navigation";

import { SeverityBreakdown, StatusBadge } from "@/components/app/status";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import type { Assessment } from "@/lib/api";
import { duration, relativeTime } from "@/lib/utils";

export function AssessmentsTable({
  assessments, showProject = false, compact = false,
}: { assessments: Assessment[]; showProject?: boolean; compact?: boolean }) {
  const router = useRouter();
  if (assessments.length === 0) {
    return <p className="rounded-md border border-line bg-surface px-4 py-6 text-[13px] text-muted">No assessments yet.</p>;
  }
  return (
    <Table>
      <THead>
        <TR>
          {showProject && <TH>Project</TH>}
          <TH>Status</TH>
          <TH>Started</TH>
          {!compact && <TH>Duration</TH>}
          {!compact && <TH>Source</TH>}
          <TH className="text-right">Pages</TH>
          <TH>Findings</TH>
        </TR>
      </THead>
      <TBody>
        {assessments.map((a) => (
          <TR
            key={a.id}
            className="cursor-pointer hover:bg-sunken/50"
            onClick={() => router.push(`/projects/${a.project_id}/assessments/${a.id}`)}
          >
            {showProject && <TD className="font-medium text-ink">{a.project_name}</TD>}
            <TD><StatusBadge status={a.status} /></TD>
            <TD className="whitespace-nowrap text-muted">{relativeTime(a.created_at)}</TD>
            {!compact && <TD className="tabular text-muted">{duration(a.started_at, a.finished_at)}</TD>}
            {!compact && <TD className="mono text-[12px] text-muted">{a.source_label ?? "Website only"}</TD>}
            <TD className="tabular text-right">{a.counts.pages}</TD>
            <TD>{a.counts.findings === 0 ? <span className="text-muted">0</span> : <SeverityBreakdown counts={a.severity_counts} />}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
