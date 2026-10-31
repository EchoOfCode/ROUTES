"use client";

import { ChevronRight } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { FindingStatusTag, MethodTag, SeverityTag } from "@/components/app/status";
import type { Finding } from "@/lib/api";
import { cn } from "@/lib/utils";

export function FindingsList({ findings, showProject = false }: { findings: Finding[]; showProject?: boolean }) {
  const [open, setOpen] = React.useState<string | null>(null);
  React.useEffect(() => {
    const id = typeof window !== "undefined" ? window.location.hash.slice(1) : "";
    if (id && findings.some((f) => f.id === id)) setOpen(id);
  }, [findings]);

  if (findings.length === 0) {
    return (
      <p className="rounded-md border border-line bg-surface px-4 py-6 text-[13px] text-muted">
        No findings. That means the checks ROUTES ran did not match anything. It does not prove the application is secure.
      </p>
    );
  }
  return (
    <ul className="divide-y divide-line overflow-hidden rounded-md border border-line bg-surface">
      {findings.map((f) => {
        const expanded = open === f.id;
        return (
          <li key={f.id} id={f.id}>
            <button
              type="button"
              onClick={() => setOpen(expanded ? null : f.id)}
              aria-expanded={expanded}
              className="grid w-full grid-cols-[92px_1fr_auto] items-start gap-4 px-4 py-3 text-left hover:bg-sunken/50"
            >
              <SeverityTag severity={f.severity} />
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-[13.5px] font-medium text-ink">{f.title}</span>
                  <FindingStatusTag status={f.status} />
                </span>
                <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12px] text-muted">
                  <span>{f.type}</span>
                  {showProject && f.project_name && <span>{f.project_name}</span>}
                  {f.endpoint && <span className="inline-flex items-center gap-1"><MethodTag method={f.method} /><span className="mono">{f.endpoint}</span></span>}
                  {f.file && <span className="mono">{f.file}{f.line ? `:${f.line}` : ""}</span>}
                </span>
              </span>
              <ChevronRight className={cn("mt-0.5 size-4 text-faint transition-transform", expanded && "rotate-90")} />
            </button>
            {expanded && <FindingDetail finding={f} showProject={showProject} />}
          </li>
        );
      })}
    </ul>
  );
}

function FindingDetail({ finding: f, showProject }: { finding: Finding; showProject: boolean }) {
  const details = f.technical_details as Record<string, unknown>;
  const flow = Array.isArray(details.flow) ? (details.flow as string[]) : [];
  const source = details.source as { kind?: string; name?: string; line?: number; expression?: string } | null | undefined;
  const sink = details.sink as { call?: string; file?: string; line?: number } | undefined;
  return (
    <div className="border-t border-line bg-canvas px-4 pb-5 pt-4 sm:pl-[124px]">
      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">What this means</h4>
          <p className="mt-1 text-[13.5px] leading-relaxed text-ink">{f.plain_description}</p>
          <h4 className="mt-4 text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">What ROUTES saw</h4>
          <p className="mt-1 text-[13px] leading-relaxed text-ink-2">{f.evidence_summary}</p>
          <h4 className="mt-4 text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">How to fix it</h4>
          <p className="mt-1 text-[13px] leading-relaxed text-ink-2">{f.recommendation}</p>
        </div>
        <div className="rounded-md border border-line bg-surface p-4">
          <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">Technical details</h4>
          <dl className="mt-2 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12.5px]">
            <dt className="text-muted">Status</dt>
            <dd>
              {f.status === "potential" && "Potential: found by static analysis, not reproduced."}
              {f.status === "inconclusive" && "Inconclusive: pattern found, exploitability unknown."}
              {f.status === "confirmed" && "Confirmed with reproduction evidence."}
            </dd>
            <dt className="text-muted">Confidence</dt><dd className="capitalize">{f.confidence}</dd>
            <dt className="text-muted">Rule</dt><dd className="mono text-[11.5px]">{f.rule_id}</dd>
            {typeof details.cwe === "string" && <><dt className="text-muted">Weakness</dt><dd className="mono text-[11.5px]">{details.cwe}</dd></>}
            {source && (
              <>
                <dt className="text-muted">Input source</dt>
                <dd>{source.kind}{source.name ? <> <span className="mono text-[11.5px]">{source.name}</span></> : null}{source.line ? <span className="text-muted"> (line {source.line})</span> : null}</dd>
              </>
            )}
            {sink?.call && <><dt className="text-muted">Database call</dt><dd className="mono break-all text-[11.5px]">{sink.call}</dd></>}
            {typeof details.query_construction === "string" && (
              <><dt className="text-muted">Query built by</dt><dd>{String(details.query_construction)}</dd></>
            )}
            {typeof details.snippet === "string" && details.snippet && (
              <><dt className="text-muted">Code</dt><dd className="mono whitespace-pre-wrap break-all text-[11.5px]">{details.snippet}</dd></>
            )}
          </dl>
          {flow.length > 0 && (
            <>
              <h4 className="mt-4 text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">Data flow</h4>
              <ol className="mt-1.5 space-y-1 border-l border-line-strong pl-3 text-[12px] text-ink-2">
                {source?.expression && <li className="mono break-all text-[11.5px]">{source.expression}</li>}
                {flow.map((s, i) => <li key={i}>{s}</li>)}
                {sink?.file && <li className="mono text-[11.5px]">→ {sink.file}:{sink.line}</li>}
              </ol>
            </>
          )}
          {showProject && f.project_id && (
            <Link href={`/projects/${f.project_id}/assessments/${f.assessment_id}?tab=findings`} className="mt-4 inline-block text-[12.5px] text-accent hover:underline">
              Open assessment
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
