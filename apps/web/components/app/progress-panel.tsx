"use client";

import { Check, Circle, Loader2, Minus, X } from "lucide-react";

import type { Assessment, Job } from "@/lib/api";
import { cn, duration } from "@/lib/utils";

const STAGES: Record<"discovery" | "source", [string, string][]> = {
  discovery: [
    ["validating", "Validating website"],
    ["checking_integration", "Checking ROUTES integration"],
    ["discovering_pages", "Discovering pages"],
    ["inspecting_javascript", "Inspecting JavaScript"],
    ["identifying_endpoints", "Identifying endpoints"],
    ["detecting_technologies", "Identifying technologies"],
  ],
  source: [
    ["retrieving_source", "Retrieving source code"],
    ["extracting", "Extracting archive safely"],
    ["profiling", "Profiling repository"],
    ["running_static_rules", "Running static security rules"],
    ["analysing_structure", "Analysing source structure"],
    ["tracing_data_flow", "Tracing user input to queries"],
  ],
};

type StepState = "done" | "active" | "pending" | "failed" | "skipped";

function stepStates(job: Job, kind: "discovery" | "source"): StepState[] {
  const ids = STAGES[kind].map(([id]) => id);
  const seen = new Set([...(job.stages_completed ?? []), ...(job.stage ? [job.stage] : [])]);
  const lastIndex = Math.max(-1, ...ids.map((id, i) => (seen.has(id) ? i : -1)));
  return ids.map((_, i) => {
    if (job.status === "completed") return "done";
    if (i < lastIndex) return "done";
    if (i === lastIndex) {
      if (job.status === "running") return "active";
      if (job.status === "failed") return "failed";
      return "done";
    }
    if (job.status === "failed" || job.status === "cancelled") return "skipped";
    return "pending";
  });
}

export function ProgressPanel({ assessment }: { assessment: Assessment }) {
  const jobs = assessment.jobs.filter((j) => j.kind !== "results") as (Job & { kind: "discovery" | "source" })[];
  const results = assessment.jobs.find((j) => j.kind === "results");
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {jobs.map((job) => (
        <div key={job.id} className="rounded-md border border-line bg-surface">
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <span className="text-[13px] font-semibold">{job.kind === "discovery" ? "Website discovery" : "Source analysis"}</span>
            <span className="text-[12px] text-muted tabular">
              {job.status === "queued" ? "Waiting for a worker" : duration(job.started_at, job.finished_at)}
            </span>
          </div>
          <ol className="px-4 py-3">
            {STAGES[job.kind].map(([id, label], i) => {
              const state = stepStates(job, job.kind)[i];
              return (
                <li key={id} className="flex items-start gap-2.5 py-1">
                  <StepIcon state={state} />
                  <span className="min-w-0">
                    <span className={cn("text-[13px]", state === "pending" || state === "skipped" ? "text-faint" : "text-ink")}>{label}</span>
                    {state === "active" && job.message && <span className="block text-[12px] text-muted">{job.message}</span>}
                  </span>
                </li>
              );
            })}
          </ol>
          {job.status === "failed" && job.error && (
            <p className="border-t border-line bg-[#fdf4f3] px-4 py-2.5 text-[12.5px] text-[#8a1c13]">{job.error}</p>
          )}
          {job.status === "cancelled" && <p className="border-t border-line px-4 py-2.5 text-[12.5px] text-muted">Cancelled.</p>}
        </div>
      ))}
      {results && results.status !== "queued" && (
        <p className="text-[12.5px] text-muted md:col-span-2">
          {results.status === "running" ? "Processing findings…" : results.status === "completed" ? "Findings processed." : null}
        </p>
      )}
    </div>
  );
}

function StepIcon({ state }: { state: StepState }) {
  const base = "mt-0.5 size-4 shrink-0";
  if (state === "done") return <Check className={cn(base, "text-ok")} strokeWidth={2.5} />;
  if (state === "active") return <Loader2 className={cn(base, "animate-spin text-accent")} />;
  if (state === "failed") return <X className={cn(base, "text-bad")} strokeWidth={2.5} />;
  if (state === "skipped") return <Minus className={cn(base, "text-faint")} />;
  return <Circle className={cn(base, "text-line-strong")} />;
}
