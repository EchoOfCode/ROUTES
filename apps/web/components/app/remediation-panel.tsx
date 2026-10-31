"use client";

import { Check, Circle, X } from "lucide-react";
import * as React from "react";

import { RemediationStatusTag } from "@/components/app/status";
import { useApi } from "@/hooks/use-api";
import { ACTIVE_REMEDIATION_STATUSES, api, ApiError, type Finding, type Remediation, type RemediationIteration } from "@/lib/api";
import { cn } from "@/lib/utils";

const SUPPORTED_RULE_PREFIX = "routes.sqli";

export function RemediationPanel({ assessmentId, finding }: { assessmentId: string; finding: Finding }) {
  const [remediationId, setRemediationId] = React.useState<string | null>(null);
  const [starting, setStarting] = React.useState(false);
  const [startError, setStartError] = React.useState<string | null>(null);

  const path = remediationId
    ? `/assessments/${assessmentId}/findings/${finding.id}/remediations/${remediationId}`
    : null;
  const { data: remediation, reload } = useApi<Remediation>(path, {
    poll: (r) => ACTIVE_REMEDIATION_STATUSES.includes(r.status),
    intervalMs: 2000,
  });

  if (!finding.rule_id.startsWith(SUPPORTED_RULE_PREFIX) || !finding.snapshot) {
    return null;
  }

  async function startRemediation() {
    setStarting(true);
    setStartError(null);
    try {
      const r = await api<Remediation>(`/assessments/${assessmentId}/findings/${finding.id}/remediate`, {
        method: "POST",
      });
      setRemediationId(r.id);
    } catch (e) {
      setStartError(e instanceof ApiError ? e.message : "Could not start remediation.");
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    if (!remediationId) return;
    await api(`/assessments/${assessmentId}/findings/${finding.id}/remediations/${remediationId}/cancel`, {
      method: "POST",
    });
    await reload();
  }

  if (!remediation) {
    return (
      <div className="mt-4 border-t border-line pt-4">
        <button
          type="button"
          onClick={startRemediation}
          disabled={starting}
          className="rounded-md bg-ink px-3 py-1.5 text-[13px] font-medium text-white hover:bg-ink/90 disabled:opacity-50"
        >
          {starting ? "Starting…" : "Fix this"}
        </button>
        {startError && <p className="mt-2 text-[12.5px] text-bad">{startError}</p>}
      </div>
    );
  }

  const cancellable = ACTIVE_REMEDIATION_STATUSES.includes(remediation.status);
  const lastFixed = [...remediation.iterations].reverse().find((it) => it.rescan_diff?.fingerprint_gone);

  return (
    <div className="mt-4 border-t border-line pt-4">
      <div className="flex items-center justify-between">
        <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">Automatic fix</h4>
        <div className="flex items-center gap-3">
          <RemediationStatusTag status={remediation.status} />
          {cancellable && (
            <button type="button" onClick={cancel} className="text-[12px] text-muted hover:text-ink hover:underline">
              Cancel
            </button>
          )}
        </div>
      </div>

      {remediation.error && (
        <p className="mt-2 text-[12.5px] text-ink-2">{remediation.error}</p>
      )}

      {remediation.iterations.length > 0 && (
        <ol className="mt-3 space-y-1.5">
          {remediation.iterations.map((it) => <IterationRow key={it.id} iteration={it} />)}
        </ol>
      )}

      {remediation.status === "succeeded" && lastFixed && (
        <BeforeAfterDiff before={finding.snapshot!.code} after={lastFixed.candidate_code ?? ""} />
      )}
    </div>
  );
}

function IterationRow({ iteration }: { iteration: RemediationIteration }) {
  const fixed = Boolean(iteration.rescan_diff?.fingerprint_gone) && !(iteration.rescan_diff?.new_fingerprints?.length);
  const icon = iteration.failure_output
    ? <X className="mt-0.5 size-4 shrink-0 text-bad" strokeWidth={2.5} />
    : fixed
      ? <Check className="mt-0.5 size-4 shrink-0 text-ok" strokeWidth={2.5} />
      : <Circle className="mt-0.5 size-4 shrink-0 text-line-strong" />;
  const tests = iteration.test_results?.tests ?? [];
  return (
    <li className="flex items-start gap-2.5">
      {icon}
      <div className="min-w-0 text-[12.5px]">
        <span className="font-medium text-ink">Round {iteration.round_no ?? "?"}</span>
        {tests.length > 0 && (
          <span className="ml-2 text-muted">
            {tests.filter((t) => t.passed).length}/{tests.length} assertions passed
          </span>
        )}
        {iteration.failure_output && <p className="mt-0.5 text-ink-2">{iteration.failure_output}</p>}
      </div>
    </li>
  );
}

function BeforeAfterDiff({ before, after }: { before: string; after: string }) {
  return (
    <div className="mt-4">
      <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-muted">Before / after</h4>
      <div className="mt-1.5 grid gap-3 sm:grid-cols-2">
        <CodeBlock label="Before" code={before} tone="bad" />
        <CodeBlock label="After" code={after} tone="ok" />
      </div>
    </div>
  );
}

function CodeBlock({ label, code, tone }: { label: string; code: string; tone: "bad" | "ok" }) {
  return (
    <div className="overflow-hidden rounded-md border border-line">
      <div className={cn("border-b border-line px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide",
                         tone === "bad" ? "bg-[#fdf4f3] text-[#8a1c13]" : "bg-[#f1f8f4] text-ok")}>
        {label}
      </div>
      <pre className="mono overflow-x-auto whitespace-pre p-3 text-[11.5px] leading-relaxed text-ink-2">{code}</pre>
    </div>
  );
}
