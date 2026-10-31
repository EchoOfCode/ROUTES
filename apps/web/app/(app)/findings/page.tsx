"use client";

import { ShieldCheck } from "lucide-react";
import * as React from "react";

import { FindingsList } from "@/components/app/findings-list";
import { EmptyState, Loading, Notice, PageBody, PageHeader } from "@/components/app/layout-parts";
import { SEVERITY_ORDER } from "@/components/app/status";
import { useApi } from "@/hooks/use-api";
import type { Finding } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function FindingsPage() {
  const { data, error, loading } = useApi<Finding[]>("/findings");
  const [severity, setSeverity] = React.useState<string | null>(null);
  const [type, setType] = React.useState<string | null>(null);
  const types = React.useMemo(() => [...new Set((data ?? []).map((f) => f.type))].sort(), [data]);
  const shown = (data ?? []).filter((f) => (!severity || f.severity === severity) && (!type || f.type === type));

  return (
    <>
      <PageHeader title="Findings" description="Issues from the latest finished assessment of each project." />
      <PageBody>
        {loading && !data && <Loading />}
        {error && <Notice tone="bad">{error.message}</Notice>}
        {data && data.length === 0 && (
          <EmptyState icon={ShieldCheck} title="No findings">
            None of the latest assessments matched a security check. Connect source code for deeper analysis; static checks cannot prove the absence of vulnerabilities.
          </EmptyState>
        )}
        {data && data.length > 0 && (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-[12.5px]">
              <Filter label="Severity" value={severity} onChange={setSeverity}
                options={SEVERITY_ORDER.filter((s) => data.some((f) => f.severity === s)).map((s) => [s, s[0].toUpperCase() + s.slice(1)])} />
              <Filter label="Type" value={type} onChange={setType} options={types.map((t) => [t, t])} />
              <span className="ml-auto text-muted tabular">{shown.length} of {data.length}</span>
            </div>
            <FindingsList findings={shown} showProject />
          </>
        )}
      </PageBody>
    </>
  );
}

function Filter({ label, value, onChange, options }: { label: string; value: string | null; onChange: (v: string | null) => void; options: [string, string][] }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className="mr-1 text-muted">{label}</span>
      {[[null, "All"] as [string | null, string], ...options].map(([v, l]) => (
        <button key={l} onClick={() => onChange(v)}
          className={cn("rounded-sm px-2 py-1 font-medium", value === v ? "bg-ink text-white" : "text-ink-2 hover:bg-sunken")}>
          {l}
        </button>
      ))}
    </div>
  );
}
