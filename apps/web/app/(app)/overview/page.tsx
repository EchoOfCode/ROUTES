"use client";

import { FolderKanban, Plus } from "lucide-react";
import Link from "next/link";

import { AssessmentsTable } from "@/components/app/assessments-table";
import { EmptyState, Loading, Notice, PageBody, PageHeader, Section } from "@/components/app/layout-parts";
import { FindingStatusTag, SeverityBreakdown, SeverityTag } from "@/components/app/status";
import { Button } from "@/components/ui/button";
import { useApi } from "@/hooks/use-api";
import { ACTIVE_STATUSES, type Overview } from "@/lib/api";

export default function OverviewPage() {
  const { data, error, loading } = useApi<Overview>("/overview", {
    poll: (d) => d.recent_assessments.some((a) => ACTIVE_STATUSES.includes(a.status)),
    intervalMs: 4000,
  });

  return (
    <>
      <PageHeader
        title="Overview"
        description="Your projects, their latest assessments and what they found."
        actions={<Button asChild><Link href="/projects/new"><Plus /> New project</Link></Button>}
      />
      <PageBody>
        {loading && !data && <Loading />}
        {error && <Notice tone="bad">{error.message}</Notice>}
        {data && data.projects === 0 && (
          <EmptyState
            icon={FolderKanban}
            title="No projects yet"
            action={<Button asChild><Link href="/projects/new"><Plus /> Assess your first website</Link></Button>}
          >
            <p>A project starts with a website you own or are permitted to assess.</p>
            <ol className="mt-3 list-decimal space-y-1 pl-4">
              <li>Enter the website URL and confirm your authorisation.</li>
              <li>ROUTES discovers its public pages, forms, endpoints and technologies.</li>
              <li>Optionally connect the source code to analyse routes and database queries.</li>
            </ol>
          </EmptyState>
        )}
        {data && data.projects > 0 && (
          <>
            <div className="mb-9 grid grid-cols-2 divide-line overflow-hidden rounded-md border border-line bg-surface md:grid-cols-4 md:divide-x">
              <Stat label="Projects" value={data.projects} href="/projects" />
              <Stat label="Assessments retained" value={data.assessments} href="/assessments" />
              <Stat label="Running now" value={data.active_assessments} />
              <div className="px-5 py-4">
                <p className="text-[11.5px] font-medium uppercase tracking-[0.04em] text-muted">Current findings</p>
                <p className="mt-1 text-[22px] font-semibold tabular">{data.open_findings}</p>
                <div className="mt-1"><SeverityBreakdown counts={data.severity_counts} /></div>
              </div>
            </div>

            <div className="grid gap-x-10 lg:grid-cols-[1.25fr_1fr]">
              <Section title="Recent assessments" actions={<Link href="/assessments" className="text-[12.5px] text-accent hover:underline">All assessments</Link>}>
                <AssessmentsTable assessments={data.recent_assessments} showProject compact />
              </Section>
              <Section title="Recent findings" description="From each project's latest finished assessment."
                actions={<Link href="/findings" className="text-[12.5px] text-accent hover:underline">All findings</Link>}>
                {data.recent_findings.length === 0 ? (
                  <p className="rounded-md border border-line bg-surface px-4 py-6 text-[13px] text-muted">
                    No findings in the latest assessments.
                  </p>
                ) : (
                  <ul className="divide-y divide-line rounded-md border border-line bg-surface">
                    {data.recent_findings.map((f) => (
                      <li key={f.id}>
                        <Link
                          href={`/projects/${f.project_id}/assessments/${f.assessment_id}?tab=findings#${f.id}`}
                          className="block px-4 py-3 hover:bg-sunken/50"
                        >
                          <div className="flex items-center gap-3">
                            <SeverityTag severity={f.severity} />
                            <FindingStatusTag status={f.status} />
                          </div>
                          <p className="mt-1 text-[13px] font-medium text-ink">{f.title}</p>
                          <p className="mono mt-0.5 truncate text-[11.5px] text-muted">
                            {f.project_name} · {f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.endpoint}
                          </p>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
            </div>
          </>
        )}
      </PageBody>
    </>
  );
}

function Stat({ label, value, href }: { label: string; value: number; href?: string }) {
  const body = (
    <>
      <p className="text-[11.5px] font-medium uppercase tracking-[0.04em] text-muted">{label}</p>
      <p className="mt-1 text-[22px] font-semibold tabular">{value}</p>
    </>
  );
  return href ? (
    <Link href={href} className="block border-b border-line px-5 py-4 hover:bg-sunken/40 md:border-b-0">{body}</Link>
  ) : (
    <div className="border-b border-line px-5 py-4 md:border-b-0">{body}</div>
  );
}
