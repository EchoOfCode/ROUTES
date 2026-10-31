"use client";

import { FolderKanban, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { EmptyState, Loading, Notice, PageBody, PageHeader } from "@/components/app/layout-parts";
import { SourceLabel } from "@/components/app/source-label";
import { StatusBadge } from "@/components/app/status";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { ACTIVE_STATUSES, type Project } from "@/lib/api";
import { relativeTime } from "@/lib/utils";

export default function ProjectsPage() {
  const router = useRouter();
  const { data, error, loading } = useApi<Project[]>("/projects", {
    poll: (d) => d.some((p) => p.latest_assessment && ACTIVE_STATUSES.includes(p.latest_assessment.status)),
    intervalMs: 4000,
  });
  return (
    <>
      <PageHeader
        title="Projects"
        description="Each project is one website, optionally linked to its source code."
        actions={<Button asChild><Link href="/projects/new"><Plus /> New project</Link></Button>}
      />
      <PageBody>
        {loading && !data && <Loading />}
        {error && <Notice tone="bad">{error.message}</Notice>}
        {data && data.length === 0 && (
          <EmptyState icon={FolderKanban} title="No projects yet"
            action={<Button asChild><Link href="/projects/new"><Plus /> New project</Link></Button>}>
            Create a project by entering the URL of a website you own or are permitted to assess.
          </EmptyState>
        )}
        {data && data.length > 0 && (
          <Table>
            <THead>
              <TR>
                <TH>Project</TH>
                <TH>Connected source</TH>
                <TH>Framework</TH>
                <TH>Latest assessment</TH>
                <TH>Last assessed</TH>
                <TH className="text-right">Findings</TH>
              </TR>
            </THead>
            <TBody>
              {data.map((p) => (
                <TR key={p.id} className="cursor-pointer hover:bg-sunken/50" onClick={() => router.push(`/projects/${p.id}`)}>
                  <TD>
                    <div className="font-medium text-ink">{p.name}</div>
                    <div className="mono text-[11.5px] text-muted">{p.website_url}</div>
                  </TD>
                  <TD><SourceLabel integration={p.integration} /></TD>
                  <TD>{p.framework && p.framework !== "Unknown" ? p.framework : <span className="text-muted">Not identified</span>}</TD>
                  <TD>{p.latest_assessment ? <StatusBadge status={p.latest_assessment.status} /> : <span className="text-muted">—</span>}</TD>
                  <TD className="whitespace-nowrap text-muted">
                    {relativeTime(p.latest_assessment?.finished_at ?? p.latest_assessment?.created_at)}
                  </TD>
                  <TD className="tabular text-right">{p.latest_assessment?.findings_count ?? "—"}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </PageBody>
    </>
  );
}
