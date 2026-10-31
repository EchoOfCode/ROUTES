"use client";

import { Plug } from "lucide-react";
import Link from "next/link";

import { EmptyState, Loading, Notice, PageBody, PageHeader, Section } from "@/components/app/layout-parts";
import { SourceLabel } from "@/components/app/source-label";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import type { Project } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const KIND = { github_public: "Public GitHub", github_private: "Private GitHub", zip: "ZIP upload" } as const;
const MATCH = { pending: "Awaiting confirmation", confirmed: "Confirmed by you", rejected: "Marked as not matching" } as const;

export default function IntegrationsPage() {
  const { data, error, loading } = useApi<Project[]>("/projects");
  return (
    <>
      <PageHeader title="Integrations" description="Source code connected to your projects, and how ROUTES handles it." />
      <PageBody>
        {loading && !data && <Loading />}
        {error && <Notice tone="bad">{error.message}</Notice>}
        {data && (
          <Section title="Connected sources">
            {data.length === 0 ? (
              <EmptyState icon={Plug} title="No projects yet">Create a project first, then connect its repository or upload a ZIP.</EmptyState>
            ) : (
              <Table>
                <THead><TR><TH>Project</TH><TH>Type</TH><TH>Source</TH><TH>Website match</TH><TH>Connected</TH></TR></THead>
                <TBody>
                  {data.map((p) => (
                    <TR key={p.id}>
                      <TD><Link href={`/projects/${p.id}`} className="font-medium text-ink hover:underline">{p.name}</Link></TD>
                      <TD>{p.integration ? KIND[p.integration.kind] : <span className="text-muted">—</span>}</TD>
                      <TD>{p.integration ? <SourceLabel integration={p.integration} /> : <Link href={`/projects/${p.id}`} className="text-accent hover:underline">Connect source</Link>}</TD>
                      <TD className="text-muted">{p.integration ? MATCH[p.integration.match_status] : "—"}</TD>
                      <TD className="text-muted">{p.integration ? formatDate(p.integration.created_at) : "—"}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Section>
        )}
        <Section title="How source code is handled">
          <ul className="max-w-3xl list-disc space-y-1.5 pl-5 text-[13px] text-ink-2">
            <li>Repositories are downloaded and archives extracted inside a disposable sandbox with no general internet access. Code is read, never executed or installed.</li>
            <li>Private-repository tokens are used once, by the network gateway, and are never stored in the database, job queue, logs or the sandbox itself.</li>
            <li>Extracted source and uploaded ZIP files are deleted when analysis finishes or fails. Only structured results and redacted evidence are kept.</li>
            <li>Detailed analysis supports Next.js (JavaScript/TypeScript) with the <code className="mono">pg</code> PostgreSQL client. Other stacks get a basic profile and general static rules.</li>
          </ul>
        </Section>
      </PageBody>
    </>
  );
}
