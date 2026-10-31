"use client";

import { ExternalLink, Play, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import * as React from "react";

import { AssessmentsTable } from "@/components/app/assessments-table";
import { ConnectSource } from "@/components/app/connect-source";
import { FindingsList } from "@/components/app/findings-list";
import { KeyValues, Loading, Notice, PageBody, PageHeader, Section } from "@/components/app/layout-parts";
import { SourceLabel } from "@/components/app/source-label";
import { StatusBadge } from "@/components/app/status";
import { TechnologiesTable } from "@/components/app/technologies-table";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useApi } from "@/hooks/use-api";
import {
  ACTIVE_STATUSES, api, ApiError, type Assessment, type Finding, type Integration, type Project, type Technology,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const project = useApi<Project>(`/projects/${id}`);
  const history = useApi<Assessment[]>(`/projects/${id}/assessments`, {
    poll: (list) => list.some((a) => ACTIVE_STATUSES.includes(a.status)),
    intervalMs: 3000,
  });
  const latestDone = history.data?.find((a) => !ACTIVE_STATUSES.includes(a.status));
  const running = history.data?.find((a) => ACTIVE_STATUSES.includes(a.status));
  const techs = useApi<Technology[]>(latestDone ? `/assessments/${latestDone.id}/technologies` : null);
  const findings = useApi<Finding[]>(latestDone ? `/assessments/${latestDone.id}/findings` : null);
  const [runOpen, setRunOpen] = React.useState(false);
  const [showConnect, setShowConnect] = React.useState(false);
  const lastStatus = React.useRef<string | undefined>(undefined);

  // Refresh project details (integration evidence, framework) when an assessment finishes.
  React.useEffect(() => {
    const status = history.data?.[0]?.status;
    if (lastStatus.current && status !== lastStatus.current) project.reload();
    lastStatus.current = status;
  }, [history.data, project]);

  if (project.error) return <PageBody><Notice tone="bad">{project.error.message}</Notice></PageBody>;
  const p = project.data;
  if (!p) return <PageBody><Loading /></PageBody>;

  async function remove() {
    if (!window.confirm(`Delete ${p!.name} and all of its assessment history? This cannot be undone.`)) return;
    try {
      await api(`/projects/${id}`, { method: "DELETE" });
      router.replace("/projects");
    } catch (e) {
      window.alert(e instanceof ApiError ? e.message : "Could not delete the project.");
    }
  }

  function connected(r: { integration: Integration; assessment_id: string }) {
    setShowConnect(false);
    project.setData({ ...p!, integration: r.integration });
    history.reload();
  }

  return (
    <>
      <PageHeader
        title={p.name}
        crumbs={[{ label: "Projects", href: "/projects" }, { label: p.name }]}
        meta={<>
          <a href={p.website_url} target="_blank" rel="noreferrer noopener" className="mono inline-flex items-center gap-1 hover:text-ink">
            {p.website_url} <ExternalLink className="size-3" />
          </a>
          {running && <StatusBadge status={running.status} />}
        </>}
        actions={<>
          {running ? (
            <Button variant="secondary" asChild><Link href={`/projects/${id}/assessments/${running.id}`}>View running assessment</Link></Button>
          ) : (
            <Button onClick={() => setRunOpen(true)}><Play /> Run assessment</Button>
          )}
          <Button variant="ghost" size="icon" onClick={remove} aria-label="Delete project"><Trash2 /></Button>
        </>}
      />
      <PageBody>
        <Section title="Project">
          <KeyValues columns={4} items={[
            ["Website", <span key="w" className="mono text-[12px]">{p.hostname}</span>],
            ["Framework", p.framework && p.framework !== "Unknown" ? p.framework : "Not identified"],
            ["Connected source", <SourceLabel key="s" integration={p.integration} />],
            ["Authorisation", `Confirmed ${formatDate(p.authorised_at)}`],
          ]} />
        </Section>

        <Section
          title="Source code"
          description="Optional. Enables route, database and static security analysis."
          actions={p.integration && !showConnect ? <Button variant="secondary" size="sm" onClick={() => setShowConnect(true)}>Replace source</Button> : null}
        >
          {p.integration && !showConnect ? (
            <MatchPanel project={p} onDecided={(integration) => project.setData({ ...p, integration })} />
          ) : (
            <ConnectSource projectId={p.id} onConnected={connected} />
          )}
        </Section>

        <Section title="Detected technologies" description={latestDone ? `From the assessment on ${formatDate(latestDone.created_at)}.` : undefined}>
          {latestDone ? (techs.data ? <TechnologiesTable technologies={techs.data} /> : <Loading />) : (
            <p className="text-[13px] text-muted">Available when the first assessment finishes.</p>
          )}
        </Section>

        <Section title="Assessment history" description="The five most recent assessments are kept. Older ones are removed automatically.">
          {history.data ? <AssessmentsTable assessments={history.data} /> : <Loading />}
        </Section>

        <Section title="Findings" description={latestDone ? "From the latest finished assessment." : undefined}
          actions={latestDone ? <Link href={`/projects/${id}/assessments/${latestDone.id}?tab=findings`} className="text-[12.5px] text-accent hover:underline">Open assessment</Link> : null}>
          {latestDone ? (findings.data ? <FindingsList findings={findings.data} /> : <Loading />) : (
            <p className="text-[13px] text-muted">No finished assessment yet.</p>
          )}
        </Section>
      </PageBody>
      <RunDialog open={runOpen} onOpenChange={setRunOpen} project={p} onStarted={(aid) => router.push(`/projects/${id}/assessments/${aid}`)} />
    </>
  );
}

function MatchPanel({ project, onDecided }: { project: Project; onDecided: (i: Integration) => void }) {
  const integration = project.integration!;
  const [pending, setPending] = React.useState(false);
  const evidence = integration.match_evidence ?? [];
  const matching = evidence.filter((e) => e.matches_target);
  async function decide(matches: boolean) {
    setPending(true);
    try {
      onDecided(await api<Integration>(`/projects/${project.id}/integrations/match`, { method: "POST", json: { matches } }));
    } finally {
      setPending(false);
    }
  }
  return (
    <div className="rounded-md border border-line bg-surface">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <SourceLabel integration={integration} />
        <span className="text-[12.5px] text-muted">
          {integration.match_status === "confirmed" && "You confirmed this repository belongs to the website."}
          {integration.match_status === "rejected" && "You indicated this repository is not the website's source."}
          {integration.match_status === "pending" && (evidence.length ? "Awaiting your confirmation" : "Matching evidence appears after analysis")}
        </span>
      </div>
      {evidence.length > 0 && (
        <div className="px-4 py-3">
          <p className="text-[12.5px] font-medium text-ink-2">
            {matching.length ? `${matching.length} reference(s) to ${project.hostname} found in the repository` : `No direct references to ${project.hostname} were found`}
          </p>
          <ul className="mt-2 space-y-1 text-[12.5px]">
            {evidence.slice(0, 8).map((e, i) => (
              <li key={i} className="flex gap-2">
                <span className={e.matches_target ? "text-ok" : "text-faint"}>{e.matches_target ? "●" : "○"}</span>
                <span className="text-ink-2">{e.detail}</span>
              </li>
            ))}
          </ul>
          {integration.match_status === "pending" && (
            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-line pt-3">
              <span className="text-[13px] font-medium">Does this repository contain the source code for the website you submitted?</span>
              <Button size="sm" onClick={() => decide(true)} disabled={pending}>Yes, it does</Button>
              <Button size="sm" variant="secondary" onClick={() => decide(false)} disabled={pending}>No</Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function RunDialog({
  open, onOpenChange, project, onStarted,
}: { open: boolean; onOpenChange: (v: boolean) => void; project: Project; onStarted: (id: string) => void }) {
  const [error, setError] = React.useState<string | null>(null);
  const [pending, setPending] = React.useState(false);
  const kind = project.integration?.kind;
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setPending(true);
    setError(null);
    try {
      const r = await api<{ assessment_id: string }>(`/projects/${project.id}/assessments`, {
        method: "POST",
        json: { include_source: form.get("include_source") !== null, token: form.get("token") || null },
      });
      onOpenChange(false);
      onStarted(r.assessment_id);
    } catch (err) {
      setError(err instanceof ApiError ? Object.values(err.details)[0] ?? err.message : "Could not start the assessment.");
    } finally {
      setPending(false);
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle>Run a new assessment</DialogTitle>
        <DialogDescription>Website discovery always runs. Source analysis runs when a source is available.</DialogDescription>
        <form onSubmit={submit} className="mt-4 space-y-4">
          {error && <Notice tone="bad">{error}</Notice>}
          {kind && kind !== "zip" && (
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" name="include_source" defaultChecked className="size-4 accent-[#1a1a18]" /> Include source analysis
            </label>
          )}
          {kind === "zip" && <Notice>Uploaded archives are deleted after analysis. Upload the ZIP again on the project page to include source code.</Notice>}
          {kind === "github_private" && (
            <div className="space-y-1.5">
              <Label htmlFor="run-token">Access token for {project.integration?.repo_owner}/{project.integration?.repo_name}</Label>
              <Input id="run-token" name="token" type="password" autoComplete="off" placeholder="github_pat_…" />
              <p className="text-[12px] text-muted">Tokens are never stored, so they are needed for each assessment. Leave empty to skip source analysis.</p>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={pending}>{pending ? "Starting…" : "Start assessment"}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
