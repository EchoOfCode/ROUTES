"use client";

import { ArrowRight, CheckCircle2, Globe, Info } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { ConnectSource } from "@/components/app/connect-source";
import { Notice, PageBody, PageHeader } from "@/components/app/layout-parts";
import { StatusBadge } from "@/components/app/status";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useApi } from "@/hooks/use-api";
import { ACTIVE_STATUSES, api, ApiError, type Assessment, type Integration, type Project } from "@/lib/api";

const STATEMENT = "I confirm that I own this website or have permission to assess it.";

export default function NewProjectPage() {
  const [created, setCreated] = React.useState<{ project: Project; assessment_id: string } | null>(null);
  const [connected, setConnected] = React.useState<Integration | null>(null);

  return (
    <>
      <PageHeader title="New project" crumbs={[{ label: "Projects", href: "/projects" }, { label: "New project" }]} />
      <PageBody className="max-w-[760px]">
        <Step n={1} title="Website" done={!!created}>
          {created ? <CreatedSummary project={created.project} /> : <UrlForm onCreated={setCreated} />}
        </Step>
        {created && (
          <>
            <Step n={2} title="Discovery" done={false}>
              <DiscoveryStatus assessmentId={created.assessment_id} projectId={created.project.id} />
            </Step>
            <Step n={3} title="Source code" optional done={!!connected}>
              {connected ? (
                <Notice tone="ok" icon={CheckCircle2} title="Source connected">
                  Analysis has been queued alongside website discovery. You can follow both on the project page.
                </Notice>
              ) : (
                <>
                  <p className="mb-3 text-[13px] text-muted">
                    Connect the application&apos;s source to map its routes, database queries and configuration, and to run static
                    security rules. You can skip this and add it later.
                  </p>
                  <ConnectSource projectId={created.project.id} onConnected={(r) => setConnected(r.integration)} />
                </>
              )}
            </Step>
            <div className="ml-10 flex gap-2">
              <Button asChild>
                <Link href={`/projects/${created.project.id}`}>Go to project <ArrowRight /></Link>
              </Button>
              <Button variant="secondary" asChild>
                <Link href={`/projects/${created.project.id}/assessments/${created.assessment_id}`}>Follow progress</Link>
              </Button>
            </div>
          </>
        )}
      </PageBody>
    </>
  );
}

function Step({ n, title, optional, done, children }: { n: number; title: string; optional?: boolean; done: boolean; children: React.ReactNode }) {
  return (
    <section className="relative mb-8 pl-10">
      <span className={`absolute left-0 top-0 flex size-6 items-center justify-center rounded-full border text-[12px] font-semibold ${done ? "border-ink bg-ink text-white" : "border-line-strong bg-surface text-ink-2"}`}>
        {n}
      </span>
      <h2 className="mb-3 text-[14px] font-semibold leading-6">
        {title} {optional && <span className="ml-1 text-[12px] font-normal text-faint">Optional</span>}
      </h2>
      {children}
    </section>
  );
}

function UrlForm({ onCreated }: { onCreated: (r: { project: Project; assessment_id: string }) => void }) {
  const [url, setUrl] = React.useState("");
  const [name, setName] = React.useState("");
  const [authorised, setAuthorised] = React.useState(false);
  const [error, setError] = React.useState<ApiError | null>(null);
  const [pending, setPending] = React.useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      onCreated(await api("/projects", { method: "POST", json: { website_url: url, name: name || null, authorised } }));
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "network", "Could not reach ROUTES."));
      setPending(false);
    }
  }

  const urlError = error?.details?.website_url;
  return (
    <form onSubmit={submit} className="space-y-5 rounded-md border border-line bg-surface p-5">
      <div className="space-y-1.5">
        <Label htmlFor="website_url" className="text-[14px] font-semibold text-ink">Which website would you like ROUTES to assess?</Label>
        <div className="relative">
          <Globe className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
          <Input
            id="website_url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com"
            className="h-10 pl-9 text-[14px]" autoFocus required aria-invalid={!!urlError} inputMode="url"
          />
        </div>
        {urlError ? <p className="text-[12px] text-bad">{urlError}</p> : (
          <p className="text-[12px] text-muted">ROUTES stays on this exact hostname. Subdomains and external sites are not crawled.</p>
        )}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="name">Project name <span className="font-normal text-faint">(optional)</span></Label>
        <Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Defaults to the hostname" maxLength={120} />
      </div>
      <label className="flex cursor-pointer gap-3 rounded-md border border-line bg-sunken/50 p-3.5">
        <Checkbox checked={authorised} onCheckedChange={(v) => setAuthorised(v === true)} className="mt-0.5" aria-describedby="auth-help" />
        <span>
          <span className="block text-[13px] font-medium text-ink">{STATEMENT}</span>
          <span id="auth-help" className="mt-0.5 block text-[12px] text-muted">
            Discovery only reads publicly available pages with ordinary GET requests. It does not submit forms, sign in or attempt attacks.
          </span>
        </span>
      </label>
      {error && !urlError && <Notice tone="bad">{error.details.authorised ?? error.message}</Notice>}
      <Button type="submit" size="lg" disabled={pending || !authorised || !url.trim()}>
        {pending ? "Starting…" : "Start discovery"}
      </Button>
    </form>
  );
}

function CreatedSummary({ project }: { project: Project }) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-line bg-surface px-4 py-3">
      <Globe className="size-4 text-faint" />
      <div className="min-w-0">
        <p className="text-[13px] font-medium">{project.name}</p>
        <p className="mono truncate text-[12px] text-muted">{project.website_url}</p>
      </div>
      <span className="ml-auto text-[12px] text-muted">Authorisation confirmed</span>
    </div>
  );
}

function DiscoveryStatus({ assessmentId, projectId }: { assessmentId: string; projectId: string }) {
  const { data } = useApi<Assessment>(`/assessments/${assessmentId}`, {
    poll: (a) => ACTIVE_STATUSES.includes(a.status),
    intervalMs: 2000,
  });
  const job = data?.jobs.find((j) => j.kind === "discovery");
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 rounded-md border border-line bg-surface px-4 py-3 text-[13px]">
        {data ? <StatusBadge status={data.status} /> : <span className="text-muted">Starting…</span>}
        <span className="text-muted">{job?.message || "Discovery runs in an isolated sandbox. This page updates automatically."}</span>
        <Link href={`/projects/${projectId}/assessments/${assessmentId}`} className="ml-auto text-[12.5px] text-accent hover:underline">Details</Link>
      </div>
      {data?.manifest_detected && (
        <Notice tone="accent" icon={Info} title="This website declares ROUTES integration">
          It publishes <code className="mono">/.well-known/routes.json</code>. Connect its GitHub repository below so the source can be analysed too.
          The manifest is treated as information only; it does not change how discovery works.
        </Notice>
      )}
    </div>
  );
}
