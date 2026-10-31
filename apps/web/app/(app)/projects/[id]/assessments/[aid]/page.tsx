"use client";

import { AlertTriangle, CheckCircle2, Info, Square } from "lucide-react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

import { FindingsList } from "@/components/app/findings-list";
import { Code, KeyValues, Loading, Notice, PageBody, PageHeader, Section } from "@/components/app/layout-parts";
import { ProgressPanel } from "@/components/app/progress-panel";
import { MethodTag, SeverityBreakdown, StatusBadge } from "@/components/app/status";
import { TechnologiesTable } from "@/components/app/technologies-table";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useApi } from "@/hooks/use-api";
import {
  ACTIVE_STATUSES, api, type Assessment, type Endpoint, type Finding, type Page, type SourceResult, type Technology,
} from "@/lib/api";
import { duration, formatDate, pathOf } from "@/lib/utils";

const ORIGIN: Record<Endpoint["origin"], string> = {
  form: "Form", link_query: "Link with parameters", js_reference: "JavaScript reference", openapi: "OpenAPI", source_route: "Source route",
};

export default function AssessmentPage() {
  const { id, aid } = useParams<{ id: string; aid: string }>();
  const params = useSearchParams();
  const router = useRouter();
  const tab = params.get("tab") ?? "overview";
  const { data: a, error, reload } = useApi<Assessment>(`/assessments/${aid}`, {
    poll: (x) => ACTIVE_STATUSES.includes(x.status),
    intervalMs: 2000,
  });
  const active = a ? ACTIVE_STATUSES.includes(a.status) : false;
  // Result tables load once the assessment is no longer running (and refresh when it finishes).
  const resultsKey = a && !active ? a.status : null;
  const pages = useApi<Page[]>(resultsKey ? `/assessments/${aid}/pages` : null);
  const endpoints = useApi<Endpoint[]>(resultsKey ? `/assessments/${aid}/endpoints` : null);
  const techs = useApi<Technology[]>(resultsKey ? `/assessments/${aid}/technologies` : null);
  const findings = useApi<Finding[]>(resultsKey ? `/assessments/${aid}/findings` : null);
  const source = useApi<SourceResult | null>(resultsKey && a?.source_kind ? `/assessments/${aid}/source` : null);
  const [cancelling, setCancelling] = React.useState(false);

  if (error) return <PageBody><Notice tone="bad">{error.message}</Notice></PageBody>;
  if (!a) return <PageBody><Loading /></PageBody>;

  async function cancel() {
    setCancelling(true);
    try { await api(`/assessments/${aid}/cancel`, { method: "POST" }); await reload(); } finally { setCancelling(false); }
  }

  const s = a.discovery_summary;
  const forms = (endpoints.data ?? []).filter((e) => e.origin === "form");
  const apiEndpoints = (endpoints.data ?? []).filter((e) => e.origin !== "form");

  return (
    <>
      <PageHeader
        title={`Assessment of ${a.project_name}`}
        crumbs={[{ label: "Projects", href: "/projects" }, { label: a.project_name, href: `/projects/${id}` }, { label: "Assessment" }]}
        meta={<>
          <StatusBadge status={a.status} />
          <span>Started {formatDate(a.started_at ?? a.created_at)}</span>
          <span>Duration {duration(a.started_at, a.finished_at)}</span>
          <span className="mono">{a.target_url}</span>
        </>}
        actions={active ? <Button variant="danger" onClick={cancel} disabled={cancelling}><Square /> Cancel</Button> : null}
      />
      <PageBody>
        {active && (
          <Section title="Progress" description="Each step runs inside a disposable, network-restricted sandbox.">
            <ProgressPanel assessment={a} />
          </Section>
        )}
        {!active && <Outcome a={a} />}
        {!active && (
          <Tabs value={tab} onValueChange={(v) => router.replace(`?tab=${v}`, { scroll: false })}>
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="technologies">Technologies <Count n={a.counts.technologies} /></TabsTrigger>
              <TabsTrigger value="pages">Pages <Count n={a.counts.pages} /></TabsTrigger>
              <TabsTrigger value="forms">Forms <Count n={a.counts.forms} /></TabsTrigger>
              <TabsTrigger value="endpoints">API endpoints <Count n={a.counts.endpoints} /></TabsTrigger>
              <TabsTrigger value="database">Database interactions</TabsTrigger>
              <TabsTrigger value="findings">Security findings <Count n={a.counts.findings} /></TabsTrigger>
              <TabsTrigger value="source">Source repository</TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <Section title="Detected stack" description="Inferred from evidence on the website. Unknown means no reliable evidence was found.">
                <KeyValues columns={4} items={[
                  ["Framework", s.stack?.framework ?? "Unknown"],
                  ["Language", s.stack?.language ?? "Unknown"],
                  ["Runtime", s.stack?.runtime ?? "Unknown"],
                  ["Database", s.stack?.database ?? "Unknown"],
                ]} />
              </Section>
              <Section title="Discovery summary">
                <KeyValues columns={3} items={[
                  ["Pages inspected", s.pages_total !== undefined ? `${s.pages_inspected} of ${s.pages_total}${s.page_limit_reached ? ` (limit of ${s.page_limit} reached)` : ""}` : "—"],
                  ["Rendered with a browser", s.rendered_pages ?? 0],
                  ["Forms", s.forms_count ?? 0],
                  ["Endpoints", a.counts.endpoints],
                  ["Script files", s.scripts_count ?? 0],
                  ["Findings", a.counts.findings ? <SeverityBreakdown counts={a.severity_counts} /> : "None"],
                  ["robots.txt", s.robots ? (s.robots.found ? `${s.robots.disallow_rules} disallow rule(s)` : "Not found") : "—"],
                  ["Sitemap URLs", s.sitemap_urls ?? 0],
                  ["OpenAPI specification", s.openapi?.length ? s.openapi.map((o) => o.title ?? pathOf(o.url)).join(", ") : "Not found"],
                  ["ROUTES integration", a.manifest_detected ? (a.manifest_data?.valid ? "Declared (valid manifest)" : "Manifest present but invalid") : "Not declared"],
                  ["Sign-in pages", s.login_pages?.length ? s.login_pages.map(pathOf).join(", ") : "None found"],
                  ["Registration pages", s.registration_pages?.length ? s.registration_pages.map(pathOf).join(", ") : "None found"],
                ]} />
              </Section>
              {s.external_hosts && s.external_hosts.length > 0 && (
                <Section title="External hosts referenced" description="Recorded only. ROUTES does not crawl hosts other than the submitted one.">
                  <p className="mono text-[12px] leading-6 text-ink-2">{s.external_hosts.join("  ·  ")}</p>
                </Section>
              )}
              {s.network && (
                <Section title="Network gateway" description="Every outbound request from the discovery sandbox passed through the ROUTES gateway.">
                  <p className="text-[13px] text-ink-2">
                    {s.network.allowed ?? 0} connection(s) allowed, {s.network.denied ?? 0} refused
                    {s.network.denied_reasons?.length ? <> ({s.network.denied_reasons.join(", ")})</> : null}.
                  </p>
                </Section>
              )}
            </TabsContent>

            <TabsContent value="technologies">
              {techs.data ? <TechnologiesTable technologies={techs.data} /> : <Loading />}
            </TabsContent>

            <TabsContent value="pages">
              {!pages.data ? <Loading /> : (
                <Table>
                  <THead><TR><TH>Page</TH><TH>Status</TH><TH>Title</TH><TH className="text-right">Links</TH><TH className="text-right">Forms</TH><TH>Notes</TH></TR></THead>
                  <TBody>
                    {pages.data.map((p) => (
                      <TR key={p.id}>
                        <TD className="mono max-w-[320px] break-all text-[12px] text-ink">{pathOf(p.url)}</TD>
                        <TD className="tabular">{p.status_code ?? "—"}</TD>
                        <TD className="max-w-[260px] truncate">{p.title ?? <span className="text-faint">—</span>}</TD>
                        <TD className="tabular text-right">{p.links_count}</TD>
                        <TD className="tabular text-right">{p.forms_count}</TD>
                        <TD className="text-[12px]">
                          {p.error ? <span className="text-warn">{p.error}</span> : (
                            <span className="text-muted">{[p.rendered && "Rendered with JavaScript", p.is_login && "Sign-in page", p.is_registration && "Registration page"].filter(Boolean).join(" · ") || "—"}</span>
                          )}
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="forms">
              {!endpoints.data ? <Loading /> : forms.length === 0 ? <Empty text="No forms were found on the inspected pages." /> : (
                <Table>
                  <THead><TR><TH>Found on</TH><TH>Submits to</TH><TH>Fields</TH></TR></THead>
                  <TBody>
                    {forms.map((f) => {
                      const fields = (f.details.fields as { name: string | null; type: string; required: boolean }[] | undefined) ?? [];
                      return (
                        <TR key={f.id}>
                          <TD className="mono text-[12px]">{f.page_url ? pathOf(f.page_url) : "—"}</TD>
                          <TD><span className="inline-flex items-center gap-1.5"><MethodTag method={f.method} /><span className="mono text-[12px]">{f.path}</span></span></TD>
                          <TD className="text-[12px]">
                            {fields.length === 0 ? "—" : fields.map((x, i) => (
                              <span key={i} className="mr-2 inline-block"><span className="mono text-ink">{x.name ?? "(unnamed)"}</span> <span className="text-muted">{x.type}{x.required ? ", required" : ""}</span></span>
                            ))}
                          </TD>
                        </TR>
                      );
                    })}
                  </TBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="endpoints">
              {!endpoints.data ? <Loading /> : apiEndpoints.length === 0 ? <Empty text="No endpoints were identified." /> : (
                <Table>
                  <THead><TR><TH>Method</TH><TH>Path</TH><TH>Parameters</TH><TH>How it was found</TH></TR></THead>
                  <TBody>
                    {apiEndpoints.map((e) => (
                      <TR key={e.id}>
                        <TD><MethodTag method={e.method} /></TD>
                        <TD className="mono break-all text-[12px] text-ink">{e.path}</TD>
                        <TD className="mono text-[12px]">{e.parameters.length ? e.parameters.join(", ") : <span className="text-faint">—</span>}</TD>
                        <TD className="text-[12px]">
                          <span className="text-ink-2">{ORIGIN[e.origin]}</span>
                          <span className="block text-muted">{e.evidence}</span>
                          {typeof e.details.source_file === "string" && <span className="block text-ok">Matches source: <span className="mono">{e.details.source_file}</span></span>}
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="database">
              {!a.source_kind ? <Empty text="Database interactions come from source analysis. Connect a repository or upload a ZIP to see them." /> :
                !source.data ? (source.loading ? <Loading /> : <Empty text="Source analysis did not produce results." />) :
                source.data.db_interactions.length === 0 ? <Empty text="No supported database query calls were found." /> : (
                  <Table>
                    <THead><TR><TH>Location</TH><TH>Endpoint</TH><TH>Client</TH><TH>Query built by</TH><TH>User input</TH></TR></THead>
                    <TBody>
                      {source.data.db_interactions.map((d, i) => (
                        <TR key={i}>
                          <TD className="mono text-[12px] text-ink">{d.file}:{d.line}</TD>
                          <TD>{d.endpoint ? <span className="inline-flex items-center gap-1.5"><MethodTag method={d.method === "ANY" ? null : d.method} /><span className="mono text-[12px]">{d.endpoint}</span></span> : "—"}</TD>
                          <TD className="mono text-[12px]">{d.client}</TD>
                          <TD><Construction value={d.query_construction} /></TD>
                          <TD className="text-[12.5px]">{d.uses_user_input ? <span className="font-medium text-bad">Reaches query</span> : <span className="text-muted">Not traced</span>}</TD>
                        </TR>
                      ))}
                    </TBody>
                  </Table>
                )}
            </TabsContent>

            <TabsContent value="findings">
              <Notice tone="neutral" icon={Info} className="mb-4">
                Findings in this build come from static analysis. <strong className="font-semibold">Potential</strong> means a suspicious pattern with a traced
                data flow; <strong className="font-semibold">inconclusive</strong> means the pattern was found but the flow could not be established.
                Nothing here has been reproduced against the running site.
              </Notice>
              {findings.data ? <FindingsList findings={findings.data} /> : <Loading />}
            </TabsContent>

            <TabsContent value="source">
              <SourceTab a={a} source={source.data} loading={source.loading} />
            </TabsContent>
          </Tabs>
        )}
      </PageBody>
    </>
  );
}

function Outcome({ a }: { a: Assessment }) {
  if (a.status === "completed") {
    return <Notice tone="ok" icon={CheckCircle2} className="mb-7" title="Assessment completed">All requested steps finished successfully.</Notice>;
  }
  if (a.status === "partially_completed") {
    return <Notice tone="warn" className="mb-7" title="Partially completed">{a.error ?? "Some steps did not finish."} Results from the steps that succeeded are shown below.</Notice>;
  }
  if (a.status === "failed") {
    return <Notice tone="bad" icon={AlertTriangle} className="mb-7" title="Assessment failed">{a.error ?? "The assessment could not complete."}</Notice>;
  }
  if (a.status === "cancelled") return <Notice className="mb-7" title="Cancelled">This assessment was cancelled; partial results may be missing.</Notice>;
  return null;
}

function Count({ n }: { n: number }) {
  return <span className="tabular rounded-sm bg-sunken px-1 text-[11px] text-muted">{n}</span>;
}

function Empty({ text }: { text: string }) {
  return <p className="rounded-md border border-line bg-surface px-4 py-6 text-[13px] text-muted">{text}</p>;
}

function Construction({ value }: { value: string }) {
  const label: Record<string, [string, string]> = {
    parameterised: ["Parameters ($1, $2…)", "text-ok"],
    constant: ["Constant SQL", "text-ok"],
    interpolated: ["Template interpolation", "text-warn"],
    concatenated: ["String concatenation", "text-warn"],
    direct: ["Value used as SQL", "text-bad"],
    tagged_template: ["Tagged template", "text-muted"],
    dynamic: ["Built elsewhere", "text-muted"],
    parameter: ["Function argument", "text-muted"],
  };
  const [text, cls] = label[value] ?? [value, "text-muted"];
  return <span className={`text-[12.5px] ${cls}`}>{text}</span>;
}

function SourceTab({ a, source, loading }: { a: Assessment; source: SourceResult | null; loading: boolean }) {
  const job = a.jobs.find((j) => j.kind === "source");
  if (!a.source_kind) return <Empty text="No source code was included in this assessment." />;
  if (loading) return <Loading />;
  if (!source) return <Notice tone="bad" title="Source analysis did not complete">{job?.error ?? "No results were produced."}</Notice>;
  const p = source.profile;
  const langs = Object.entries(p.languages ?? {}).sort((x, y) => y[1] - x[1]);
  return (
    <>
      <Notice
        tone={source.support_status === "supported" ? "ok" : source.support_status === "partial" ? "warn" : "neutral"}
        className="mb-6"
        title={source.support_status === "supported" ? "Fully supported stack" : source.support_status === "partial" ? "Partially supported" : "Not supported for detailed analysis"}
      >
        {source.support_reason}
      </Notice>
      <Section title="Repository profile">
        <KeyValues columns={4} items={[
          ["Source", <span key="s" className="mono text-[12px]">{a.source_label}</span>],
          ["Framework", `${source.framework}${p.framework_version ? ` ${p.framework_version}` : ""}`],
          ["Runtime", source.runtime],
          ["Router", p.router ?? "—"],
          ["Languages", langs.length ? langs.map(([l, n]) => `${l} (${n})`).join(", ") : "—"],
          ["Package manager", p.package_manager ?? "—"],
          ["Database libraries", p.database_libraries?.length ? p.database_libraries.join(", ") : "None found"],
          ["Files analysed", `${p.analysed_files ?? 0} of ${p.total_files ?? 0}`],
        ]} />
      </Section>
      {source.warnings.length > 0 && (
        <Section title="Analysis notes">
          <ul className="list-disc space-y-1 pl-5 text-[13px] text-ink-2">{source.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
        </Section>
      )}
      <Section title="Routes found in source" description="Read from route handler code, not inferred from file names alone.">
        {source.routes.length === 0 ? <Empty text="No API routes were found." /> : (
          <Table>
            <THead><TR><TH>Path</TH><TH>Methods</TH><TH>Router</TH><TH>File</TH></TR></THead>
            <TBody>
              {source.routes.map((r) => (
                <TR key={r.file}>
                  <TD className="mono text-[12px] text-ink">{r.path}</TD>
                  <TD><span className="inline-flex gap-1">{r.methods.map((m) => <MethodTag key={m} method={m} />)}</span></TD>
                  <TD className="text-muted">{r.router === "app" ? "App Router" : "Pages Router"}</TD>
                  <TD className="mono text-[12px] text-muted">{r.file}{r.line ? `:${r.line}` : ""}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Section>
      <div className="grid gap-x-10 lg:grid-cols-2">
        <Section title="Configuration references" description="Names only. Values are never read or stored.">
          {source.env_var_names.length === 0 ? <Empty text="No environment variables referenced." /> : (
            <p className="flex flex-wrap gap-1.5">{source.env_var_names.map((n) => <Code key={n}>{n}</Code>)}</p>
          )}
        </Section>
        <Section title="Dependencies" description="Inventory only; no vulnerability (CVE) scanning in this build.">
          <p className="text-[12.5px] leading-6 text-ink-2">
            {(p.dependencies ?? []).slice(0, 60).map((d) => `${d.name}${d.version ? ` ${d.version}` : ""}`).join(" · ") || "None declared"}
            {(p.dependencies?.length ?? 0) > 60 && <span className="text-muted"> … and {(p.dependencies?.length ?? 0) - 60} more</span>}
          </p>
        </Section>
      </div>
    </>
  );
}
