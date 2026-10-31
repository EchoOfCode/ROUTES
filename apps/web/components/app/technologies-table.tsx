"use client";

import * as React from "react";

import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import type { Technology } from "@/lib/api";

const CATEGORY: Record<string, string> = {
  framework: "Framework", ui_library: "UI library", cms: "CMS", web_server: "Web server", hosting: "Hosting",
  cdn: "CDN", language: "Language", analytics: "Analytics", database: "Database", database_library: "Database library",
  api_specification: "API specification", javascript_library: "JavaScript library", security: "Security",
  payments: "Payments", ecommerce: "E-commerce", website_builder: "Website builder",
};

export function TechnologiesTable({ technologies }: { technologies: Technology[] }) {
  const [open, setOpen] = React.useState<string | null>(null);
  if (technologies.length === 0) {
    return <p className="rounded-md border border-line bg-surface px-4 py-6 text-[13px] text-muted">No technologies identified yet.</p>;
  }
  return (
    <Table>
      <THead>
        <TR><TH>Technology</TH><TH>Category</TH><TH>Confidence</TH><TH>Found in</TH><TH>Evidence</TH></TR>
      </THead>
      <TBody>
        {technologies.map((t) => (
          <TR key={t.id}>
            <TD className="font-medium text-ink">{t.name}{t.version && <span className="mono ml-1.5 text-[11.5px] font-normal text-muted">{t.version}</span>}</TD>
            <TD>{CATEGORY[t.category] ?? t.category}</TD>
            <TD><Confidence value={t.confidence} /></TD>
            <TD className="text-muted">{t.source === "repository" ? "Source code" : "Website"}</TD>
            <TD className="max-w-[420px]">
              <button className="text-left text-[12.5px] text-ink-2 hover:text-ink" onClick={() => setOpen(open === t.id ? null : t.id)}>
                {open === t.id ? (
                  <ul className="space-y-1">{t.evidence.map((e, i) => <li key={i} className="mono break-all text-[11.5px]">{e}</li>)}</ul>
                ) : (
                  <span>{t.evidence[0] ?? "—"}{t.evidence.length > 1 && <span className="text-accent"> +{t.evidence.length - 1} more</span>}</span>
                )}
              </button>
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

export function Confidence({ value }: { value: string }) {
  const filled = value === "high" ? 3 : value === "medium" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] capitalize">
      <span className="flex gap-0.5">{[0, 1, 2].map((i) => <span key={i} className={`h-2.5 w-1 rounded-[1px] ${i < filled ? "bg-ink-2" : "bg-line-strong"}`} />)}</span>
      {value}
    </span>
  );
}
