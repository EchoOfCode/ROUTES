import { AlertTriangle, ChevronRight, type LucideIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { cn } from "@/lib/utils";

export type Crumb = { label: string; href?: string };

export function PageHeader({
  title, description, crumbs, actions, meta,
}: { title: React.ReactNode; description?: React.ReactNode; crumbs?: Crumb[]; actions?: React.ReactNode; meta?: React.ReactNode }) {
  return (
    <header className="border-b border-line bg-surface">
      <div className="mx-auto max-w-[1180px] px-8 pb-5 pt-6">
        {crumbs && crumbs.length > 0 && (
          <nav className="mb-2 flex items-center gap-1 text-[12.5px] text-muted" aria-label="Breadcrumb">
            {crumbs.map((c, i) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="size-3 text-faint" />}
                {c.href ? <Link href={c.href} className="hover:text-ink">{c.label}</Link> : <span>{c.label}</span>}
              </span>
            ))}
          </nav>
        )}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="truncate text-[21px] font-semibold tracking-[-0.01em] text-ink">{title}</h1>
            {description && <p className="mt-1 max-w-2xl text-[13px] text-muted">{description}</p>}
            {meta && <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px] text-muted">{meta}</div>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </div>
      </div>
    </header>
  );
}

export function PageBody({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("mx-auto max-w-[1180px] px-8 py-7", className)}>{children}</div>;
}

export function Section({
  title, description, actions, children, className,
}: { title: string; description?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("mb-9", className)}>
      <div className="mb-3 flex items-end justify-between gap-4">
        <div>
          <h2 className="text-[13.5px] font-semibold text-ink">{title}</h2>
          {description && <p className="mt-0.5 text-[12.5px] text-muted">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function KeyValues({ items, columns = 3 }: { items: [string, React.ReactNode][]; columns?: 2 | 3 | 4 }) {
  const cols = { 2: "sm:grid-cols-2", 3: "sm:grid-cols-3", 4: "sm:grid-cols-4" }[columns];
  return (
    <dl className={cn("grid grid-cols-1 gap-px overflow-hidden rounded-md border border-line bg-line", cols)}>
      {items.map(([k, v]) => (
        <div key={k} className="bg-surface px-4 py-3">
          <dt className="text-[11.5px] font-medium uppercase tracking-[0.04em] text-muted">{k}</dt>
          <dd className="mt-1 break-words text-[13px] text-ink">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyState({
  icon: Icon, title, children, action,
}: { icon: LucideIcon; title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-line-strong bg-surface px-6 py-10">
      <div className="mx-auto flex max-w-md flex-col items-start gap-3">
        <Icon className="size-5 text-faint" strokeWidth={1.75} />
        <div>
          <p className="text-[14px] font-semibold text-ink">{title}</p>
          {children && <div className="mt-1 text-[13px] text-muted">{children}</div>}
        </div>
        {action}
      </div>
    </div>
  );
}

export function Notice({
  tone = "neutral", title, children, icon: Icon = AlertTriangle, className,
}: { tone?: "neutral" | "warn" | "bad" | "accent" | "ok"; title?: string; children?: React.ReactNode; icon?: LucideIcon; className?: string }) {
  const tones = {
    neutral: "border-line bg-sunken/60 text-ink-2",
    warn: "border-[#f2d7b6] bg-[#fdf8f1] text-[#7a3a06]",
    bad: "border-[#f0c6c2] bg-[#fdf4f3] text-[#8a1c13]",
    accent: "border-[#cfd9f3] bg-accent-soft text-[#1e3a86]",
    ok: "border-[#bfe3cf] bg-[#f1faf5] text-[#05603a]",
  };
  return (
    <div className={cn("flex gap-2.5 rounded-md border px-3.5 py-3 text-[13px]", tones[tone], className)}>
      <Icon className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={cn(title && "mt-0.5", "opacity-90")}>{children}</div>}
      </div>
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <p className="py-10 text-[13px] text-muted">{label}</p>;
}

export function Code({ children }: { children: React.ReactNode }) {
  return <code className="mono rounded-sm bg-sunken px-1 py-px text-[12px] text-ink-2">{children}</code>;
}
