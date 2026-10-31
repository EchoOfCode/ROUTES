"""Renderables for stored results. Everything shown comes from the database;
nothing is invented to fill space, and empty states say so plainly."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from rich import box
from rich.console import Group, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from routes_storage.models import as_utc

from routes_cli.renderers.theme import Glyphs, severity_text, status_text
from routes_cli.stages import STEP_TITLES

WHY_IT_MATTERS = {
    "SQL Injection": "If someone can change the text of a database query, they may be able to read, change or delete "
                     "data they should not have access to, such as other users' records.",
    "Hardcoded Secret": "Anyone who can read the code (collaborators, a leaked repository, a public bundle) can use a "
                        "credential written in it. Credentials in code are also hard to rotate.",
    "Unsafe Command Execution": "If user input reaches a shell command, an attacker may be able to run their own "
                                "commands on your server.",
    "Unsafe Code Execution": "Evaluating dynamic text as code lets whoever controls that text run code inside your "
                             "application.",
    "Cross-Site Scripting": "Inserting unescaped HTML lets injected scripts run in your users' browsers, where they "
                            "can act as the user or steal their session.",
    "Insecure Configuration": "A weakened default (TLS checks, cookies, CORS) removes a protection that normally "
                              "stops a whole class of attacks.",
    "Weak Cryptography": "Older hash functions can be reversed or forged cheaply, so they should not protect "
                         "passwords, tokens or signatures.",
}

LIMITATIONS = {
    "potential": "Static evidence only. ROUTES read the code but did not run it or send any attack to your site, so "
                 "this is not confirmed. Check the code path before acting, and treat it as real until shown otherwise.",
    "inconclusive": "ROUTES found the pattern but could not trace where the data comes from. It may be safe; review "
                    "the callers of this code.",
    "confirmed": "Confirmed findings are not produced in this version of ROUTES.",
}


def local_time(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return as_utc(dt).astimezone().strftime(fmt) if dt else "-"


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    dt = as_utc(dt)
    secs = int((datetime.now(UTC) - dt).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return local_time(dt, "%Y-%m-%d")


def _duration(a) -> str:
    if not a.started_at or not a.finished_at:
        return "-"
    secs = int((a.finished_at - a.started_at).total_seconds())
    return f"{secs // 60}:{secs % 60:02d}"


def table(*columns: str, **kw) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style="label", border_style="faint", pad_edge=False, expand=False, **kw)
    for c in columns:
        t.add_column(c)
    return t


def empty(message: str) -> Text:
    return Text(message, style="muted")


# ---------------------------------------------------------------- findings
def severity_counts(findings) -> Counter:
    return Counter(f.severity for f in findings)


def findings_table(findings, g: Glyphs) -> RenderableType:
    if not findings:
        return empty("No findings in this assessment. That means the checks ROUTES ran found nothing, not that the "
                     "application is secure.")
    t = table("ID", "Vulnerability", "Severity", "Status", "Conf.", "Location")
    t.columns[0].style = "muted"
    t.columns[1].no_wrap = True
    t.columns[2].no_wrap = True
    t.columns[5].overflow = "fold"
    t.columns[5].min_width = 18
    for f in findings:
        where = f"{f.file}:{f.line}" if f.file else (f.endpoint or "-")
        t.add_row(f"{f.seq:02d}", escape(f.type), severity_text(f.severity, g), f.status.upper(),
                  f.confidence, escape(where))
    return t


def finding_detail(f, g: Glyphs) -> RenderableType:
    td = f.technical_details or {}

    def section(title: str, body: RenderableType) -> Group:
        return Group(Text(title, style="heading"), Padding(body, (0, 0, 1, 2)))

    head = Text.from_markup(f"[muted]#{f.seq:02d}[/]  [heading]{escape(f.title)}[/]\n"
                            f"{severity_text(f.severity, g)}  [muted]·[/]  {f.status.upper()}  [muted]·[/]  "
                            f"confidence {f.confidence}  [muted]·[/]  {escape(f.type)}")
    where = []
    if f.file:
        where.append(f"[path]{escape(f.file)}[/]" + (f"[muted]:{f.line}[/]" if f.line else ""))
    if f.endpoint:
        where.append(f"endpoint {escape((f.method or 'ANY') + ' ' + f.endpoint)}")
    parts = [head, Text(""),
             section("What is wrong", Text(f.plain_description)),
             section("Why it matters", Text(WHY_IT_MATTERS.get(f.type, "This pattern is commonly involved in "
                                                                       "security problems."))),
             section("Where", Text.from_markup("\n".join(where) or "[muted]No precise location.[/]")),
             section("What ROUTES detected", Text(f.evidence_summary))]
    flow = td.get("flow") or []
    if flow:
        lines = [f"{i}. {escape(str(step.get('description') if isinstance(step, dict) else step))}"
                 for i, step in enumerate(flow[:12], 1)]
        parts.append(section("Evidence (data flow)", Text.from_markup("\n".join(lines))))
    extra = [f"rule {escape(f.rule_id)}"] + ([f"{td['cwe']}"] if td.get("cwe") else [])
    if td.get("query_construction"):
        extra.append(f"query built by {escape(str(td['query_construction']))}")
    parts.append(section("Technical reference", Text(" · ".join(extra), style="muted")))
    parts.append(section("Suggested fix", Text(f.recommendation)))
    parts.append(section("Limitations of this result", Text(LIMITATIONS.get(f.status, LIMITATIONS["potential"]),
                                                             style="muted")))
    return Group(*parts)


# ----------------------------------------------------------------- history
def history_table(assessments, g: Glyphs) -> RenderableType:
    if not assessments:
        return empty("No assessments yet. Start one with /scan <url> or /analyze <source>.")
    t = table("Assessment", "Project", "Target", "Status", "Findings", "Started", "Took")
    for a in assessments:
        counts = severity_counts(a.findings)
        sev = "  ".join(f"[sev.{s}]{g.sev[s]} {counts[s]}[/]" for s in ("critical", "high", "medium", "low") if counts[s])
        target = a.target_url or a.source_label or "-"
        if a.target_url and a.source_label:
            target = f"{a.target_url} + {a.source_label}"
        t.add_row(f"[muted]{a.id[:8]}[/]", escape(a.project.name), escape(target[:60]), status_text(a.status),
                  sev or ("[muted]0[/]" if a.source_kind else "[muted]-[/]"), _ago(a.created_at), _duration(a))
    return t


def projects_table(projects, current: str, g: Glyphs) -> RenderableType:
    if not projects:
        return empty("No projects yet. Add one with: routes project add <path-or-repo> --name <name> [--url <website>]")
    t = table("", "Project", "Website", "Source", "Assessments", "Last")
    for p in projects:
        mark = f"[accent]{g.arrow}[/]" if p.name == current else ""
        kind = "registered" if p.registered else "[muted]one-off[/]"
        last = p.assessments[0] if p.assessments else None
        t.add_row(mark, f"{escape(p.name)}  [muted]{kind}[/]", escape(p.website_url or "-"),
                  escape(f"{p.source_kind}: {p.source_location}" if p.source_kind else "-")[:70],
                  str(len(p.assessments)), status_text(last.status) if last else "[muted]-[/]")
    return t


def project_detail(p, g: Glyphs) -> RenderableType:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="label")
    t.add_column()
    t.add_row("Project", f"[heading]{escape(p.display_name)}[/]  [muted]({escape(p.name)})[/]")
    t.add_row("Website", escape(p.website_url or "not set"))
    t.add_row("Permission", "confirmed " + local_time(p.authorised_at, "%Y-%m-%d") if p.authorised_at else "[muted]not confirmed[/]")
    t.add_row("Source", escape(f"{p.source_kind}: {p.source_location}" + (f" @ {p.source_ref}" if p.source_ref else ""))
              if p.source_kind else "[muted]none[/]")
    t.add_row("Repository match", {"confirmed": "[ok]confirmed by you[/]", "rejected": "[muted]not the same app[/]"}
              .get(p.match_status, "[muted]not confirmed[/]"))
    t.add_row("History", f"{len(p.assessments)} of 5 kept")
    return Group(t, Text(""), history_table(p.assessments, g))


# ----------------------------------------------------------------- summary
def assessment_summary(a, g: Glyphs) -> RenderableType:
    s = a.summary or {}
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", min_width=16)
    grid.add_column()
    grid.add_row("Status", status_text(a.status) + (f"  [muted]{escape(a.error)}[/]" if a.error else ""))
    if a.target_url:
        grid.add_row("Website", escape(a.target_url))
    if a.source_label:
        grid.add_row("Source", escape(a.source_label))
    for step in a.steps:
        mark = {"completed": f"[ok]{g.done}[/]", "failed": f"[err]{g.failed}[/]",
                "cancelled": f"[muted]{g.cancelled}[/]"}.get(step.status, f"[muted]{g.pending}[/]")
        grid.add_row(STEP_TITLES.get(step.kind, step.kind), f"{mark} {step.status}"
                     + (f"  [muted]{escape(step.error or '')}[/]" if step.error and step.status != "completed" else ""))
    if any(st.kind == "discovery" and st.status == "completed" for st in a.steps):
        limit_note = " (25-page limit reached)" if s.get("page_limit_reached") else ""
        grid.add_row("Pages", f"{s.get('pages_inspected', 0)} inspected, {s.get('pages_failed', 0)} failed{limit_note}")
        grid.add_row("Manifest", "[ok]found[/] /.well-known/routes.json" if a.manifest_detected else "[muted]not found[/]")
        web_eps = [e for e in a.endpoints if e.origin != "source_route"]
        grid.add_row("Endpoints", f"{len(web_eps)} found" + (f", {s['forms_count']} forms" if s.get("forms_count") else ""))
        stack = s.get("stack") or {}
        if stack:
            grid.add_row("Stack", " · ".join(f"{k} {escape(str(v))}" for k, v in stack.items()
                                             if k != "confidence" and v and v != "Unknown") or "[muted]not identified[/]")
    sr = a.source_result
    if sr is not None:
        grid.add_row("Source support", f"{sr.support_status}  [muted]{escape(sr.support_reason or '')}[/]")
        grid.add_row("Framework", escape(f"{sr.framework} ({sr.runtime})"))
        grid.add_row("Routes", f"{len(sr.routes)} route handlers, {len(sr.db_interactions)} database calls")
    counts = severity_counts(a.findings)
    if sr is not None:
        sev = "  ".join(f"[sev.{k}]{g.sev[k]} {counts[k]} {k}[/]" for k in ("critical", "high", "medium", "low", "info")
                        if counts[k])
        grid.add_row("Findings", sev or "[muted]none[/]")
    return grid


def technologies_table(techs, g: Glyphs) -> RenderableType:
    if not techs:
        return empty("No technologies identified.")
    t = table("Technology", "Category", "Version", "Confidence", "Seen in", "Evidence")
    for x in techs:
        t.add_row(escape(x.name), x.category, escape(x.version or "-"), x.confidence, x.source,
                  escape("; ".join(x.evidence[:2]))[:80])
    return t


def endpoints_table(endpoints, g: Glyphs, limit: int = 60) -> RenderableType:
    if not endpoints:
        return empty("No endpoints identified.")
    t = table("Method", "Path", "Found via", "Parameters")
    for e in endpoints[:limit]:
        src = e.details.get("source_file") if e.details else None
        t.add_row(e.method, escape(e.path[:70]) + (f" [muted]{g.arrow} {escape(src)}[/]" if src else ""),
                  e.origin.replace("_", " "), escape(", ".join(e.parameters[:6])))
    if len(endpoints) > limit:
        t.caption = f"{len(endpoints) - limit} more not shown"
    return t
