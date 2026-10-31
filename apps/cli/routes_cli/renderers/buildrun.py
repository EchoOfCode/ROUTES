"""Rendering of build-and-run verification evidence. Every status carries a text
label or symbol as well as a colour."""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from routes_core.buildrun import PHASE_LABELS
from routes_cli.renderers.theme import Glyphs

VERDICT = {
    "VERIFIED_RUN": ("ok", "Verified run: built, started and every test passed"),
    "TESTS_FAILED": ("warn", "Tests failed: the application ran but some tests did not pass"),
    "BUILD_FAILED": ("err", "Build failed: a setup, build or start step failed"),
    "DYNAMIC_VERIFICATION_UNSUPPORTED": ("warn", "Dynamic verification unsupported for this project"),
    "INCONCLUSIVE": ("muted", "Inconclusive: no verification result could be established"),
}
STEP_STYLE = {"passed": "ok", "installed": "ok", "ready": "ok", "applied": "ok", "not_required": "muted",
              "not_run": "faint", "failed": "err", "timeout": "err", "interrupted": "warn"}


def phase_line(phase: str, g: Glyphs, *, current: bool) -> str:
    text = PHASE_LABELS.get(phase, phase)
    if phase in ("FAILED",):
        return f"  [err]{g.failed}[/] {text}"
    if phase == "CANCELLED":
        return f"  [muted]{g.cancelled}[/] {text}"
    if phase in ("COMPLETED", "CLEANED_UP"):
        return f"  [ok]{g.done}[/] {text}"
    return f"  [accent]{g.arrow}[/] {text}"


def _step(label: str, status: str | None, g: Glyphs, detail: str = "") -> tuple[str, str, str]:
    status = status or "not_run"
    style = STEP_STYLE.get(status, "muted")
    mark = g.done if style == "ok" else g.failed if style == "err" else g.skipped
    return label, f"[{style}]{mark} {status.replace('_', ' ')}[/]", escape(detail)


def render(state: dict, g: Glyphs) -> RenderableType:
    r = state.get("result") or {}
    verdict = r.get("verification", "INCONCLUSIVE")
    style, text = VERDICT.get(verdict, VERDICT["INCONCLUSIVE"])
    parts: list[RenderableType] = [Text.from_markup(f"[heading]Outcome[/]  [{style}]{escape(verdict)}[/]  {escape(text)}")]
    if r.get("error"):
        parts.append(Text.from_markup(f"[muted]Reason:[/] {escape(str(r['error']))}"))
    stages = r.get("stages") or {}
    detail = failure_detail(r.get("failed_stage"), stages)
    if detail:
        parts.append(Text.from_markup("[muted]Details (end of the sandbox output, secrets redacted):[/]"))
        parts.append(Text(detail, style="faint"))

    t = Table.grid(padding=(0, 2))
    t.add_column(style="label", min_width=20)
    t.add_column(min_width=16)
    t.add_column(style="muted")
    src = stages.get("source") or {}
    patch = src.get("patch") or {}
    t.add_row(*_step("Source snapshot", src.get("status"), g, f"{src.get('files', 0)} files" if src else ""))
    t.add_row(*_step("Candidate patch", "applied" if patch.get("applied") else ("not_run" if not src else "not_required"),
                     g, ", ".join(patch.get("files") or [])))
    dep = stages.get("dependencies") or {}
    t.add_row(*_step("Dependencies", dep.get("status"), g,
                     f"{dep.get('packages', 0)} packages, install scripts disabled" if dep else ""))
    db = stages.get("database") or {}
    schema = db.get("schema") or []
    t.add_row(*_step("Disposable database", db.get("status"), g,
                     f"{len(schema)} schema file(s), {len(db.get('seed') or [])} seed step(s)" if schema else ""))
    app = r.get("application") or {}
    t.add_row(*_step("Production build", app.get("build"), g, (stages.get("build") or {}).get("command", "")))
    t.add_row(*_step("Application start", app.get("startup"), g, (stages.get("startup") or {}).get("command", "")))
    t.add_row(*_step("Health check", app.get("health_check"), g,
                     ((stages.get("startup") or {}).get("health") or {}).get("path", "")))
    parts += [Text(""), t]

    tests = r.get("tests") or {}
    if tests.get("total"):
        tt = Table(box=None, padding=(0, 2), show_edge=False)
        for col in ("Category", "Total", "Passed", "Failed"):
            tt.add_column(col, style="label" if col == "Category" else None)
        for cat in ("security", "functional", "edge", "health"):
            c = r.get(cat) or {}
            if c.get("total"):
                failed = c.get("failed", 0)
                tt.add_row(cat.capitalize(), str(c["total"]), f"[ok]{c.get('passed', 0)}[/]",
                           f"[err]{g.failed} {failed}[/]" if failed else "0")
        tt.add_row("[heading]All[/]", str(tests.get("total", 0)), str(tests.get("passed", 0)), str(tests.get("failed", 0)))
        parts += [Text(""), tt]
        failures = [c for c in r.get("cases") or [] if c.get("status") != "passed"]
        if failures:
            parts.append(Text(""))
            parts.append(Text.from_markup("[heading]Failed tests[/]"))
            for c in failures[:20]:
                parts.append(Text.from_markup(f"  [err]{g.failed}[/] {escape('[' + str(c.get('category')) + ']')} {escape(c.get('id', ''))}: "
                                              f"{escape(c.get('name', ''))}"))
                for reason in c.get("reasons", [])[:3]:
                    parts.append(Text.from_markup(f"      [muted]{escape(reason)}[/]"))

    iso = (r.get("isolation") or {}).get("build_runner") or {}
    if iso:
        mark = f"[ok]{g.done} isolated[/]" if iso.get("verdict") == "isolated" else f"[err]{g.failed} violated[/]"
        parts += [Text(""), Text.from_markup(f"[label]Network isolation after install[/]  {mark}  "
                                             f"[muted]{len(iso.get('probes') or [])} destinations probed[/]")]
    net = state.get("network_summary") or {}
    if net:
        dest = ", ".join(net.get("destinations") or []) or "none"
        parts.append(Text.from_markup(f"[label]Egress during install[/]  {net.get('allowed', 0)} allowed, "
                                      f"{net.get('denied', 0)} denied  [muted]({escape(dest)})[/]"))
    scripts = dep.get("scripts_not_run") or []
    if scripts:
        parts.append(Text.from_markup(f"[warn]Install scripts not run[/] [muted](approve with --approve-script)[/]: "
                                      f"{escape(', '.join(scripts[:15]))}"))
    notes = (r.get("project") or {}).get("notes") or []
    for n in notes:
        parts.append(Text.from_markup(f"[muted]{g.bullet} {escape(n)}[/]"))
    return Group(*parts)


# ----------------------------------------------------------- live progress
# Order in which the engine can enter phases. A phase is shown as done only once
# the engine has entered a later one; nothing is estimated or pre-filled.
PROGRESS_PHASES = ["CREATED", "SOURCE_READY", "DEPENDENCIES_INSTALLING", "DATABASE_STARTING", "BUILDING",
                   "APPLICATION_STARTING", "TESTING", "COLLECTING_RESULTS"]
TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")
SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-\\"


def progress(state: dict | None, g: Glyphs, *, frame: int = 0, animate: bool = True, local: list[str] | None = None,
             elapsed: float = 0.0, source: str = "") -> RenderableType:
    spin_set = SPINNER_UNICODE if g.done == "✓" else SPINNER_ASCII
    spinner = spin_set[frame % len(spin_set)] if animate else g.running
    state = state or {}
    history = [p["phase"] for p in state.get("phase_history") or []]
    entered = set(history)
    terminal = next((p for p in history if p in TERMINAL), None)
    cleaned = "CLEANED_UP" in entered
    last_work = next((p for p in reversed(history) if p in PROGRESS_PHASES), None)

    head = Table.grid(padding=(0, 2))
    head.add_column(style="label", min_width=8)
    head.add_column()
    if source:
        head.add_row("Source", f"[heading]{escape(source)}[/]")
    if state.get("id"):
        head.add_row("Run", f"[muted]{escape(state['id'])}[/]")
    status = {"COMPLETED": "[ok]Completed[/]", "FAILED": "[err]Failed[/]", "CANCELLED": "[muted]Cancelled[/]"}.get(
        terminal or "", f"[accent]{escape(PHASE_LABELS.get(last_work or '', 'Preparing'))}[/]")
    head.add_row("Status", status)
    parts: list[RenderableType] = [head, Text("")]

    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=2)
    rows.add_column()
    rows.add_column(style="muted")
    for i, text in enumerate(local or []):
        is_last = i == len(local) - 1
        if history or not is_last:
            rows.add_row(f"[ok]{g.done}[/]", text, "")
        else:
            rows.add_row(f"[accent]{spinner}[/]", f"[heading]{escape(text)}[/]", "")
    if history:
        reached = [p for p in PROGRESS_PHASES if p in entered]
        last_index = PROGRESS_PHASES.index(reached[-1]) if reached else -1
        for idx, phase in enumerate(PROGRESS_PHASES):
            label = PHASE_LABELS.get(phase, phase)
            if phase in entered:
                if phase == last_work and not terminal:
                    rows.add_row(f"[accent]{spinner}[/]", f"[heading]{escape(label)}[/]", "")
                elif phase == last_work and terminal == "FAILED":
                    rows.add_row(f"[err]{g.failed}[/]", escape(label), "failed here")
                elif phase == last_work and terminal == "CANCELLED":
                    rows.add_row(f"[muted]{g.cancelled}[/]", escape(label), "cancelled")
                else:
                    rows.add_row(f"[ok]{g.done}[/]", escape(label), "")
            elif idx < last_index:
                rows.add_row(f"[faint]{g.skipped}[/]", f"[faint]{escape(label)}[/]", "not required")
            else:
                rows.add_row(f"[faint]{g.pending}[/]", f"[faint]{escape(label)}[/]", "")
        if terminal and not cleaned:
            rows.add_row(f"[accent]{spinner}[/]", "Removing the environment", "")
        elif cleaned:
            rows.add_row(f"[ok]{g.done}[/]", "Environment removed", "")
    parts.append(rows)

    events = state.get("events") or []
    counts: dict = {}
    for e in events:
        counts.update(e.get("data") or {})
    if counts.get("tests_total"):
        total, done = counts["tests_total"], min(counts.get("tests_done", 0), counts["tests_total"])
        width = 24
        filled = round(width * done / max(total, 1))
        bar = f"[accent]{g.bar_full * filled}[/][faint]{g.bar_empty * (width - filled)}[/]"
        failed = counts.get("tests_failed", 0)
        parts += [Text(""), Text.from_markup(f"    [label]Tests[/]  {done} / {total}  {bar}"
                                             + (f"  [err]{g.failed} {failed} failed[/]" if failed else ""))]
    if events and not terminal and events[-1].get("message"):
        parts += [Text(""), Text(f"  {events[-1]['message'][:160]}", style="muted", overflow="ellipsis", no_wrap=True)]
    mins, secs = divmod(int(elapsed), 60)
    parts += [Text(""), Text(f"  Elapsed {mins:02d}:{secs:02d}", style="faint")]
    return Group(*parts)


def failure_detail(failed_stage: str | None, stages: dict, max_lines: int = 15) -> str:
    """The most useful bounded excerpt for the stage that failed (already redacted in the sandbox)."""
    text = ""
    if failed_stage == "database":
        db = stages.get("database") or {}
        failed = [s for s in (db.get("schema") or []) + (db.get("seed") or []) if s.get("status") != "applied"]
        if failed:
            text = f"{failed[0].get('file')}: {failed[0].get('output') or failed[0].get('status')}"
        elif db.get("error"):
            text = str(db["error"])
    elif failed_stage in ("dependencies", "build", "startup"):
        stage = stages.get(failed_stage) or {}
        text = str(stage.get("log_tail") or stage.get("app_log_tail") or "")
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return "\n".join("  " + line[:200] for line in lines[-max_lines:])
