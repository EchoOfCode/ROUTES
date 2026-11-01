"""Rendering of a remediation run: where the workflow is, every attempt of the
correction loop, and the evidence behind each verdict. Every status has a
symbol and a word as well as a colour."""

from __future__ import annotations

import time

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from routes_cli.renderers.progress import SPINNER_ASCII, SPINNER_UNICODE
from routes_cli.renderers.theme import Glyphs, severity_text
from routes_cli.remediation.workflow import ATTEMPT_STEPS, STEPS, FindingRun, RemediationRun, Step

STEP_LABEL = {"context": "Context", "plan": "Model A plan", "testbench": "Testbench", "baseline": "Baseline",
              "loop": "Correction loop", "verdict": "Verdict"}
ATTEMPT_LABEL = {"patch": "Model B", "validate": "validate", "sandbox": "build+test", "rescan": "rescan"}
STAGE_TEXT = {
    "queued": "queued", "preparing_context": "reading the code", "redacting": "redacting secrets",
    "analysis": "Model A: root cause", "planning": "Model A: plan", "generating_tests": "generating tests",
    "baseline_verification": "baseline on the original", "validating_tests": "validating the testbench",
    "generating_patch": "Model B: writing the patch", "validating_patch": "validating the patch",
    "building": "building the patched copy", "testing": "testing the patched copy",
    "post_remediation_analysis": "re-analysing the patched code", "analysing_failure": "analysing the failure",
    "retrying": "retrying with feedback", "completed": "completed", "human_review": "needs human review",
    "inconclusive": "inconclusive", "failed": "failed", "cancelled": "cancelled",
}
RESOLUTION = {
    "verified_fixed": ("ok", "VERIFIED FIXED"), "inconclusive": ("warn", "INCONCLUSIVE"),
    "human_review": ("warn", "HUMAN REVIEW"), "not_fixed": ("err", "NOT FIXED"), "failed": ("err", "FAILED"),
    "cancelled": ("muted", "CANCELLED"),
}
RUN_VERDICT = {
    "verified_fixed": ("ok", "Every targeted finding is verified fixed"),
    "partially_remediated": ("warn", "Some findings are verified fixed"),
    "human_review": ("warn", "Automated attempts did not produce a verified fix"),
    "inconclusive": ("warn", "A fix could not be verified"),
    "failed": ("err", "Remediation failed"), "cancelled": ("muted", "Cancelled"),
}


def _mark(status: str, g: Glyphs, spinner: str) -> str:
    return {"done": f"[ok]{g.done}[/]", "warn": "[warn]![/]", "failed": f"[err]{g.failed}[/]",
            "skipped": f"[faint]{g.skipped}[/]", "running": f"[accent]{spinner}[/]"}.get(status, f"[faint]{g.pending}[/]")


def _elapsed(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60}m{seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def _attempt_row(a, g: Glyphs, spinner: str) -> str:
    cells = []
    for k in ATTEMPT_STEPS:
        st: Step = a.steps[k]
        style = {"running": "accent", "failed": "err", "done": "", "skipped": "faint"}.get(st.status, "faint")
        word = ATTEMPT_LABEL[k]
        cells.append(f"{_mark(st.status, g, spinner)} [{style}]{word}[/]" if style else f"{_mark(st.status, g, spinner)} {word}")
    line = f"    Attempt {a.no}  " + "  ".join(cells)
    running = next((a.steps[k] for k in ATTEMPT_STEPS if a.steps[k].status == "running"), None)
    if running is not None and running.detail:
        line += f"\n               [muted]{escape(running.detail[:110])}[/]"
    elif a.outcome == "passed":
        line += f"\n               [ok]passed every check[/]"
    elif a.failure:
        arrow = "→ feedback to Model B" if a.outcome in ("failed", "rejected") else ""
        line += f"\n               [warn]{escape(a.failure.splitlines()[0][:110])}[/] [muted]{arrow}[/]"
    return line


def finding_block(fr: FindingRun, g: Glyphs, spinner: str, *, index: int, total: int) -> RenderableType:
    head = (f"[heading]{index}/{total}  #{fr.seq:02d} {escape(fr.title)}[/]  {severity_text(fr.severity, g)}  "
            f"[path]{escape(fr.file)}:{fr.line}[/]")
    if fr.resolution:
        style, word = RESOLUTION.get(fr.resolution, ("muted", fr.resolution))
        head += f"  [{style}]{word}[/]"
    else:
        head += f"  [accent]{escape(STAGE_TEXT.get(fr.stage, fr.stage))}[/]"
    t = Table.grid(padding=(0, 1))
    t.add_column(width=2)
    t.add_column(style="label", min_width=16)
    t.add_column()
    for name in STEPS:
        st = fr.steps[name]
        detail = st.detail
        if name == "loop" and st.status in ("pending",):
            detail = f"up to {fr.max_attempts} attempts"
        t.add_row(_mark(st.status, g, spinner), STEP_LABEL[name], f"[muted]{escape(detail[:150])}[/]")
        if name == "loop":
            for a in fr.attempts:
                t.add_row("", "", Text.from_markup(_attempt_row(a, g, spinner)))
    return Group(Text.from_markup(head), t)


def render(run: RemediationRun, g: Glyphs, frame: int = 0, *, animate: bool = True,
           show_all: bool = False) -> RenderableType:
    spin = SPINNER_UNICODE if g.done == "✓" else SPINNER_ASCII
    spinner = spin[frame % len(spin)] if animate else g.running
    elapsed = (run.finished_at or time.time()) - run.started_at
    total = len(run.findings)
    done = sum(1 for f in run.findings if f.resolution)
    parts: list[RenderableType] = [Text.from_markup(
        f"[muted]{escape(run.source)} · Model A {escape(run.models.get('A', ''))} · Model B "
        f"{escape(run.models.get('B', ''))} · {done}/{total} finding(s) done · {_elapsed(elapsed)}[/]")]
    # Finished findings collapse to one line; the active one is shown in full.
    for i, fr in enumerate(run.findings):
        if show_all or (i == run.current and run.active) or (not run.active and total == 1):
            parts += [Text(""), finding_block(fr, g, spinner, index=i + 1, total=total)]
        else:
            parts.append(_compact(fr, g, i + 1, total))
    if run.combined.status != "skipped":
        parts += [Text(""), Text.from_markup(f"{_mark(run.combined.status, g, spinner)} [label]Combined check[/]  "
                                             f"[muted]{escape(run.combined.detail[:160])}[/]")]
    return Group(*parts)


def _compact(fr: FindingRun, g: Glyphs, index: int, total: int) -> Text:
    if fr.resolution:
        style, word = RESOLUTION.get(fr.resolution, ("muted", fr.resolution))
        used = len(fr.attempts)
        tail = f"[{style}]{word}[/] [muted]· {used}/{fr.max_attempts} attempt(s)[/]"
    else:
        tail = f"[faint]{g.pending} waiting[/]"
    return Text.from_markup(f"  {index}/{total}  #{fr.seq:02d} {escape(fr.title[:60])}  "
                            f"[faint]{escape(fr.file)}:{fr.line}[/]  {tail}")


def summary(run: RemediationRun, g: Glyphs, saved=None) -> RenderableType:  # noqa: ANN001
    style, text = RUN_VERDICT.get(run.verdict or "failed", ("muted", run.verdict or ""))
    parts: list[RenderableType] = [Text.from_markup(
        f"[heading]Outcome[/]  [{style}]{escape((run.verdict or '').upper().replace('_', ' '))}[/]  {escape(text)}")]
    t = Table(box=None, header_style="label", padding=(0, 2))
    for col in ("Finding", "Location", "Attempts", "Baseline", "Sandbox", "Rescan", "Verdict"):
        t.add_column(col)
    for fr in run.findings:
        rs, word = RESOLUTION.get(fr.resolution or "", ("muted", fr.resolution or "-"))
        gates = fr.gates or {}

        def gate(key: str, na: bool = False) -> str:
            if na:
                return "[faint]n/a[/]"
            return f"[ok]{g.done}[/]" if gates.get(key) else f"[err]{g.failed}[/]"
        t.add_row(f"#{fr.seq:02d} {escape(fr.title[:40])}", f"{escape(fr.file)}:{fr.line}",
                  f"{len(fr.attempts)}/{fr.max_attempts}",
                  gate("testbench_validated", fr.mode == "static"),
                  gate("verification_passed", fr.mode == "static"),
                  gate("reanalysis_confirmed"), f"[{rs}]{word}[/]")
    parts += [Text(""), t, Text("")]
    for fr in run.findings:
        parts.append(Text.from_markup(f"[muted]#{fr.seq:02d}[/] {escape(fr.reason)}"))
    if run.combined.status not in ("skipped",):
        parts.append(Text.from_markup(f"[muted]Combined:[/] {escape(run.combined.detail)}"))
    if saved is not None:
        parts.append(Text(""))
        if saved.combined:
            parts.append(Text.from_markup(f"[ok]Patch[/]   [path]{escape(str(saved.combined))}[/]"))
        parts.append(Text.from_markup(f"[muted]Record[/]  [path]{escape(str(saved.report))}[/]"))
    return Group(*parts)
