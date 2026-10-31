"""Live assessment progress, built only from real updates.

Both the direct commands (Rich Live) and the interactive interface (Textual)
feed ``Update`` objects from ``routes_cli.service`` into ``ProgressModel`` and
render it. A stage is shown as done only after the sandbox has moved past it;
the page bar appears only when the discovery sandbox reports page counts.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from routes_cli.renderers.theme import Glyphs, status_text
from routes_cli.service import AssessmentFinished, AssessmentStarted, ResultsProcessing, StepUpdate
from routes_cli.stages import STEP_TITLES, label, stages_for

SPINNER_UNICODE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_ASCII = "|/-\\"


@dataclass
class StepState:
    kind: str
    local: tuple[str, ...] = ()
    status: str = "queued"
    stage: str | None = None
    completed: list[str] = field(default_factory=list)
    message: str = ""
    data: dict = field(default_factory=dict)
    cleaning_up: bool = False
    error: str | None = None


class ProgressModel:
    def __init__(self) -> None:
        self.assessment_id: str | None = None
        self.project = ""
        self.target: str | None = None
        self.source: str | None = None
        self.steps: dict[str, StepState] = {}
        self.started = time.monotonic()
        self.ended: float | None = None
        self.processing = False
        self.finished: AssessmentFinished | None = None
        self.feed: deque[str] = deque(maxlen=6)
        self._announced: set[str] = set()

    # ------------------------------------------------------------------ input
    def apply(self, u) -> list[tuple[str, str]]:
        """Apply an update. Returns notable events as (severity, message) for notifications."""
        notes: list[tuple[str, str]] = []
        if isinstance(u, AssessmentStarted):
            self.assessment_id, self.project, self.target, self.source = (u.assessment_id, u.project_name,
                                                                          u.target_url, u.source_label)
            self.steps = {k: StepState(k, local=u.local_stages if k == "source" else ()) for k in u.steps}
            self.started = time.monotonic()
        elif isinstance(u, StepUpdate):
            s = self.steps.setdefault(u.kind, StepState(u.kind))
            if u.message and u.message != s.message:
                self.feed.append(f"{STEP_TITLES.get(u.kind, u.kind)}: {u.message}")
            s.status, s.message, s.cleaning_up, s.error = u.status, u.message or s.message, u.cleaning_up, u.error
            if u.stage:
                s.stage = u.stage
            s.completed = list(u.completed) if u.completed or u.status != "running" else s.completed
            s.data = {**s.data, **u.data}
            notes += self._notable(s)
            if u.status == "failed" and u.error:
                notes.append(("error", f"{STEP_TITLES.get(u.kind, u.kind)} failed: {u.error}"))
        elif isinstance(u, ResultsProcessing):
            self.processing = True
        elif isinstance(u, AssessmentFinished):
            self.finished, self.processing, self.ended = u, False, time.monotonic()
        return notes

    def _notable(self, s: StepState) -> list[tuple[str, str]]:
        out = []
        sm = s.data.get("static_matches")
        if sm is not None and "static" not in self._announced:
            self._announced.add("static")
            out.append(("warning" if sm else "information",
                        f"Static rules reported {sm} potential issue{'s' if sm != 1 else ''}."))
        flows = s.data.get("sqli_flows")
        if flows is not None and "sqli" not in self._announced:
            self._announced.add("sqli")
            out.append(("warning" if flows else "information",
                        f"Data-flow analysis found {flows} SQL injection flow{'s' if flows != 1 else ''}."))
        return out

    @property
    def elapsed(self) -> float:
        return (self.ended or time.monotonic()) - self.started

    @property
    def active(self) -> bool:
        return self.finished is None

    # ----------------------------------------------------------------- output
    def render(self, g: Glyphs, frame: int = 0, *, animate: bool = True) -> RenderableType:
        spin = SPINNER_UNICODE if g.done == "✓" else SPINNER_ASCII
        spinner = spin[frame % len(spin)] if animate else g.running
        head = Table.grid(padding=(0, 2))
        head.add_column(style="label", min_width=8)
        head.add_column()
        if self.target:
            head.add_row("Target", f"[heading]{escape(self.target)}[/]")
        if self.source:
            head.add_row("Source", f"[heading]{escape(self.source)}[/]")
        status = self.finished.status if self.finished else ("Processing results" if self.processing else self._phase())
        head.add_row("Status", status_text(status) if self.finished else f"[accent]{status}[/]")
        parts: list[RenderableType] = [head]
        for kind, s in self.steps.items():
            parts.append(Text(""))
            parts.append(Text.from_markup(f"[heading]{STEP_TITLES.get(kind, kind)}[/]  {self._step_badge(s, g)}"))
            parts.append(self._stage_rows(s, g, spinner))
            bar = self._counters(s, g)
            if bar is not None:
                parts.append(bar)
        parts.append(Text(""))
        if self.processing:
            parts.append(Text.from_markup(f"  [accent]{spinner}[/] {label('results')}"))
        if self.active and self.feed:
            parts.append(Text(f"  {self.feed[-1]}", style="muted", overflow="ellipsis", no_wrap=True))
        mins, secs = divmod(int(self.elapsed), 60)
        parts.append(Text(f"  Elapsed {mins:02d}:{secs:02d}", style="faint"))
        return Group(*parts)

    def _phase(self) -> str:
        running = [STEP_TITLES.get(k, k) for k, s in self.steps.items() if s.status == "running"]
        return " + ".join(running) if running else "Starting"

    def _step_badge(self, s: StepState, g: Glyphs) -> str:
        return {"completed": f"[ok]{g.done} done[/]", "failed": f"[err]{g.failed} failed[/]",
                "cancelled": f"[muted]{g.cancelled} cancelled[/]", "running": "[accent]running[/]"
                }.get(s.status, "[muted]waiting[/]")

    def _stage_rows(self, s: StepState, g: Glyphs, spinner: str) -> Table:
        t = Table.grid(padding=(0, 1))
        t.add_column(width=2)
        t.add_column()
        t.add_column(style="muted")
        done = set(s.completed)
        starting = s.stage == "starting" and s.status == "running"
        for key, text in stages_for(s.kind, local=list(s.local)):
            if starting and key not in s.local:
                # The sandbox is being created: after any local steps, before the sandbox's own stages.
                t.add_row(f"[accent]{spinner}[/]", label("starting"), "")
                starting = False
            if key in done:
                t.add_row(f"[ok]{g.done}[/]", text, "")
            elif s.status == "running" and key == s.stage:
                t.add_row(f"[accent]{spinner}[/]", f"[heading]{text}[/]", "")
            elif s.status == "completed":
                t.add_row(f"[faint]{g.skipped}[/]", f"[faint]{text}[/]", "not applicable")
            elif s.status == "failed" and key == s.stage:
                t.add_row(f"[err]{g.failed}[/]", text, escape((s.error or "")[:90]))
            elif s.status == "cancelled" and key == s.stage:
                t.add_row(f"[muted]{g.cancelled}[/]", text, "cancelled")
            else:
                t.add_row(f"[faint]{g.pending}[/]", f"[faint]{text}[/]", "")
        if s.cleaning_up:
            t.add_row(f"[accent]{spinner}[/]", label("cleanup"), "")
        if s.status == "failed" and s.error and s.stage not in {k for k, _ in stages_for(s.kind, local=list(s.local))}:
            t.add_row(f"[err]{g.failed}[/]", "[err]Failed[/]", escape(s.error[:120]))
        return t

    def _counters(self, s: StepState, g: Glyphs) -> RenderableType | None:
        d = s.data
        rows = Table.grid(padding=(0, 2))
        rows.add_column(style="label", min_width=22)
        rows.add_column()
        shown = False
        if "page_limit" in d and "pages_done" in d:
            limit, done = max(1, d["page_limit"]), min(d["pages_done"], d["page_limit"])
            width = 24
            filled = round(width * done / limit)
            bar = f"[accent]{g.bar_full * filled}[/][faint]{g.bar_empty * (width - filled)}[/]"
            rows.add_row("    Pages inspected", f"{done} / {d['page_limit']}  {bar}")
            shown = True
        for key, text in (("files", "Files extracted"), ("static_matches", "Static rule matches"),
                          ("routes", "Routes traced"), ("sqli_flows", "SQL injection flows")):
            if key in d:
                rows.add_row(f"    {text}", str(d[key]))
                shown = True
        return rows if shown else None
