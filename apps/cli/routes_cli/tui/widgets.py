"""Widgets for the ROUTES interface."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.suggester import Suggester
from textual.widgets import Input, Static

from routes_cli.renderers.progress import ProgressModel
from routes_cli.renderers.theme import Glyphs
from routes_cli.tui.commands import complete

WORDMARK = [
    "█▀█ █▀█ █ █ ▀█▀ █▀▀ █▀",
    "█▀▄ █▄█ █▄█  █  ██▄ ▄█",
]
WORDMARK_ASCII = ["ROUTES"]


class Logo(Vertical):
    """Two-line wordmark. With motion enabled, the lines fade in one after the other."""

    def __init__(self, *, ascii_only: bool, animate: bool, **kw):
        super().__init__(**kw)
        self.lines = WORDMARK_ASCII if ascii_only else WORDMARK
        self.reveal = animate

    def compose(self) -> ComposeResult:
        for line in self.lines:
            yield Static(line, classes="logo-line")

    def on_mount(self) -> None:
        if not self.reveal:
            return
        for i, child in enumerate(self.query(".logo-line")):
            child.styles.opacity = 0.0
            child.styles.animate("opacity", 1.0, duration=0.35, delay=0.08 * i, easing="out_cubic")


def fade_in(widget, *, enabled: bool, duration: float = 0.18) -> None:
    """Fade a freshly mounted view in. Skipped entirely in reduced-motion mode."""
    if not enabled:
        return
    widget.styles.opacity = 0.0

    def start() -> None:
        widget.styles.animate("opacity", 1.0, duration=duration, easing="out_cubic")

    widget.call_after_refresh(start)


class Readiness(Static):
    """Environment chips filled in from real checks."""

    SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, g: Glyphs, *, animate: bool, **kw):
        super().__init__("", **kw)
        self.g = g
        self.animate_spin = animate
        self.items: dict[str, tuple[str, str] | None] = {"Docker": None, "Engine": None, "Database": None}
        self.frame = 0
        self._timer = None

    def on_mount(self) -> None:
        if self.animate_spin:
            self._timer = self.set_interval(1 / 10, self._tick)
        self.refresh_view()

    def _tick(self) -> None:
        self.frame += 1
        if all(v is not None for v in self.items.values()) and self._timer is not None:
            self._timer.stop()
        self.refresh_view()

    def set(self, name: str, ok: bool | None, detail: str) -> None:
        state = "ok" if ok else ("warn" if ok is None else "err")
        self.items[name] = (state, detail)
        self.refresh_view()

    def refresh_view(self) -> None:
        g = self.g
        parts = []
        for name, value in self.items.items():
            if value is None:
                spin = self.SPIN[self.frame % len(self.SPIN)] if self.animate_spin and g.done == "✓" else g.pending
                parts.append(f"[faint]{spin} {name}[/]")
            else:
                state, detail = value
                mark = {"ok": g.done, "warn": "!", "err": g.failed}[state]
                parts.append(f"[{state}]{mark}[/] {name} [muted]{detail}[/]")
        self.update(Text.from_markup("    ".join(parts)))


class AssessmentPanel(Static):
    """Live progress rendered from ``ProgressModel`` (real sandbox events only)."""

    def __init__(self, model: ProgressModel, g: Glyphs, *, animate: bool, **kw):
        super().__init__("", **kw)
        self.model = model
        self.g = g
        self.animate_spin = animate
        self.frame = 0

    def on_mount(self) -> None:
        self.set_interval(1 / 12 if self.animate_spin else 1.0, self._tick)
        self.redraw()

    def _tick(self) -> None:
        self.frame += 1
        self.redraw()

    def redraw(self) -> None:
        self.update(self.model.render(self.g, self.frame, animate=self.animate_spin and self.model.active))


class CommandSuggester(Suggester):
    def __init__(self, projects_provider):
        super().__init__(use_cache=False, case_sensitive=True)
        self.projects_provider = projects_provider

    async def get_suggestion(self, value: str) -> str | None:
        return complete(value, projects=self.projects_provider())


class PromptInput(Input):
    """Persistent command prompt with history (Up/Down) and Tab completion."""

    BINDINGS = []

    def __init__(self, history_path: Path, projects_provider, **kw):
        super().__init__(placeholder="Type a command, e.g. /scan https://example.com  ·  /help",
                         suggester=CommandSuggester(projects_provider), select_on_focus=False, **kw)
        self.history_path = history_path
        self.history: list[str] = self._load()
        self.cursor_index: int | None = None
        self.draft = ""

    def _load(self) -> list[str]:
        try:
            return [l for l in self.history_path.read_text(encoding="utf-8").splitlines() if l.strip()][-500:]
        except OSError:
            return []

    def remember(self, line: str) -> None:
        line = line.strip()
        if not line or (self.history and self.history[-1] == line):
            self.cursor_index = None
            return
        self.history.append(line)
        self.history = self.history[-500:]
        self.cursor_index = None
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            self.history_path.write_text("\n".join(self.history) + "\n", encoding="utf-8")
        except OSError:
            pass

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "up" and self.history:
            if self.cursor_index is None:
                self.draft = self.value
                self.cursor_index = len(self.history)
            self.cursor_index = max(0, self.cursor_index - 1)
            self._show(self.history[self.cursor_index])
            event.prevent_default()
            event.stop()
            return
        if event.key == "down" and self.cursor_index is not None:
            self.cursor_index += 1
            if self.cursor_index >= len(self.history):
                self.cursor_index = None
                self._show(self.draft)
            else:
                self._show(self.history[self.cursor_index])
            event.prevent_default()
            event.stop()
            return
        if event.key == "tab":
            if self._suggestion and self._suggestion != self.value:
                self._show(self._suggestion)
            event.prevent_default()
            event.stop()
            return
        await super()._on_key(event)

    def _show(self, text: str) -> None:
        self.value = text
        self.cursor_position = len(text)


class Menu(Widget, can_focus=True):
    """Arrow-key menu. The highlighted entry gets a pointer and a background band
    (not colour alone)."""

    BINDINGS = [Binding("up", "move(-1)", show=False), Binding("down", "move(1)", show=False),
                Binding("enter", "choose", show=False)]

    class Chosen(Message):
        def __init__(self, menu: "Menu", key: str) -> None:
            super().__init__()
            self.menu = menu
            self.key = key

        @property
        def control(self) -> "Menu":
            return self.menu

    index: reactive[int] = reactive(0)

    def __init__(self, items: list[tuple[str, str]], pointer: str = "›", **kw):
        super().__init__(**kw)
        self.items = items
        self.pointer = pointer

    def render(self) -> Text:
        text = Text()
        for i, (_, label) in enumerate(self.items):
            active = i == self.index
            style = ("bold #e6e6e3 on #1f3b38" if self.has_focus else "#e6e6e3 on #1d2a29") if active else "#b9bcc2"
            marker = f" {self.pointer} " if active else "   "
            text.append(f"{marker}{label}".ljust(44), style=style)
            if i < len(self.items) - 1:
                text.append("\n")
        return text

    def action_move(self, delta: int) -> None:
        self.index = (self.index + delta) % len(self.items)

    def action_choose(self) -> None:
        self.post_message(self.Chosen(self, self.items[self.index][0]))

    def on_click(self, event) -> None:
        if 0 <= event.y < len(self.items):
            self.index = event.y
            self.action_choose()

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()
