"""ROUTES terminal identity: one accent, neutral greys, and status colours that
always come with a text label or symbol (colour is never the only signal)."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.theme import Theme

ACCENT = "#36c2b4"        # "route teal"
ACCENT_DIM = "#1f7a71"
TEXT = "#e6e6e3"
MUTED = "#8a8f98"
FAINT = "#5c6068"
RED = "#ef5b5b"
AMBER = "#e9a23b"
BLUE = "#5b9cf0"
GREEN = "#52c47c"

THEME = Theme({
    "accent": ACCENT, "accent.dim": ACCENT_DIM, "muted": MUTED, "faint": FAINT,
    "ok": GREEN, "warn": AMBER, "err": RED, "info": BLUE,
    "sev.critical": f"bold {RED}", "sev.high": RED, "sev.medium": AMBER, "sev.low": BLUE, "sev.info": MUTED,
    "heading": f"bold {TEXT}", "label": MUTED, "path": f"underline {TEXT}",
})

SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
STATUS_LABEL = {
    "completed": "Completed", "partially_completed": "Partially completed", "failed": "Failed",
    "cancelled": "Cancelled", "queued": "Queued", "running": "Running", "discovering": "Discovering",
    "analysing": "Analysing",
}
STATUS_STYLE = {"completed": "ok", "partially_completed": "warn", "failed": "err", "cancelled": "muted",
                "queued": "muted", "running": "accent", "discovering": "accent", "analysing": "accent"}


@dataclass(frozen=True)
class Glyphs:
    done: str
    failed: str
    running: str
    pending: str
    skipped: str
    cancelled: str
    sev: dict
    bar_full: str
    bar_empty: str
    arrow: str
    bullet: str
    rule: str


UNICODE = Glyphs("✓", "✗", "●", "○", "–", "■",
                 {"critical": "▲▲", "high": "▲", "medium": "◆", "low": "●", "info": "·"}, "█", "░", "›", "•", "─")
ASCII = Glyphs("+", "x", "*", "o", "-", "#",
               {"critical": "!!", "high": "!", "medium": "~", "low": "-", "info": "."}, "#", ".", ">", "*", "-")


def glyphs(console: Console | None = None) -> Glyphs:
    console = console or Console()
    enc = (console.encoding or "").lower()
    if (console.is_terminal and console.legacy_windows) or not enc.startswith("utf"):
        return ASCII
    return UNICODE


def make_console(*, plain: bool = False, stderr: bool = False) -> Console:
    """``plain`` disables colour and live rendering (pipes, files, --no-animation)."""
    if plain:
        return Console(theme=THEME, no_color=True, highlight=False, emoji=False, soft_wrap=False, stderr=stderr,
                       force_terminal=False)
    return Console(theme=THEME, highlight=False, emoji=False, stderr=stderr)


def severity_text(severity: str, g: Glyphs) -> str:
    return f"[sev.{severity}]{g.sev.get(severity, '·')} {SEVERITY_LABEL.get(severity, severity.upper())}[/]"


def status_text(status: str) -> str:
    return f"[{STATUS_STYLE.get(status, 'muted')}]{STATUS_LABEL.get(status, status)}[/]"
