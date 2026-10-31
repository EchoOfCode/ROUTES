from __future__ import annotations

from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from routes_cli.doctor import FAIL, PASS, WARN, Check, summary
from routes_cli.renderers.theme import Glyphs


def doctor_view(checks: list[Check], g: Glyphs) -> RenderableType:
    style = {PASS: ("ok", g.done), WARN: ("warn", "!"), FAIL: ("err", g.failed)}
    parts: list[RenderableType] = [Text("ROUTES ENVIRONMENT", style="heading"), Text("")]
    group = None
    t = None
    for c in checks:
        if c.group != group:
            if t is not None:
                parts += [t, Text("")]
            group = c.group
            parts.append(Text(group, style="label"))
            t = Table.grid(padding=(0, 2))
            t.add_column(width=7)
            t.add_column(min_width=24)
            t.add_column()
        st, mark = style[c.status]
        detail = escape(c.detail) + (f"\n[muted]{escape(c.hint)}[/]" if c.hint else "")
        t.add_row(f"[{st}]{mark} {c.status}[/]", c.name, detail)
    if t is not None:
        parts.append(t)
    p, w, f = summary(checks)
    verdict = ("[ok]Ready.[/]" if not f and not w else "[warn]Usable, with warnings.[/]" if not f
               else "[err]Not ready.[/] Fix the failed checks above.")
    parts += [Text(""), Text.from_markup(f"{verdict}  [muted]{p} passed · {w} warnings · {f} failed[/]")]
    return Group(*parts)
