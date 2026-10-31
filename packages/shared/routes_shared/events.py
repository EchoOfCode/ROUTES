"""Sandbox progress-event protocol, shared by the sandboxes and the Sandbox Manager.

A sandbox writes one JSON object per line to stderr, prefixed with
``EVENT_PREFIX``: ``{"stage": ..., "message": ..., "data": {...}}``.

``data`` carries *measured* counters only (for example pages actually
inspected so far). It is restricted to a fixed set of non-negative integer
fields so that clients can draw real progress without parsing free text, and
so that a compromised sandbox cannot smuggle arbitrary structures through it.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from routes_shared.contracts import EVENT_PREFIX

DATA_FIELDS: frozenset[str] = frozenset({
    "pages_done",      # HTML pages inspected so far (discovery)
    "page_limit",      # configured page cap (discovery)
    "endpoints",       # endpoints identified (discovery)
    "technologies",    # technologies detected (discovery)
    "files",           # source files extracted (analyzer)
    "routes",          # route handlers found (analyzer)
    "static_matches",  # findings reported by the static rules (analyzer)
    "sqli_flows",      # SQL injection flows found by data-flow analysis (analyzer)
})
MAX_VALUE = 10_000_000
MAX_EVENTS = 200


def clean_data(data: object) -> dict[str, int]:
    if not isinstance(data, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in data.items():
        if key in DATA_FIELDS and isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_VALUE:
            out[key] = value
    return out


def format_event(stage: str, message: str = "", **data: int) -> str:
    payload: dict = {"stage": stage[:64], "message": message[:300]}
    cleaned = clean_data(data)
    if cleaned:
        payload["data"] = cleaned
    return EVENT_PREFIX + json.dumps(payload, separators=(",", ":"))


def emit(stage: str, message: str = "", *, stream: TextIO | None = None, **data: int) -> None:
    out = stream or sys.stderr
    out.write(format_event(stage, message, **data) + "\n")
    out.flush()


def parse_events(text: str, limit: int = MAX_EVENTS) -> list[dict]:
    events: list[dict] = []
    for line in text.splitlines():
        if not line.startswith(EVENT_PREFIX):
            continue
        try:
            event = json.loads(line[len(EVENT_PREFIX):])
        except ValueError:
            continue
        if not isinstance(event, dict) or not isinstance(event.get("stage"), str):
            continue
        item = {"stage": event["stage"][:64], "message": str(event.get("message", ""))[:300]}
        data = clean_data(event.get("data"))
        if data:
            item["data"] = data
        events.append(item)
    return events[-limit:]
