"""Supervision of one sandbox run: poll, report progress, cancel, enforce a deadline.

This is the database-free core of the worker's ``supervise``. The CLI calls
it from a background thread and renders the progress it reports.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled", "timeout"})


class RunClient(Protocol):
    def get(self, run_id: str) -> dict | None: ...
    def cancel(self, run_id: str) -> None: ...


@dataclass(frozen=True)
class Progress:
    """What has *actually* happened so far, derived only from sandbox events."""

    current_stage: str | None
    completed_stages: tuple[str, ...]
    message: str
    data: dict[str, int] = field(default_factory=dict)
    event_count: int = 0


def summarise(events: list[dict]) -> Progress:
    """A stage counts as completed only once a *later* stage has started."""
    if not events:
        return Progress(None, (), "")
    stages = list(dict.fromkeys(e["stage"] for e in events))
    data: dict[str, int] = {}
    for e in events:
        data.update(e.get("data") or {})
    return Progress(stages[-1], tuple(stages[:-1]), events[-1].get("message") or "", data, len(events))


def is_finished(state: dict) -> bool:
    """Terminal *and* cleaned up. The manager sets ``finished_at`` only after the
    container, network and gateway session have been removed."""
    if state.get("status") not in TERMINAL_RUN_STATUSES:
        return False
    return "finished_at" not in state or state.get("finished_at") is not None


def is_cleaning_up(state: dict) -> bool:
    return state.get("status") in TERMINAL_RUN_STATUSES and not is_finished(state)


def poll_run(client: RunClient, run: dict, *, deadline_seconds: float,
             on_state: Callable[[dict], None] | None = None,
             should_cancel: Callable[[], bool] | None = None,
             poll_seconds: float = 2.0,
             sleep: Callable[[float], None] = time.sleep,
             clock: Callable[[], float] = time.monotonic) -> dict:
    """Poll until the run reaches a terminal state and return that state.

    Cancellation is requested once; polling then continues until the manager
    has actually stopped and cleaned up the sandbox, so a run is never
    reported as cancelled while its container still exists.
    """
    run_id = run["id"]
    deadline = clock() + deadline_seconds
    last_seen: dict = run
    cancel_sent = False
    while True:
        state = client.get(run_id)
        if state is not None:
            last_seen = state
            if on_state is not None:
                on_state(state)
            if is_finished(state):
                return state
        if not cancel_sent and should_cancel is not None and should_cancel():
            client.cancel(run_id)
            cancel_sent = True
        if clock() > deadline:
            client.cancel(run_id)
            return {**last_seen, "status": "timeout", "error": "The assessment step exceeded its time limit."}
        sleep(poll_seconds)
