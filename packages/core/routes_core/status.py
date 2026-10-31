"""Assessment outcome rules shared by every store: final status, correlation, retention."""

from __future__ import annotations

from typing import Iterable, Protocol, Sequence

from routes_shared.enums import ACTIVE_ASSESSMENT_STATUSES, AssessmentStatus, JobStatus

HISTORY_LIMIT = 5


class StepLike(Protocol):
    kind: str
    status: str
    error: str | None


def compute_final_status(steps: Iterable[StepLike], *, cancel_requested: bool) -> tuple[str, str | None]:
    """Never 'completed' unless every essential step completed."""
    steps = [s for s in steps if s.kind != "results"]
    if cancel_requested:
        return AssessmentStatus.CANCELLED, "The assessment was cancelled."
    completed = [s for s in steps if s.status == JobStatus.COMPLETED]
    if steps and len(completed) == len(steps):
        return AssessmentStatus.COMPLETED, None
    failures = [f"{s.kind.capitalize()}: {s.error or 'did not complete'}" for s in steps if s.status != JobStatus.COMPLETED]
    if completed:
        return AssessmentStatus.PARTIALLY_COMPLETED, " ".join(failures)
    return AssessmentStatus.FAILED, " ".join(failures) or "The assessment could not complete."


def normalise_path(path: str) -> str:
    """'/api/products/[id]', '/api/products/{id}' and '/api/products/7' compare equal."""
    parts = []
    for seg in path.split("?")[0].strip("/").split("/"):
        if seg.startswith(("[", "{", ":")) or seg.isdigit():
            seg = "*"
        parts.append(seg)
    return "/" + "/".join(p for p in parts if p)


class EndpointLike(Protocol):
    origin: str
    path: str
    details: dict | None


def correlate(endpoints: Sequence[EndpointLike]) -> int:
    """Annotate website endpoints that correspond to a route handler found in the
    source. Only call this when the developer confirmed the repository matches."""
    source_routes = {normalise_path(e.path): e for e in endpoints if e.origin == "source_route"}
    matched = 0
    for e in endpoints:
        if e.origin == "source_route":
            continue
        route = source_routes.get(normalise_path(e.path))
        if route is not None:
            rd = route.details or {}
            e.details = {**(e.details or {}), "source_file": rd.get("file"), "source_line": rd.get("line")}
            matched += 1
    return matched


class AssessmentLike(Protocol):
    status: str


def retention_victims(newest_first: Sequence[AssessmentLike], limit: int = HISTORY_LIMIT) -> list:
    """Assessments beyond the newest ``limit`` that may be deleted (never active ones)."""
    return [a for a in newest_first[limit:] if a.status not in ACTIVE_ASSESSMENT_STATUSES]
