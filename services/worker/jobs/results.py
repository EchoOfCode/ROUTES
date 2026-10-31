"""Results processing: correlate, set the final status honestly, apply retention."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select

from routes_shared.enums import TERMINAL_ASSESSMENT_STATUSES, JobStatus

from app.models import Assessment, AssessmentJob, DiscoveredEndpoint, ProjectIntegration
from app.services import lifecycle
from worker.jobs.common import db_session

log = logging.getLogger("routes.worker.results")


def _normalise(path: str) -> str:
    """'/api/products/[id]' and '/api/products/{id}' and '/api/products/' compare equal-ish."""
    parts = []
    for seg in path.split("?")[0].strip("/").split("/"):
        if seg.startswith(("[", "{", ":")) or seg.isdigit():
            seg = "*"
        parts.append(seg)
    return "/" + "/".join(p for p in parts if p)


def correlate(db, assessment: Assessment) -> int:
    """When the developer confirmed the repository matches, mark website
    endpoints that correspond to a route handler found in the source."""
    integration = db.scalar(select(ProjectIntegration).where(ProjectIntegration.project_id == assessment.project_id))
    if integration is None or integration.match_status != "confirmed":
        return 0
    endpoints = db.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.assessment_id == assessment.id)).all()
    source_routes = {_normalise(e.path): e for e in endpoints if e.origin == "source_route"}
    matched = 0
    for e in endpoints:
        if e.origin == "source_route":
            continue
        route = source_routes.get(_normalise(e.path))
        if route is not None:
            e.details = {**(e.details or {}), "source_file": route.details.get("file"), "source_line": route.details.get("line")}
            matched += 1
    return matched


def run_results_job(job_id: str, assessment_id: str) -> None:
    with db_session() as db:
        assessment = db.get(Assessment, uuid.UUID(assessment_id), with_for_update=True)
        if assessment is None or assessment.status in TERMINAL_ASSESSMENT_STATUSES:
            return
        job = db.get(AssessmentJob, uuid.UUID(job_id))
        if job is not None:
            job.status = JobStatus.RUNNING
            job.started_at = lifecycle.now()
            job.stage = "processing_findings"
        assessment.status = "running"
        db.commit()
        try:
            matched = correlate(db, assessment)
            status, error = lifecycle.compute_final_status(assessment)
            assessment.status = status
            assessment.error = error
            assessment.finished_at = lifecycle.now()
            assessment.discovery_summary = {**(assessment.discovery_summary or {}), "correlated_endpoints": matched}
            if job is not None:
                job.status = JobStatus.COMPLETED
                job.finished_at = lifecycle.now()
                job.stage = "done"
            db.commit()
        except Exception:
            db.rollback()
            assessment = db.get(Assessment, uuid.UUID(assessment_id))
            assessment.status = "failed"
            assessment.error = "Results could not be processed."
            assessment.finished_at = lifecycle.now()
            db.commit()
            raise
        removed = lifecycle.apply_retention(db, assessment.project_id)
        if removed:
            log.info("retention removed %d old assessment(s) for project %s", removed, assessment.project_id)



