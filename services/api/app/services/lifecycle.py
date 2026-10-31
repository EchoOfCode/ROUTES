"""Assessment lifecycle: creation, attaching work, finalisation and retention.

Shared by the API and the worker so the state machine lives in one place.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from routes_shared.enums import (
    ACTIVE_ASSESSMENT_STATUSES,
    TERMINAL_ASSESSMENT_STATUSES,
    TERMINAL_JOB_STATUSES,
    AssessmentStatus,
    JobKind,
    JobStatus,
)

from routes_core import status as status_rules

from app.core.config import get_settings
from app.core.errors import ApiError
from app.models import Assessment, AssessmentJob, Project, ProjectIntegration

log = logging.getLogger("routes.lifecycle")


def now() -> datetime:
    return datetime.now(UTC)


def source_label(integration: ProjectIntegration | None) -> str | None:
    if integration is None:
        return None
    if integration.kind == "zip":
        return integration.upload_filename
    ref = f"@{integration.repo_ref}" if integration.repo_ref else ""
    return f"{integration.repo_owner}/{integration.repo_name}{ref}"


def active_assessment(db: Session, project_id: uuid.UUID, *, lock: bool = False) -> Assessment | None:
    stmt = select(Assessment).where(
        Assessment.project_id == project_id, Assessment.status.in_(ACTIVE_ASSESSMENT_STATUSES)
    )
    if lock:
        stmt = stmt.with_for_update()
    return db.scalar(stmt)


def create_assessment(
    db: Session, project: Project, *, integration: ProjectIntegration | None, source_details: dict | None
) -> tuple[Assessment, list[AssessmentJob]]:
    """Create an assessment with a discovery job, optional source job and a results job.

    The partial unique index guarantees at most one active assessment per project.
    """
    assessment = Assessment(
        project_id=project.id,
        status=AssessmentStatus.QUEUED,
        target_url=project.website_url,
        source_kind=integration.kind if (integration and source_details is not None) else None,
        source_label=source_label(integration) if source_details is not None else None,
        discovery_summary={},
    )
    jobs = [AssessmentJob(kind=JobKind.DISCOVERY, status=JobStatus.QUEUED)]
    if source_details is not None:
        jobs.append(AssessmentJob(kind=JobKind.SOURCE, status=JobStatus.QUEUED, details=source_details))
    jobs.append(AssessmentJob(kind=JobKind.RESULTS, status=JobStatus.QUEUED, details={"enqueued": False}))
    assessment.jobs = jobs
    db.add(assessment)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ApiError(409, "assessment_active", "An assessment is already running for this project.") from exc
    return assessment, jobs


def attach_source_job(db: Session, assessment_id: uuid.UUID, integration: ProjectIntegration, details: dict):
    """Attach a source job to a still-running assessment. Returns the job or None
    if the assessment can no longer accept work (caller then starts a new one)."""
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id).with_for_update())
    if assessment is None or assessment.status not in ACTIVE_ASSESSMENT_STATUSES or assessment.cancel_requested:
        db.rollback()
        return None
    jobs = {j.kind: j for j in assessment.jobs}
    results = jobs.get(JobKind.RESULTS)
    if results is not None and results.details.get("enqueued"):
        db.rollback()
        return None
    existing = jobs.get(JobKind.SOURCE)
    if existing is not None:
        if existing.status not in TERMINAL_JOB_STATUSES:
            db.rollback()
            raise ApiError(409, "source_active", "Source analysis is already in progress for this assessment.")
        db.rollback()
        return None
    job = AssessmentJob(assessment_id=assessment.id, kind=JobKind.SOURCE, status=JobStatus.QUEUED, details=details)
    db.add(job)
    assessment.source_kind = integration.kind
    assessment.source_label = source_label(integration)
    db.commit()
    return job


def refresh_phase(db: Session, assessment: Assessment) -> None:
    """Derive the parent's in-progress status from its children."""
    if assessment.status in TERMINAL_ASSESSMENT_STATUSES:
        return
    running = {j.kind for j in assessment.jobs if j.status == JobStatus.RUNNING}
    if JobKind.DISCOVERY in running:
        assessment.status = AssessmentStatus.DISCOVERING
    elif JobKind.SOURCE in running:
        assessment.status = AssessmentStatus.ANALYSING
    elif running:
        assessment.status = AssessmentStatus.RUNNING
    if running and assessment.started_at is None:
        assessment.started_at = now()


def maybe_finalize(db: Session, assessment_id: uuid.UUID, enqueue) -> bool:
    """If every work job is terminal, enqueue the results job exactly once."""
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id).with_for_update())
    if assessment is None:
        db.rollback()
        return False
    work = [j for j in assessment.jobs if j.kind != JobKind.RESULTS]
    results = next((j for j in assessment.jobs if j.kind == JobKind.RESULTS), None)
    if results is None or any(j.status not in TERMINAL_JOB_STATUSES for j in work):
        db.rollback()
        return False
    if results.details.get("enqueued"):
        db.rollback()
        return False
    results.details = {**results.details, "enqueued": True}
    db.commit()
    enqueue(JobKind.RESULTS, results.id, assessment_id=str(assessment.id))
    return True


def compute_final_status(assessment: Assessment) -> tuple[str, str | None]:
    return status_rules.compute_final_status(assessment.jobs, cancel_requested=assessment.cancel_requested)


def apply_retention(db: Session, project_id: uuid.UUID) -> int:
    """Keep the newest N assessments; never delete active ones. Returns deleted count."""
    rows = db.scalars(
        select(Assessment).where(Assessment.project_id == project_id).order_by(Assessment.created_at.desc())
    ).all()
    victims = status_rules.retention_victims(rows, get_settings().assessment_history_limit)
    for a in victims:
        db.delete(a)  # FK cascades remove pages, endpoints, technologies, findings, jobs.
    if victims:
        db.commit()
    return len(victims)


def reconcile_after_restart(db: Session) -> int:
    """Mark work interrupted by a restart as failed and purge staged uploads."""
    ts = now()
    msg = "Interrupted because ROUTES was restarted."
    db.execute(
        update(AssessmentJob)
        .where(AssessmentJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]))
        .values(status=JobStatus.FAILED, error=msg, finished_at=ts)
    )
    result = db.execute(
        update(Assessment)
        .where(Assessment.status.in_(ACTIVE_ASSESSMENT_STATUSES))
        .values(status=AssessmentStatus.FAILED, error=msg, finished_at=ts)
    )
    db.commit()
    purge_uploads()
    return result.rowcount or 0


def purge_uploads() -> None:
    root = Path(get_settings().uploads_dir)
    if not root.is_dir():
        return
    for child in root.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        except OSError:
            log.warning("could not remove staged upload %s", child.name)
