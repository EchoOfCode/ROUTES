"""Orchestration used by the HTTP layer: start assessments and connect sources."""

from __future__ import annotations

import logging

from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from routes_shared.enums import AssessmentStatus, JobKind, JobStatus

from app.core.errors import ApiError
from app.models import Assessment, AssessmentJob, Project, ProjectIntegration
from app.services import lifecycle, queueing, sandbox_client
from app.services.uploads import discard_upload

log = logging.getLogger("routes.assessments")


def source_details_for(integration: ProjectIntegration, *, upload_id: str | None = None) -> dict:
    if integration.kind == "zip":
        return {"source": "zip", "upload_id": upload_id, "filename": integration.upload_filename}
    return {
        "source": "github",
        "owner": integration.repo_owner,
        "repo": integration.repo_name,
        "ref": integration.repo_ref,
        "private": integration.kind == "github_private",
    }


def _enqueue_or_fail(db: Session, assessment: Assessment, jobs: list[AssessmentJob], credential_handle: str | None):
    try:
        for job in jobs:
            if job.kind == JobKind.DISCOVERY:
                queueing.enqueue_job("discovery", job.id)
            elif job.kind == JobKind.SOURCE:
                queueing.enqueue_job("source", job.id, credential_handle=credential_handle)
    except RedisError as exc:
        log.exception("failed to enqueue assessment %s", assessment.id)
        for job in jobs:
            if job.status == JobStatus.QUEUED:
                job.status = JobStatus.FAILED
                job.error = "Could not be queued."
        assessment.status = AssessmentStatus.FAILED
        assessment.error = "The job queue is unavailable. Check that Redis is running."
        assessment.finished_at = lifecycle.now()
        db.commit()
        if credential_handle:
            sandbox_client.discard_credential(credential_handle)
        for job in jobs:
            if job.kind == JobKind.SOURCE:
                discard_upload(job.details.get("upload_id"))
        raise ApiError(503, "queue_unavailable", "The job queue is unavailable. Try again shortly.") from exc


def start_assessment(
    db: Session, project: Project, *, include_source: bool, token: str | None
) -> tuple[Assessment, list[str]]:
    notes: list[str] = []
    integration = project.integrations[0] if project.integrations else None
    details = None
    handle = None
    if include_source and integration is not None:
        if integration.kind == "zip":
            notes.append("ZIP archives are deleted after analysis. Upload the archive again to include source code.")
        elif integration.kind == "github_private" and not token:
            notes.append("Private repository tokens are never stored. Provide a token to include source analysis.")
        else:
            details = source_details_for(integration)
            if integration.kind == "github_private":
                handle = sandbox_client.store_ephemeral_credential(token, integration.repo_owner, integration.repo_name)
    try:
        assessment, jobs = lifecycle.create_assessment(db, project, integration=integration, source_details=details)
    except ApiError:
        if handle:
            sandbox_client.discard_credential(handle)
        raise
    _enqueue_or_fail(db, assessment, jobs, handle)
    return assessment, notes


def run_source_for(
    db: Session, project: Project, integration: ProjectIntegration, *, upload_id: str | None, credential_handle: str | None
) -> Assessment:
    """Analyse a newly connected source: join the active assessment if it can
    still accept work, otherwise start a fresh assessment (discovery + source)."""
    details = source_details_for(integration, upload_id=upload_id)
    active = lifecycle.active_assessment(db, project.id)
    if active is not None:
        job = lifecycle.attach_source_job(db, active.id, integration, details)
        if job is not None:
            db.refresh(active)
            _enqueue_or_fail(db, active, [job], credential_handle)
            return active
        db.expire_all()
        if lifecycle.active_assessment(db, project.id) is not None:
            raise ApiError(
                409, "assessment_finishing",
                "The current assessment is finishing. Start a new assessment once it completes.",
            )
    assessment, jobs = lifecycle.create_assessment(db, project, integration=integration, source_details=details)
    _enqueue_or_fail(db, assessment, jobs, credential_handle)
    return assessment


def cancel_assessment(db: Session, assessment: Assessment) -> None:
    if assessment.status not in lifecycle.ACTIVE_ASSESSMENT_STATUSES:
        raise ApiError(409, "not_active", "Only running assessments can be cancelled.")
    assessment.cancel_requested = True
    for job in assessment.jobs:
        if job.kind != JobKind.RESULTS and job.status == JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            job.finished_at = lifecycle.now()
            try:
                queueing.cancel_job(job.kind, job.id)
            except RedisError:
                pass
            if job.kind == JobKind.SOURCE:
                discard_upload(job.details.get("upload_id"))
    db.commit()
    try:
        lifecycle.maybe_finalize(db, assessment.id, queueing.enqueue_job)
    except RedisError:
        log.warning("results job could not be enqueued for cancelled assessment %s", assessment.id)
