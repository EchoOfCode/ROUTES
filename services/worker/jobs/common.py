"""Shared worker plumbing: DB sessions, Sandbox Manager client, job state."""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import contextmanager

from sqlalchemy.orm import Session

from routes_core.engine import EngineClient, EngineUnavailable
from routes_core.runner import poll_run, summarise

from routes_shared.enums import TERMINAL_ASSESSMENT_STATUSES, TERMINAL_JOB_STATUSES, JobStatus

from app.core.db import get_sessionmaker
from app.models import Assessment, AssessmentJob
from app.services import lifecycle, queueing

log = logging.getLogger("routes.worker")

POLL_SECONDS = 2.0


class InfrastructureError(Exception):
    """Raised (and retried by RQ) only when ROUTES' own services are unavailable."""


@contextmanager
def db_session():
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


class ManagerClient(EngineClient):
    """Engine client for workers: infrastructure failures become retryable errors."""

    def __init__(self) -> None:
        super().__init__(os.environ.get("SANDBOX_MANAGER_URL", "http://sandbox-manager:8100"),
                         os.environ.get("SANDBOX_MANAGER_TOKEN", ""))

    def start(self, spec: dict) -> dict:
        try:
            return super().start(spec)
        except EngineUnavailable as exc:
            raise InfrastructureError(str(exc)) from exc


def begin(db: Session, job_id: str) -> tuple[AssessmentJob, Assessment] | None:
    """Mark a job running unless it is already terminal (idempotent re-delivery)."""
    job = db.get(AssessmentJob, uuid.UUID(job_id), with_for_update=True)
    if job is None or job.status in TERMINAL_JOB_STATUSES:
        db.rollback()
        return None
    assessment = db.get(Assessment, job.assessment_id)
    if assessment is None or assessment.status in TERMINAL_ASSESSMENT_STATUSES or assessment.cancel_requested:
        job.status = JobStatus.CANCELLED
        job.finished_at = lifecycle.now()
        db.commit()
        finish(db, job.assessment_id)
        return None
    job.status = JobStatus.RUNNING
    job.attempts += 1
    job.started_at = job.started_at or lifecycle.now()
    job.error = None
    lifecycle.refresh_phase(db, assessment)
    db.commit()
    return job, assessment


def complete(db: Session, job: AssessmentJob, status: str, error: str | None = None, details: dict | None = None) -> None:
    job.status = status
    job.error = (error or None) and error[:1000]
    job.finished_at = lifecycle.now()
    if details:
        job.details = {**(job.details or {}), **details}
    if status == JobStatus.COMPLETED:
        job.stage = "done"
        job.message = None
    db.commit()


def finish(db: Session, assessment_id) -> None:
    try:
        lifecycle.maybe_finalize(db, assessment_id, queueing.enqueue_job)
    except Exception:  # noqa: BLE001
        log.exception("could not enqueue results for %s", assessment_id)
        raise InfrastructureError("Could not enqueue result processing.")


def supervise(db: Session, manager, job: AssessmentJob, run: dict, *, deadline_seconds: int) -> dict:
    """Poll the sandbox run, mirroring its progress into the job record."""
    job.details = {**(job.details or {}), "run_id": run["id"]}
    db.commit()

    def on_state(state: dict) -> None:
        progress = summarise(state.get("events") or [])
        if progress.current_stage:
            job.stage = progress.current_stage[:64]
            job.message = progress.message[:500]
            job.stages_completed = list(progress.completed_stages)
        db.commit()

    def should_cancel() -> bool:
        db.refresh(job.assessment)
        return bool(job.assessment.cancel_requested)

    return poll_run(manager, run, deadline_seconds=deadline_seconds, on_state=on_state,
                    should_cancel=should_cancel, poll_seconds=POLL_SECONDS)
