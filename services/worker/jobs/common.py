"""Shared worker plumbing: DB sessions, Sandbox Manager client, job state."""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import contextmanager

import httpx
from sqlalchemy.orm import Session

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


class ManagerClient:
    def __init__(self) -> None:
        self.client = httpx.Client(
            base_url=os.environ.get("SANDBOX_MANAGER_URL", "http://sandbox-manager:8100"),
            headers={"Authorization": f"Bearer {os.environ.get('SANDBOX_MANAGER_TOKEN', '')}"},
            timeout=httpx.Timeout(20.0, connect=5.0),
        )

    def start(self, spec: dict) -> dict:
        try:
            r = self.client.post("/runs", json=spec)
        except httpx.HTTPError as exc:
            raise InfrastructureError("The Sandbox Manager is unavailable.") from exc
        if r.status_code == 422:
            raise ValueError(r.json().get("detail", "The sandbox request was rejected."))
        if r.status_code != 201:
            raise InfrastructureError(f"The Sandbox Manager refused the run ({r.status_code}).")
        return r.json()

    def get(self, run_id: str) -> dict | None:
        try:
            r = self.client.get(f"/runs/{run_id}")
        except httpx.HTTPError:
            return None
        if r.status_code == 404:
            return {"status": "failed", "error": "The sandbox run was lost (the Sandbox Manager restarted)."}
        return r.json() if r.status_code == 200 else None

    def cancel(self, run_id: str) -> None:
        try:
            self.client.delete(f"/runs/{run_id}")
        except httpx.HTTPError:
            pass

    def close(self) -> None:
        self.client.close()


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


def supervise(db: Session, manager: ManagerClient, job: AssessmentJob, run: dict, *, deadline_seconds: int) -> dict:
    """Poll the sandbox run, mirroring its progress into the job record."""
    run_id = run["id"]
    deadline = time.monotonic() + deadline_seconds
    job.details = {**(job.details or {}), "run_id": run_id}
    db.commit()
    last_seen: dict = run
    while True:
        state = manager.get(run_id)
        if state is not None:
            last_seen = state
            events = state.get("events") or []
            if events:
                stages = list(dict.fromkeys(e["stage"] for e in events))
                job.stage = events[-1]["stage"][:64]
                job.message = (events[-1].get("message") or "")[:500]
                job.stages_completed = stages[:-1]
            db.commit()
            if state.get("status") in ("completed", "failed", "cancelled", "timeout"):
                return state
        db.refresh(job.assessment)
        if job.assessment.cancel_requested:
            manager.cancel(run_id)
        if time.monotonic() > deadline:
            manager.cancel(run_id)
            return {**last_seen, "status": "timeout", "error": "The assessment step exceeded its time limit."}
        time.sleep(POLL_SECONDS)
