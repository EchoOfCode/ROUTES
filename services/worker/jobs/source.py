"""Source analysis job: run the analyzer sandbox and persist structured results.

Only metadata and redacted evidence are stored; source files never leave the
sandbox, which is destroyed (with its tmpfs workspace) after the run.
"""

from __future__ import annotations

import logging

from pydantic import ValidationError
from sqlalchemy import delete, select

from routes_shared.contracts import SourceResult
from routes_shared.enums import JobStatus
from routes_core.mapping import source_records

from app.models import DetectedTechnology, DiscoveredEndpoint, ProjectIntegration, SecurityFinding, SourceAnalysisResult
from worker.jobs.common import ManagerClient, begin, complete, db_session, finish, supervise

log = logging.getLogger("routes.worker.source")
DEADLINE = 1100


def run_source_job(job_id: str, credential_handle: str | None = None) -> None:
    manager = ManagerClient()
    try:
        with db_session() as db:
            started = begin(db, job_id)
            if started is None:
                return
            job, assessment = started
            assessment_id = assessment.id
            details = job.details or {}
            try:
                spec = {"kind": "source", "source": details.get("source"), "target_url": assessment.target_url}
                if details.get("source") == "zip":
                    spec["upload_id"] = details.get("upload_id")
                else:
                    spec.update(owner=details.get("owner"), repo=details.get("repo"), ref=details.get("ref"),
                                credential_handle=credential_handle)
                try:
                    run = manager.start(spec)
                except ValueError as exc:
                    complete(db, job, JobStatus.FAILED, f"The source could not be analysed: {exc}")
                    return
                state = supervise(db, manager, job, run, deadline_seconds=DEADLINE)
                db.refresh(assessment)
                if state.get("status") == "cancelled" or assessment.cancel_requested:
                    complete(db, job, JobStatus.CANCELLED, "Cancelled.")
                    return
                if state.get("status") != "completed":
                    error = (state.get("result") or {}).get("error") or state.get("error") or "Source analysis did not complete."
                    complete(db, job, JobStatus.FAILED, error)
                    return
                try:
                    result = SourceResult.model_validate(state["result"])
                except (ValidationError, KeyError, TypeError) as exc:
                    log.warning("invalid analyzer output: %s", exc)
                    complete(db, job, JobStatus.FAILED, "The analysis sandbox returned malformed results.")
                    return
                persist(db, assessment, result)
                complete(db, job, JobStatus.COMPLETED, details={
                    "support_status": result.support_status,
                    "findings": len(result.findings),
                    "semgrep_failed": bool(state["result"].get("semgrep_failed")),
                })
            except Exception:
                db.rollback()
                complete(db, job, JobStatus.FAILED, "An internal error interrupted source analysis.")
                raise
            finally:
                finish(db, assessment_id)
    finally:
        manager.close()


def persist(db, assessment, result: SourceResult) -> None:
    db.execute(delete(SourceAnalysisResult).where(SourceAnalysisResult.assessment_id == assessment.id))
    db.execute(delete(SecurityFinding).where(SecurityFinding.assessment_id == assessment.id))
    db.execute(delete(DetectedTechnology).where(DetectedTechnology.assessment_id == assessment.id,
                                                DetectedTechnology.source == "repository"))
    db.execute(delete(DiscoveredEndpoint).where(DiscoveredEndpoint.assessment_id == assessment.id,
                                                DiscoveredEndpoint.origin == "source_route"))
    records = source_records(result)
    db.add(SourceAnalysisResult(assessment_id=assessment.id, **records.analysis))
    for f in records.findings:
        db.add(SecurityFinding(assessment_id=assessment.id, **f))
    for t in records.technologies:
        db.add(DetectedTechnology(assessment_id=assessment.id, **t))
    for e in records.endpoints:
        db.add(DiscoveredEndpoint(assessment_id=assessment.id, **e))
    # Discovery and source jobs run concurrently: lock and re-read the row so neither
    # overwrites the other's summary keys with a stale copy.
    db.refresh(assessment, with_for_update=True)
    assessment.discovery_summary = {**(assessment.discovery_summary or {}), **records.summary}
    integration = db.scalar(select(ProjectIntegration).where(ProjectIntegration.project_id == assessment.project_id))
    if integration is not None:
        integration.match_evidence = records.match_evidence
