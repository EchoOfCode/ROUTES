"""Website discovery job: run the discovery sandbox and persist its results."""

from __future__ import annotations

import logging

from pydantic import ValidationError
from sqlalchemy import delete

from routes_shared.contracts import DiscoveryResult
from routes_shared.enums import JobStatus
from routes_core.mapping import discovery_records, network_summary

from app.models import DetectedTechnology, DiscoveredEndpoint, DiscoveredPage
from worker.jobs.common import ManagerClient, begin, complete, db_session, finish, supervise

log = logging.getLogger("routes.worker.discovery")
DEADLINE = 840  # below the RQ job timeout (900s)


def run_discovery_job(job_id: str) -> None:
    manager = ManagerClient()
    try:
        with db_session() as db:
            started = begin(db, job_id)
            if started is None:
                return
            job, assessment = started
            assessment_id = assessment.id
            try:
                try:
                    run = manager.start({"kind": "discovery", "target_url": assessment.target_url})
                except ValueError as exc:
                    complete(db, job, JobStatus.FAILED, f"The website URL was rejected: {exc}")
                    return
                state = supervise(db, manager, job, run, deadline_seconds=DEADLINE)
                db.refresh(assessment)
                net = network_summary(state)
                if state.get("status") == "cancelled" or assessment.cancel_requested:
                    complete(db, job, JobStatus.CANCELLED, "Cancelled.", {"network": net})
                    return
                if state.get("status") != "completed":
                    result = state.get("result") or {}
                    error = result.get("error") or state.get("error") or "Website discovery did not complete."
                    if result.get("manifest"):
                        assessment.manifest_detected = bool(result["manifest"].get("detected"))
                    complete(db, job, JobStatus.FAILED, error, {"network": net})
                    return
                try:
                    result = DiscoveryResult.model_validate(state["result"])
                except (ValidationError, KeyError, TypeError) as exc:
                    log.warning("invalid discovery output: %s", exc)
                    complete(db, job, JobStatus.FAILED, "The discovery sandbox returned malformed results.")
                    return
                persist(db, assessment, result, net)
                complete(db, job, JobStatus.COMPLETED, details={"network": net,
                                                                "requests_made": state["result"].get("requests_made")})
            except Exception:
                db.rollback()
                complete(db, job, JobStatus.FAILED, "An internal error interrupted website discovery.")
                raise
            finally:
                finish(db, assessment_id)
    finally:
        manager.close()


def persist(db, assessment, result: DiscoveryResult, network: dict) -> None:
    # Replace (not append) so a retried job never duplicates rows.
    for model in (DiscoveredPage, DetectedTechnology):
        stmt = delete(model).where(model.assessment_id == assessment.id)
        if model is DetectedTechnology:
            stmt = stmt.where(DetectedTechnology.source == "website")
        db.execute(stmt)
    db.execute(delete(DiscoveredEndpoint).where(DiscoveredEndpoint.assessment_id == assessment.id,
                                                DiscoveredEndpoint.origin != "source_route"))
    records = discovery_records(result, network)
    for page in records.pages:
        db.add(DiscoveredPage(assessment_id=assessment.id, **page))
    for e in records.endpoints:
        db.add(DiscoveredEndpoint(assessment_id=assessment.id, **e))
    for t in records.technologies:
        db.add(DetectedTechnology(assessment_id=assessment.id, **t))
    # Discovery and source jobs run concurrently: lock and re-read the row so neither
    # overwrites the other's summary keys with a stale copy.
    db.refresh(assessment, with_for_update=True)
    assessment.manifest_detected = records.manifest_detected
    assessment.manifest_data = records.manifest_data
    assessment.discovery_summary = {**(assessment.discovery_summary or {}), **records.summary}
