"""Website discovery job: run the discovery sandbox and persist its results."""

from __future__ import annotations

import logging

from pydantic import ValidationError
from sqlalchemy import delete

from routes_shared.contracts import DiscoveryResult
from routes_shared.enums import JobStatus
from routes_shared.redaction import redact_text

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
                summary = state.get("network_summary") or {}
                net = {k: summary.get(k) for k in ("requests", "allowed", "denied", "denied_reasons", "destinations")}
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
    seen_pages = set()
    for p in result.pages[:result.page_limit + 5]:
        if p.url in seen_pages:
            continue
        seen_pages.add(p.url)
        db.add(DiscoveredPage(assessment_id=assessment.id, **p.model_dump()))
    for e in result.endpoints:
        details = {}
        if e.origin == "form":
            form = next((f for f in result.forms if f.action == e.url and f.page_url == e.page_url), None)
            if form is not None:
                details = {"fields": [f.model_dump() for f in form.fields]}
        db.add(DiscoveredEndpoint(assessment_id=assessment.id, method=e.method[:16], url=e.url, path=e.path,
                                  origin=e.origin, parameters=list(e.parameters), details=details,
                                  evidence=redact_text(e.evidence, max_length=500), page_url=e.page_url))
    for t in result.technologies:
        db.add(DetectedTechnology(assessment_id=assessment.id, name=t.name, category=t.category, version=t.version,
                                  confidence=t.confidence, source="website", evidence=list(t.evidence)))
    assessment.manifest_detected = result.manifest.detected
    assessment.manifest_data = result.manifest.model_dump() if result.manifest.checked else None
    pages_ok = sum(1 for p in result.pages if not p.error)
    assessment.discovery_summary = {
        **(assessment.discovery_summary or {}),
        "stack": result.stack.model_dump(),
        "pages_total": len(result.pages),
        "pages_inspected": pages_ok,
        "pages_failed": len(result.pages) - pages_ok,
        "page_limit": result.page_limit,
        "page_limit_reached": result.page_limit_reached,
        "rendered_pages": sum(1 for p in result.pages if p.rendered),
        "login_pages": [p.url for p in result.pages if p.is_login][:10],
        "registration_pages": [p.url for p in result.pages if p.is_registration][:10],
        "robots": result.robots.model_dump(),
        "sitemap_urls": result.sitemap_urls,
        "scripts": result.scripts[:200],
        "scripts_count": len(result.scripts),
        "external_hosts": result.external_hosts[:200],
        "openapi": [o.model_dump() for o in result.openapi],
        "forms_count": len(result.forms),
        "network": network,
    }
