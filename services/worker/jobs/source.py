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
from routes_shared.redaction import redact_structure, redact_text

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
    clean = redact_structure(result.model_dump(), max_length=2000)  # defence in depth
    profile = clean["profile"]
    db.add(SourceAnalysisResult(
        assessment_id=assessment.id, source_kind=result.source_kind, support_status=result.support_status,
        support_reason=clean["support_reason"], framework=profile["framework"], runtime=profile["runtime"],
        profile=profile, routes=clean["routes"], db_interactions=clean["db_interactions"],
        input_sources=clean["input_sources"], config_refs=clean["config_refs"], env_var_names=clean["env_var_names"],
        match_evidence=clean["match_evidence"], warnings=clean["warnings"],
    ))
    seen = set()
    for f in state_findings(clean):
        key = f.pop("fingerprint")
        if key in seen:
            continue
        seen.add(key)
        db.add(SecurityFinding(assessment_id=assessment.id, fingerprint=key, **f))
    if profile["framework"] != "Unknown":
        evidence = [f"package.json dependency {profile['framework']} {profile.get('framework_version') or ''}".strip()]
        db.add(DetectedTechnology(assessment_id=assessment.id, name=profile["framework"], category="framework",
                                  version=profile.get("framework_version"), confidence="high", source="repository",
                                  evidence=evidence))
    for lib in profile.get("database_libraries", [])[:20]:
        db.add(DetectedTechnology(assessment_id=assessment.id, name=lib, category="database_library", version=None,
                                  confidence="high", source="repository", evidence=["Declared in package.json"]))
    for r in clean["routes"][:500]:
        for method in r["methods"] or ["ANY"]:
            db.add(DiscoveredEndpoint(assessment_id=assessment.id, method=method[:16], url=r["path"], path=r["path"],
                                      origin="source_route", parameters=[],
                                      details={"file": r["file"], "line": r["line"], "router": r["router"]},
                                      evidence=f"Route handler in {r['file']}"[:500], page_url=None))
    assessment.discovery_summary = {**(assessment.discovery_summary or {}), "source_framework": profile["framework"],
                                    "source_support": result.support_status}
    integration = db.scalar(select(ProjectIntegration).where(ProjectIntegration.project_id == assessment.project_id))
    if integration is not None:
        integration.match_evidence = clean["match_evidence"]


def state_findings(clean: dict) -> list[dict]:
    out = []
    for f in clean["findings"]:
        out.append({
            "type": f["type"], "status": f["status"], "severity": f["severity"], "confidence": f["confidence"],
            "title": f["title"], "file": f["file"], "line": f["line"], "endpoint": f["endpoint"],
            "method": (f["method"] or None) and f["method"][:16], "rule_id": f["rule_id"],
            "plain_description": f["plain_description"], "evidence_summary": redact_text(f["evidence_summary"], max_length=2000),
            "technical_details": f["technical_details"], "recommendation": f["recommendation"],
            "fingerprint": f.get("fingerprint") or _fingerprint(f),
        })
    return out


def _fingerprint(f: dict) -> str:
    import hashlib

    return hashlib.sha256(f"{f['rule_id']}|{f['file']}|{f['line']}|{f['method']}".encode()).hexdigest()[:32]
