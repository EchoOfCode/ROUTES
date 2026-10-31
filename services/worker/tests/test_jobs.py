"""Assessment lifecycle tests for worker jobs (fake Sandbox Manager, real PostgreSQL)."""

import uuid

import pytest
from sqlalchemy import select, text

from app.core.db import get_engine, get_sessionmaker
from app.models import (
    Assessment,
    AssessmentJob,
    Base,
    DiscoveredEndpoint,
    DiscoveredPage,
    Project,
    ProjectIntegration,
    SecurityFinding,
    SourceAnalysisResult,
    User,
)
from app.services import lifecycle, queueing
from worker.jobs import common, discovery, results, source

DISCOVERY_RESULT = {
    "target_url": "https://example.com/", "hostname": "example.com", "reachable": True,
    "manifest": {"checked": True, "detected": True, "valid": True, "status_code": 200,
                 "data": {"routes_enabled": True, "integration": "routes", "supported_assessments": ["sqli"], "version": "1.0"}},
    "pages": [{"url": "https://example.com/", "status_code": 200, "title": "Home"},
              {"url": "https://example.com/login", "status_code": 200, "title": "Login", "is_login": True}],
    "forms": [{"page_url": "https://example.com/login", "action": "https://example.com/api/login", "method": "POST",
               "fields": [{"name": "email", "type": "email"}]}],
    "endpoints": [{"method": "POST", "url": "https://example.com/api/login", "path": "/api/login", "origin": "form",
                   "parameters": ["email"], "page_url": "https://example.com/login"},
                  {"method": "GET", "url": "https://example.com/api/search", "path": "/api/search", "origin": "js_reference"}],
    "technologies": [{"name": "Next.js", "category": "framework", "confidence": "high", "evidence": ["x-powered-by"]}],
    "stack": {"framework": "Next.js", "language": "JavaScript", "runtime": "Node.js", "database": "Unknown", "confidence": "high"},
}

SOURCE_RESULT = {
    "source_kind": "github", "support_status": "supported", "support_reason": "ok",
    "profile": {"framework": "Next.js", "runtime": "Node.js", "database_libraries": ["PostgreSQL (pg)"]},
    "routes": [{"path": "/api/search", "methods": ["GET"], "file": "app/api/search/route.ts", "line": 4, "router": "app"}],
    "findings": [{
        "type": "SQL Injection", "status": "potential", "severity": "high", "confidence": "high", "title": "t",
        "file": "app/api/search/route.ts", "line": 6, "endpoint": "/api/search", "method": "GET",
        "rule_id": "routes.sqli.pg-tainted-query", "plain_description": "p",
        "evidence_summary": 'const key = "sk_live_abcdefghijklmnopqrstuvwx"', "recommendation": "r",
        "technical_details": {}, "fingerprint": "f1"}],
    "match_evidence": [{"kind": "homepage", "detail": "x", "matches_target": True}],
}


class FakeManager:
    runs: dict = {}
    script: dict = {}
    started: list = []

    def __init__(self):
        pass

    def start(self, spec):
        FakeManager.started.append(spec)
        run_id = uuid.uuid4().hex
        FakeManager.runs[run_id] = FakeManager.script[spec["kind"]]
        return {"id": run_id, "status": "running"}

    def get(self, run_id):
        return {"id": run_id, "events": [{"stage": "discovering_pages", "message": "2 pages"}], **FakeManager.runs[run_id]}

    def cancel(self, run_id):
        FakeManager.runs[run_id] = {"status": "cancelled"}

    def close(self):
        pass


@pytest.fixture(autouse=True)
def env(monkeypatch):
    FakeManager.runs.clear()
    FakeManager.started.clear()
    FakeManager.script = {"discovery": {"status": "completed", "result": DISCOVERY_RESULT},
                          "source": {"status": "completed", "result": SOURCE_RESULT}}
    enqueued = []
    monkeypatch.setattr(common, "POLL_SECONDS", 0)
    for mod in (discovery, source):
        monkeypatch.setattr(mod, "ManagerClient", FakeManager)
    monkeypatch.setattr(queueing, "enqueue_job", lambda kind, job_id, **kw: enqueued.append((str(kind), str(job_id), kw)))
    yield enqueued
    tables = ", ".join(t.name for t in reversed(Base.metadata.sorted_tables))
    with get_engine().begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} CASCADE"))


def make_assessment(db, *, with_source=True, match="confirmed"):
    user = User(email=f"{uuid.uuid4().hex}@x.io", password_hash="x", display_name="")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="p", website_url="https://example.com/", hostname="example.com",
                      authorised_at=lifecycle.now(), authorisation_statement="ok")
    db.add(project)
    db.flush()
    integration = ProjectIntegration(project_id=project.id, kind="github_public", repo_owner="a", repo_name="b",
                                     match_status=match)
    db.add(integration)
    db.commit()
    details = {"source": "github", "owner": "a", "repo": "b", "ref": None} if with_source else None
    assessment, jobs = lifecycle.create_assessment(db, project, integration=integration, source_details=details)
    return assessment, {j.kind: j for j in jobs}


def run_results(db, enqueued):
    for kind, job_id, kw in list(enqueued):
        if kind == "results":
            results.run_results_job(job_id, kw["assessment_id"])


def test_full_lifecycle_completed(db, env):
    a, jobs = make_assessment(db)
    discovery.run_discovery_job(str(jobs["discovery"].id))
    assert [k for k, *_ in env] == []  # source still pending
    source.run_source_job(str(jobs["source"].id))
    assert [k for k, *_ in env] == ["results"]
    run_results(db, env)
    db.expire_all()
    a = db.get(Assessment, a.id)
    assert a.status == "completed" and a.finished_at and a.error is None
    assert a.manifest_detected is True
    assert len(db.scalars(select(DiscoveredPage).where(DiscoveredPage.assessment_id == a.id)).all()) == 2
    finding = db.scalar(select(SecurityFinding).where(SecurityFinding.assessment_id == a.id))
    assert finding.status == "potential"
    assert "sk_live_abcdefghijklmnopqrstuvwx" not in finding.evidence_summary  # redacted before storage
    assert db.scalar(select(SourceAnalysisResult).where(SourceAnalysisResult.assessment_id == a.id)) is not None
    js_ep = db.scalar(select(DiscoveredEndpoint).where(DiscoveredEndpoint.path == "/api/search",
                                                       DiscoveredEndpoint.origin == "js_reference"))
    assert js_ep.details["source_file"] == "app/api/search/route.ts"  # correlated (match confirmed)
    stages = db.get(AssessmentJob, jobs["discovery"].id)
    assert stages.status == "completed"


def test_failed_discovery_is_partial_not_completed(db, env):
    FakeManager.script["discovery"] = {"status": "failed", "error": "x",
                                       "result": {"fatal": True, "error": "The website could not be reached: timeout"}}
    a, jobs = make_assessment(db)
    discovery.run_discovery_job(str(jobs["discovery"].id))
    source.run_source_job(str(jobs["source"].id))
    run_results(db, env)
    db.expire_all()
    a = db.get(Assessment, a.id)
    assert a.status == "partially_completed"
    assert "could not be reached" in a.error
    assert db.get(AssessmentJob, jobs["discovery"].id).error.startswith("The website could not be reached")


def test_everything_failed(db, env):
    FakeManager.script["discovery"] = {"status": "timeout", "error": "The sandbox exceeded its time limit."}
    a, jobs = make_assessment(db, with_source=False)
    discovery.run_discovery_job(str(jobs["discovery"].id))
    run_results(db, env)
    db.expire_all()
    assert db.get(Assessment, a.id).status == "failed"


def test_malformed_sandbox_output_rejected(db, env):
    FakeManager.script["discovery"] = {"status": "completed", "result": {"pages": "not a list"}}
    a, jobs = make_assessment(db, with_source=False)
    discovery.run_discovery_job(str(jobs["discovery"].id))
    db.expire_all()
    job = db.get(AssessmentJob, jobs["discovery"].id)
    assert job.status == "failed" and "malformed" in job.error


def test_redelivered_job_is_not_run_twice(db, env):
    a, jobs = make_assessment(db, with_source=False)
    discovery.run_discovery_job(str(jobs["discovery"].id))
    discovery.run_discovery_job(str(jobs["discovery"].id))
    assert len(FakeManager.started) == 1
    assert len(db.scalars(select(DiscoveredPage).where(DiscoveredPage.assessment_id == a.id)).all()) == 2


def test_cancelled_before_start(db, env):
    a, jobs = make_assessment(db, with_source=False)
    a.cancel_requested = True
    db.commit()
    discovery.run_discovery_job(str(jobs["discovery"].id))
    assert FakeManager.started == []
    run_results(db, env)
    db.expire_all()
    assert db.get(Assessment, a.id).status == "cancelled"


def test_retention_after_completion(db, env):
    a, jobs = make_assessment(db, with_source=False)
    project_id, first_id = a.project_id, a.id
    discovery.run_discovery_job(str(jobs["discovery"].id))
    run_results(db, env)
    for _ in range(6):
        env.clear()
        project = db.get(Project, project_id)
        new, new_jobs = lifecycle.create_assessment(db, project, integration=None, source_details=None)
        discovery.run_discovery_job(str(new_jobs["discovery"].id) if isinstance(new_jobs, dict) else
                                    str(next(j for j in new_jobs if j.kind == "discovery").id))
        run_results(db, env)
    db.expire_all()
    remaining = db.scalars(select(Assessment).where(Assessment.project_id == project_id)).all()
    assert len(remaining) == 5
    assert first_id not in {r.id for r in remaining}
    assert db.get(ProjectIntegration, db.scalar(select(ProjectIntegration.id))) is not None


def test_concurrent_discovery_and_source_keep_both_summaries(db):
    """Regression: the source job used to overwrite discovery_summary with a stale copy."""
    from routes_shared.contracts import DiscoveryResult, SourceResult

    assessment, _ = make_assessment(db)
    with get_sessionmaker()() as other:
        stale = other.get(Assessment, assessment.id)
        _ = stale.discovery_summary                       # source worker loaded the row earlier
        with get_sessionmaker()() as first:
            a1 = first.get(Assessment, assessment.id)
            discovery.persist(first, a1, DiscoveryResult.model_validate(DISCOVERY_RESULT), {"requests": 1})
            first.commit()                                # discovery finished in between
        source.persist(other, stale, SourceResult.model_validate(SOURCE_RESULT))
        other.commit()
    db.expire_all()
    summary = db.get(Assessment, assessment.id).discovery_summary
    assert summary["pages_total"] == 2 and summary["source_framework"] == "Next.js"
