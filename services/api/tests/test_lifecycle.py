from datetime import timedelta

from conftest import create_project
from sqlalchemy import select

from app.models import Assessment, AssessmentJob, Project, SecurityFinding
from app.services import lifecycle


def _set_jobs(db, assessment_id, **statuses):
    for job in db.scalars(select(AssessmentJob).where(AssessmentJob.assessment_id == assessment_id)):
        if job.kind in statuses:
            job.status = statuses[job.kind]
            job.error = None if statuses[job.kind] == "completed" else "boom"
    db.commit()


def test_maybe_finalize_enqueues_results_once(alice, db):
    aid = create_project(alice)["assessment_id"]
    calls = []
    enqueue = lambda kind, job_id, **kw: calls.append(kind)  # noqa: E731
    assert lifecycle.maybe_finalize(db, aid, enqueue) is False  # discovery still queued
    _set_jobs(db, aid, discovery="completed")
    assert lifecycle.maybe_finalize(db, aid, enqueue) is True
    assert lifecycle.maybe_finalize(db, aid, enqueue) is False
    assert calls == ["results"]


def test_final_status_rules(alice, db):
    aid = create_project(alice)["assessment_id"]
    project = db.scalar(select(Project))
    a = db.get(Assessment, aid)
    a.jobs.append(AssessmentJob(kind="source", status="completed"))
    db.commit()
    for discovery, source, expected in [
        ("completed", "completed", "completed"),
        ("completed", "failed", "partially_completed"),
        ("failed", "completed", "partially_completed"),
        ("failed", "failed", "failed"),
    ]:
        _set_jobs(db, aid, discovery=discovery, source=source)
        db.refresh(a)
        status, error = lifecycle.compute_final_status(a)
        assert status == expected, (discovery, source)
        assert (error is None) == (expected == "completed")
    a.cancel_requested = True
    assert lifecycle.compute_final_status(a)[0] == "cancelled"
    assert project is not None


def test_attach_source_refused_after_results_enqueued(alice, db):
    aid = create_project(alice)["assessment_id"]
    _set_jobs(db, aid, discovery="completed")
    lifecycle.maybe_finalize(db, aid, lambda *a, **k: None)
    project = db.scalar(select(Project))
    from app.models import ProjectIntegration

    integ = ProjectIntegration(project_id=project.id, kind="github_public", repo_owner="a", repo_name="b")
    db.add(integ)
    db.commit()
    assert lifecycle.attach_source_job(db, aid, integ, {"source": "github"}) is None


def test_retention_keeps_five_and_never_deletes_active(alice, db):
    body = create_project(alice)
    project = db.get(Project, body["project"]["id"])
    first = db.get(Assessment, body["assessment_id"])
    first.status = "completed"
    db.commit()
    base = first.created_at
    for i in range(1, 7):
        a = Assessment(project_id=project.id, status="completed", target_url=project.website_url,
                       created_at=base + timedelta(minutes=i))
        db.add(a)
    db.commit()
    oldest_id = first.id
    db.add(SecurityFinding(assessment_id=oldest_id, type="SQL Injection", severity="high", confidence="high",
                           title="t", rule_id="r", plain_description="d", evidence_summary="e",
                           recommendation="r", fingerprint="f"))
    db.commit()
    # An older *active* assessment must survive retention.
    first.status = "discovering"
    db.commit()
    deleted = lifecycle.apply_retention(db, project.id)
    remaining = db.scalars(select(Assessment).where(Assessment.project_id == project.id)).all()
    assert deleted == 1
    assert len(remaining) == 6 and oldest_id in {a.id for a in remaining}
    first.status = "completed"
    db.commit()
    assert lifecycle.apply_retention(db, project.id) == 1
    assert db.scalar(select(SecurityFinding)) is None  # dependent findings cascaded
    assert len(db.scalars(select(Assessment)).all()) == 5
    assert db.get(Project, project.id) is not None  # project configuration retained


def test_reconcile_after_restart(alice, db):
    aid = create_project(alice)["assessment_id"]
    assert lifecycle.reconcile_after_restart(db) == 1
    db.expire_all()
    a = db.get(Assessment, aid)
    assert a.status == "failed" and "restarted" in a.error
    assert all(j.status == "failed" for j in a.jobs)
