"""Remediation job tests (real PostgreSQL + Redis): M0 foundations only.

No LLM/sandbox work yet - this just proves a Remediation row can be queued
on the `remediate` queue and run to completion by the worker job function.
"""

import uuid

from rq import Queue

from routes_shared.enums import RemediationStatus

from app.core.redis import get_redis
from app.models import Assessment, Project, Remediation, SecurityFinding, User
from app.services import lifecycle, queueing
from worker.jobs import remediate


def make_finding(db) -> SecurityFinding:
    user = User(email=f"{uuid.uuid4().hex}@x.io", password_hash="x", display_name="")
    db.add(user)
    db.flush()
    project = Project(
        owner_id=user.id, name="p", website_url="https://example.com/", hostname="example.com",
        authorised_at=lifecycle.now(), authorisation_statement="ok",
    )
    db.add(project)
    db.flush()
    assessment = Assessment(project_id=project.id, status="completed", target_url="https://example.com/")
    db.add(assessment)
    db.flush()
    finding = SecurityFinding(
        assessment_id=assessment.id, type="SQL Injection", status="potential", severity="high", confidence="high",
        title="t", file="app/api/x/route.ts", line=6, endpoint="/api/x", method="GET",
        rule_id="routes.sqli.pg-tainted-query", plain_description="p", evidence_summary="e", technical_details={},
        recommendation="r", fingerprint=uuid.uuid4().hex[:32],
    )
    db.add(finding)
    db.commit()
    return finding


def test_remediation_job_can_be_queued_and_appears_in_db(db):
    finding = make_finding(db)
    remediation = Remediation(finding_id=finding.id, status=RemediationStatus.PENDING)
    db.add(remediation)
    db.commit()

    queueing.enqueue_job("remediate", remediation.id, finding_id=str(finding.id))
    queue = Queue("remediate", connection=get_redis())
    queued = queue.fetch_job(str(remediation.id))
    assert queued is not None
    queued.delete()

    remediate.run_remediate_job(str(remediation.id), str(finding.id))

    db.expire_all()
    row = db.get(Remediation, remediation.id)
    assert row.status == RemediationStatus.SUCCEEDED
    assert row.started_at is not None
    assert row.finished_at is not None
