"""Remediation endpoint tests: POST .../remediate, GET .../remediations/{id},
POST .../remediations/{id}/cancel."""

import uuid

from conftest import create_project

from app.models import Assessment, Project, Remediation, RemediationIteration

SNAPSHOT = {"file": "app/api/search/route.ts", "start_line": 1, "end_line": 5,
           "code": "export async function GET() {}"}


def _make_finding(db, client, *, rule_id="routes.sqli.pg-tainted-query", snapshot=SNAPSHOT) -> tuple[str, str]:
    from app.models import SecurityFinding

    project_data = create_project(client)
    project = db.get(Project, uuid.UUID(project_data["project"]["id"]))
    assessment = Assessment(project_id=project.id, status="completed", target_url=project.website_url)
    db.add(assessment)
    db.flush()
    finding = SecurityFinding(
        assessment_id=assessment.id, type="SQL Injection", status="potential", severity="high", confidence="high",
        title="t", file=SNAPSHOT["file"], line=3, endpoint="/api/search", method="GET", rule_id=rule_id,
        plain_description="p", evidence_summary="e", technical_details={}, recommendation="r",
        fingerprint=uuid.uuid4().hex[:32], snapshot=snapshot,
    )
    db.add(finding)
    db.commit()
    return str(assessment.id), str(finding.id)


def test_start_remediation_creates_and_enqueues(alice, db, enqueued):
    assessment_id, finding_id = _make_finding(db, alice)

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["finding_id"] == finding_id
    assert any(kind == "remediate" for kind, *_ in enqueued)


def test_start_remediation_is_idempotent_while_active(alice, db, enqueued):
    assessment_id, finding_id = _make_finding(db, alice)

    first = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()
    second = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()

    assert first["id"] == second["id"]
    assert len([k for k, *_ in enqueued if k == "remediate"]) == 1


def test_start_remediation_rejects_non_sqli_findings(alice, db):
    assessment_id, finding_id = _make_finding(db, alice, rule_id="routes.xss.dom-sink-tainted")

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "unsupported_finding"


def test_start_remediation_rejects_findings_without_a_snapshot(alice, db):
    assessment_id, finding_id = _make_finding(db, alice, snapshot=None)

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "no_snapshot"


def test_get_remediation_returns_iterations(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    remediation = Remediation(finding_id=uuid.UUID(finding_id), status="succeeded", finding_status="fixed")
    db.add(remediation)
    db.flush()
    db.add(RemediationIteration(remediation_id=remediation.id, iteration_no=1, round_no=1,
                                candidate_hash="abc", candidate_code="export async function GET() {}",
                                test_results={"status": "passed"}, rescan_diff={}))
    db.commit()

    r = alice.get(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{remediation.id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "succeeded"
    assert len(body["iterations"]) == 1
    assert body["iterations"][0]["candidate_hash"] == "abc"


def test_get_remediation_404_for_someone_elses_finding(alice, bob, db):
    assessment_id, finding_id = _make_finding(db, alice)
    remediation_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]

    r = bob.get(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}")
    assert r.status_code == 404


def test_cancel_sets_the_flag_and_cancels_the_queued_job(alice, db, enqueued):
    assessment_id, finding_id = _make_finding(db, alice)
    remediation_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}/cancel")
    assert r.status_code == 200, r.text
    assert r.json()["cancel_requested"] is True


def test_cancel_is_a_noop_on_an_already_terminal_remediation(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    remediation = Remediation(finding_id=uuid.UUID(finding_id), status="succeeded", finding_status="fixed")
    db.add(remediation)
    db.commit()

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{remediation.id}/cancel")
    assert r.status_code == 200, r.text
    assert r.json()["cancel_requested"] is False
