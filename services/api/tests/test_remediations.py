"""Remediation endpoint tests (real PostgreSQL, the real migrations)."""

import uuid

from conftest import create_project
from sqlalchemy import select, update

from app.models import (
    Assessment,
    Project,
    Remediation,
    RemediationIteration,
    RemediationOutbox,
    RemediationPatchAttempt,
    RemediationPatchBatch,
    SecurityFinding,
    User,
)
from app.services import artifacts
from app.services import remediation_store as store

SNAPSHOT = {"file": "app/api/search/route.ts", "start_line": 1, "end_line": 5,
            "code": "export async function GET() {}"}


def _make_assessment(db, client) -> Assessment:
    project_data = create_project(client)
    project = db.get(Project, uuid.UUID(project_data["project"]["id"]))
    assessment = Assessment(project_id=project.id, status="completed", target_url=project.website_url)
    db.add(assessment)
    db.commit()
    return assessment


def _add_finding(db, assessment, *, rule_id="routes.sqli.pg-tainted-query", snapshot=SNAPSHOT,
                 file="app/api/search/route.ts") -> SecurityFinding:
    snap = None if snapshot is None else {**snapshot, "file": file}
    finding = SecurityFinding(
        assessment_id=assessment.id, type="SQL Injection", status="potential", severity="high", confidence="high",
        title="t", file=file, line=3, endpoint="/api/search", method="GET", rule_id=rule_id,
        plain_description="p", evidence_summary="e", technical_details={}, recommendation="r",
        fingerprint=uuid.uuid4().hex[:32], snapshot=snap,
    )
    db.add(finding)
    db.commit()
    return finding


def _make_finding(db, client, **kw) -> tuple[str, str]:
    a = _make_assessment(db, client)
    f = _add_finding(db, a, **kw)
    return str(a.id), str(f.id)


def _owner(db, assessment_id) -> User:
    a = db.get(Assessment, uuid.UUID(assessment_id))
    return db.get(User, db.get(Project, a.project_id).owner_id)


# ------------------------------------------------- existing behaviour kept
def test_start_remediation_creates_and_enqueues(alice, db, enqueued):
    assessment_id, finding_id = _make_finding(db, alice)

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending" and body["finding_id"] == finding_id
    assert body["stage"] == "queued" and body["assessment_id"] == assessment_id and body["max_attempts"] == 3
    assert [f["finding_id"] for f in body["findings"]] == [finding_id]
    assert [c for c in enqueued if c[0] == "remediate"] == [("remediate", body["id"], {"finding_id": finding_id})]
    row = db.scalar(select(RemediationOutbox).where(RemediationOutbox.remediation_id == uuid.UUID(body["id"])))
    assert row.status == "published"


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


def test_get_remediation_returns_legacy_iterations(alice, db):
    """Rows written before migration 0008 still carry their candidate code."""
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]
    db.add(RemediationIteration(remediation_id=uuid.UUID(run_id), iteration_no=1, round_no=1, candidate_hash="abc",
                                candidate_code="export async function GET() {}", test_results={"status": "passed"},
                                rescan_diff={}))
    db.commit()

    r = alice.get(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{run_id}")
    assert r.status_code == 200, r.text
    it = r.json()["iterations"]
    assert len(it) == 1 and it[0]["candidate_hash"] == "abc" and it[0]["candidate_code"].startswith("export")


def test_new_iterations_serve_candidate_code_from_the_artifact_store(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = uuid.UUID(alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"])
    batch = db.scalar(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run_id))
    store.claim(db, run_id, "w")
    for s in ("preparing_context", "redacting", "analysis", "planning", "generating_tests", "baseline_verification",
              "validating_tests", "generating_patch"):
        store.transition(db, run_id, "w", s)
    attempt = store.start_attempt(db, run_id, "w", batch.id, plan=None)
    store.finish_generation(db, run_id, "w", attempt.id, snapshot=SNAPSHOT,
                            candidate_code="export async function GET() { return 1; }", candidate_hash="h",
                            fix_source="llm_b", fix_note=None, invocation_id=None, errors=[])
    store.finish_attempt(db, run_id, "w", attempt.id, verification_status="failed", failure_reason="x",
                         test_results={}, rescan_diff={})

    body = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}").json()
    assert body["iterations"][0]["candidate_code"] == "export async function GET() { return 1; }"
    assert db.scalar(select(RemediationIteration.candidate_code)
                     .where(RemediationIteration.remediation_id == run_id)) is None

    attempts = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/attempts").json()
    art = attempts[0]["patch_artifact_id"]
    r = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/artifacts/{art}")
    assert r.status_code == 200 and r.text.startswith("--- a/app/api/search/route.ts")
    assert r.headers["cache-control"] == "no-store"


def test_cancel_sets_the_flag_and_finishes_an_unclaimed_run(alice, db, enqueued):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]

    r = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediations/{run_id}/cancel")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cancel_requested"] is True and body["status"] == "cancelled" and body["verdict"] == "cancelled"


def test_cancel_is_a_noop_on_an_already_terminal_remediation(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]
    db.execute(update(Remediation).where(Remediation.id == uuid.UUID(run_id))
               .values(status="succeeded", stage="completed", verdict="verified_fixed"))
    db.commit()

    r = alice.post(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/cancel")
    assert r.status_code == 200, r.text
    assert r.json()["cancel_requested"] is False and r.json()["status"] == "succeeded"


# ----------------------------------------------------- multi-finding runs
def test_one_run_for_several_findings_with_idempotency_key(alice, db, enqueued):
    a = _make_assessment(db, alice)
    f1 = _add_finding(db, a, file="app/api/a/route.ts")
    f2 = _add_finding(db, a, file="app/api/b/route.ts")
    body = {"finding_ids": [str(f1.id), str(f2.id)], "idempotency_key": "req-0001-abcdef"}

    r = alice.post(f"/api/v1/assessments/{a.id}/remediations", json=body)
    assert r.status_code == 201, r.text
    again = alice.post(f"/api/v1/assessments/{a.id}/remediations", json=body)
    assert again.status_code == 200 and again.json()["id"] == r.json()["id"]
    assert len([c for c in enqueued if c[0] == "remediate"]) == 1
    batches = alice.get(f"/api/v1/assessments/{a.id}/remediations/{r.json()['id']}/batches").json()
    assert [(b["sequence"], b["files"]) for b in batches] == [(1, ["app/api/a/route.ts"]),
                                                              (2, ["app/api/b/route.ts"])]


def test_findings_in_the_same_file_cannot_share_a_run(alice, db):
    a = _make_assessment(db, alice)
    f1 = _add_finding(db, a)
    f2 = _add_finding(db, a)
    r = alice.post(f"/api/v1/assessments/{a.id}/remediations", json={"finding_ids": [str(f1.id), str(f2.id)]})
    assert r.status_code == 422 and r.json()["error"]["code"] == "overlapping_findings"


def test_a_finding_already_in_an_active_run_is_refused_for_a_new_multi_run(alice, db):
    a = _make_assessment(db, alice)
    f1 = _add_finding(db, a, file="app/api/a/route.ts")
    f2 = _add_finding(db, a, file="app/api/b/route.ts")
    assert alice.post(f"/api/v1/assessments/{a.id}/findings/{f1.id}/remediate").status_code == 201
    r = alice.post(f"/api/v1/assessments/{a.id}/remediations", json={"finding_ids": [str(f1.id), str(f2.id)]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "remediation_active"


def test_history_is_paginated_and_a_new_run_never_overwrites_an_old_one(alice, db):
    a = _make_assessment(db, alice)
    f = _add_finding(db, a)
    ids = []
    for _ in range(3):
        rid = alice.post(f"/api/v1/assessments/{a.id}/findings/{f.id}/remediate").json()["id"]
        alice.post(f"/api/v1/assessments/{a.id}/remediations/{rid}/cancel")
        ids.append(rid)
    assert len(set(ids)) == 3
    page = alice.get(f"/api/v1/assessments/{a.id}/remediations?limit=2").json()
    assert page["total"] == 3 and len(page["items"]) == 2 and page["items"][0]["id"] == ids[-1]
    rest = alice.get(f"/api/v1/assessments/{a.id}/remediations?limit=2&offset=2").json()
    assert [i["id"] for i in rest["items"]] == [ids[0]]


def test_audit_trail_is_ordered_and_paginated(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]
    alice.post(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/cancel")
    first = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/audit?limit=1").json()
    assert first["items"][0]["event_type"] == "remediation_requested" and first["next_after_seq"]
    rest = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/audit"
                     f"?after_seq={first['next_after_seq']}").json()
    assert [e["event_type"] for e in rest["items"]] == ["cancel_requested", "remediation_completed"]
    assert "metadata" in rest["items"][0]


def test_report_is_built_from_persisted_records(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]
    alice.post(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/cancel")
    report = alice.get(f"/api/v1/assessments/{assessment_id}/remediations/{run_id}/report").json()
    assert report["verdict"] == "cancelled" and report["findings"][0]["resolution"] == "cancelled"
    assert report["assessment_id"] == assessment_id


# ------------------------------------------------------------- isolation
def test_every_remediation_endpoint_is_404_for_another_user(alice, bob, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"]
    run = uuid.UUID(run_id)
    store.claim(db, run, "w")
    store.transition(db, run, "w", "preparing_context")
    store.transition(db, run, "w", "redacting")
    ctx = store.record_context(db, run, "w", batch_id=db.scalar(select(RemediationPatchBatch.id).where(
        RemediationPatchBatch.remediation_id == run)), finding_id=uuid.UUID(finding_id), snapshot=SNAPSHOT,
        redacted_code=SNAPSHOT["code"], placeholders=0)
    base = f"/api/v1/assessments/{assessment_id}"
    gets = [f"{base}/findings/{finding_id}/remediations/{run_id}", f"{base}/remediations",
            f"{base}/remediations/{run_id}", f"{base}/remediations/{run_id}/plans",
            f"{base}/remediations/{run_id}/contexts", f"{base}/remediations/{run_id}/testbench",
            f"{base}/remediations/{run_id}/batches", f"{base}/remediations/{run_id}/attempts",
            f"{base}/remediations/{run_id}/invocations", f"{base}/remediations/{run_id}/verifications",
            f"{base}/remediations/{run_id}/reanalysis", f"{base}/remediations/{run_id}/audit",
            f"{base}/remediations/{run_id}/report",
            f"{base}/remediations/{run_id}/artifacts/{ctx.snapshot_artifact_id}"]
    for url in gets:
        assert alice.get(url).status_code == 200, url
        assert bob.get(url).status_code == 404, url
    for url in (f"{base}/findings/{finding_id}/remediate", f"{base}/remediations/{run_id}/cancel",
                f"{base}/findings/{finding_id}/remediations/{run_id}/cancel"):
        assert bob.post(url).status_code == 404, url
    assert bob.post(f"{base}/remediations", json={"finding_ids": [finding_id]}).status_code == 404
    assert db.get(Remediation, run).cancel_requested is False


def test_a_run_cannot_be_read_through_another_assessment(alice, db):
    a1 = _make_assessment(db, alice)
    f1 = _add_finding(db, a1)
    a2 = _make_assessment(db, alice)
    run_id = alice.post(f"/api/v1/assessments/{a1.id}/findings/{f1.id}/remediate").json()["id"]
    assert alice.get(f"/api/v1/assessments/{a2.id}/remediations/{run_id}").status_code == 404


def test_artifacts_of_another_run_are_not_served(alice, db):
    a = _make_assessment(db, alice)
    f1 = _add_finding(db, a, file="app/api/a/route.ts")
    f2 = _add_finding(db, a, file="app/api/b/route.ts")
    r1 = uuid.UUID(alice.post(f"/api/v1/assessments/{a.id}/findings/{f1.id}/remediate").json()["id"])
    r2 = uuid.UUID(alice.post(f"/api/v1/assessments/{a.id}/findings/{f2.id}/remediate").json()["id"])
    art = artifacts.store(db, r1, "plan", "x", redaction_status="none_needed", contains_source=False)
    db.commit()
    assert alice.get(f"/api/v1/assessments/{a.id}/remediations/{r1}/artifacts/{art.id}").status_code == 200
    assert alice.get(f"/api/v1/assessments/{a.id}/remediations/{r2}/artifacts/{art.id}").status_code == 404


def test_existing_finding_and_assessment_endpoints_still_work(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate")
    r = alice.get(f"/api/v1/assessments/{assessment_id}")
    assert r.status_code == 200, r.text
    findings = alice.get(f"/api/v1/assessments/{assessment_id}/findings")
    assert findings.status_code == 200, findings.text
    assert finding_id in findings.text


def test_attempt_rows_are_unique_per_batch(alice, db):
    assessment_id, finding_id = _make_finding(db, alice)
    run = uuid.UUID(alice.post(f"/api/v1/assessments/{assessment_id}/findings/{finding_id}/remediate").json()["id"])
    batch = db.scalar(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run))
    store.claim(db, run, "w")
    a1 = store.start_attempt(db, run, "w", batch.id, plan=None)
    a2 = store.start_attempt(db, run, "w", batch.id, plan=None)
    assert (a1.attempt_no, a2.attempt_no) == (1, 2)
    nos = db.scalars(select(RemediationPatchAttempt.attempt_no).where(RemediationPatchAttempt.batch_id == batch.id))
    assert sorted(nos) == [1, 2]
