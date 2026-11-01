"""Remediation job + persistence tests (real PostgreSQL).

Model transports and sandbox results are scripted. That is test
infrastructure, never evidence: `SandboxGradeRunner` below is a scripted
double that *declares* sandbox-grade evidence only so the verdict rules can be
exercised. The production FakeSandboxRunner is "simulated" and the tests prove
it can never yield verified_fixed.
"""

import json
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError

from routes_shared.buildrun import validate_patch
from routes_shared.enums import RemediationStatus
from routes_shared.remediation_workflow import InvalidTransition

from app.models import (
    AiModelInvocation,
    Assessment,
    Project,
    ProjectIntegration,
    Remediation,
    RemediationArtifact,
    RemediationAuditEvent,
    RemediationContext,
    RemediationFinding,
    RemediationIteration,
    RemediationOutbox,
    RemediationPatchAttempt,
    RemediationPatchBatch,
    RemediationPlan,
    RemediationReanalysisFinding,
    RemediationReanalysisRun,
    RemediationTestCase,
    RemediationTestResult,
    RemediationTestSuite,
    RemediationVerificationRun,
    SecurityFinding,
    User,
)
from app.models.base import utcnow
from app.services import artifacts, outbox, queueing
from app.services import remediation_store as store
from app.services import lifecycle
from worker.gate_library import known_bad_fixes_for
from worker.jobs import remediate
from worker.llm.client import LLMClient
from worker.sandbox.fake import FakeSandboxRunner
from worker.sandbox.runner import SandboxRunResult, TestResult

RULE_ID = "routes.sqli.pg-tainted-query"
N_BAD_FIXES = len(known_bad_fixes_for(RULE_ID))
API_KEY = "sk-test-NEVERSTOREDNEVERSTORED0123"


def snapshot(file="app/api/search/route.ts"):
    return {
        "file": file, "start_line": 10, "end_line": 14,
        "code": (
            "export async function GET(request) {\n"
            '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
            "  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);\n"
            "  return NextResponse.json(result.rows);\n"
            "}"
        ),
    }


LLM_A = json.dumps({"prompt_for_fix": "Parameterise the query.", "testbench": "test('exploit', () => {})"})


def llm_b(variant: int = 0) -> str:
    extra = "  void 0;\n" * variant  # a real code difference (comments are normalised away)
    return ("```ts\nexport async function GET(request) {\n"
            '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
            f"{extra}"
            "  const result = await pool.query('SELECT * FROM products WHERE name ILIKE $1', [`%${q}%`]);\n"
            "  return NextResponse.json(result.rows);\n}\n```")


class SandboxGradeRunner(FakeSandboxRunner):
    """Scripted test double that declares sandbox-grade evidence (see module docstring)."""

    kind = "test-double"
    evidence_grade = "sandbox"


def gated_ok():  # original code: exploit fails, benign passes -> the testbench detects the bug
    return SandboxRunResult(status="failed", tests=[TestResult("exploit blocked", "exploit", False),
                                                    TestResult("benign works", "benign", True)])


def gate_bad():  # original code passes the exploit test -> the testbench cannot detect the bug
    return SandboxRunResult(status="passed", tests=[TestResult("exploit blocked", "exploit", True),
                                                    TestResult("benign works", "benign", True)])


def verify_pass():
    return SandboxRunResult(status="passed", tests=[TestResult("exploit blocked", "exploit", True),
                                                    TestResult("benign works", "benign", True)],
                            stdout="2 passed", duration_ms=40)


def verify_fail():
    return SandboxRunResult(status="failed", tests=[TestResult("exploit blocked", "exploit", False, "still injectable"),
                                                    TestResult("benign works", "benign", True)])


def rescan(fps):
    return SandboxRunResult(status="passed", rescan_fingerprints=fps)


def gate_ok_runs():
    return [gated_ok() for _ in range(1 + N_BAD_FIXES)]


def llm_factory(scripts: dict[str, list[str]], calls: list | None = None):
    remaining = {m: list(c) for m, c in scripts.items()}

    def factory(*, endpoint, api_key, model, cache_mode, cache_dir, **_):
        def handler(request: httpx.Request) -> httpx.Response:
            if calls is not None:
                calls.append(model)
            queue = remaining.get(model) or []
            if not queue:
                raise AssertionError(f"ran out of scripted responses for {model}")
            return httpx.Response(200, json={"choices": [{"message": {"content": queue.pop(0)}}],
                                             "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                                                       "total_tokens": 18}, "model": f"{model}-2026"})
        return LLMClient(endpoint=endpoint, api_key=api_key, model=model, cache_mode="live",
                         transport=httpx.MockTransport(handler))
    return factory


MODEL_A = "llama-3.3-70b-versatile"
MODEL_B = "qwen/qwen-2.5-coder-32b-instruct:free"


@pytest.fixture(autouse=True)
def _settings(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_A_API_KEY", API_KEY)
    monkeypatch.setenv("LLM_B_API_KEY", API_KEY)
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    from app.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(queueing, "enqueue_job", lambda *a, **k: None)
    yield
    get_settings.cache_clear()


def setup(db, files=("app/api/search/route.ts",), with_integration=True):
    user = User(email=f"{uuid.uuid4().hex}@x.io", password_hash="x", display_name="")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="p", website_url="https://example.com/", hostname="example.com",
                      authorised_at=lifecycle.now(), authorisation_statement="ok")
    db.add(project)
    db.flush()
    if with_integration:
        db.add(ProjectIntegration(project_id=project.id, kind="github_public", repo_owner="acme", repo_name="shop",
                                  repo_ref="main", match_status="confirmed"))
    assessment = Assessment(project_id=project.id, status="completed", target_url="https://example.com/")
    db.add(assessment)
    db.flush()
    findings = []
    for f in files:
        finding = SecurityFinding(
            assessment_id=assessment.id, type="SQL Injection", status="potential", severity="high",
            confidence="high", title="User input used to build a SQL query", file=f, line=12,
            endpoint="/api/search", method="GET", rule_id=RULE_ID, plain_description="Input reaches a query.",
            evidence_summary="e", technical_details={}, recommendation="r", fingerprint=uuid.uuid4().hex[:32],
            snapshot=snapshot(f))
        db.add(finding)
        findings.append(finding)
    # An unrelated finding of the same assessment: must stay "remaining".
    db.add(SecurityFinding(
        assessment_id=assessment.id, type="Misconfiguration", status="potential", severity="low", confidence="low",
        title="other", file="next.config.js", line=1, rule_id="routes.config.headers", plain_description="p",
        evidence_summary="e", technical_details={}, recommendation="r", fingerprint="f" * 32))
    db.commit()
    return user, assessment, findings


def start(db, user, assessment, findings, **kw):
    run, created = store.create_run(db, user=user, assessment=assessment, findings=findings, **kw)
    assert created
    return run


def run_job(monkeypatch, run, runner, scripts, calls=None):
    monkeypatch.setattr(remediate, "LLMClient", llm_factory(scripts, calls))
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: runner)
    remediate.run_remediate_job(str(run.id), str(run.finding_id))


def stages(db, run_id):
    return [e.new_state for e in db.scalars(select(RemediationAuditEvent).where(
        RemediationAuditEvent.remediation_id == run_id, RemediationAuditEvent.event_type == "stage_changed")
        .order_by(RemediationAuditEvent.seq)).all()]


def other_fp():
    return ["f" * 32]


# --------------------------------------------------------------- lifecycle
def test_successful_remediation_persists_the_whole_lifecycle(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.stage, r.status, r.finding_status) == ("verified_fixed", "completed", "succeeded", "fixed")
    assert r.project_id == assessment.project_id and r.assessment_id == assessment.id
    assert r.attempts_total == 1 and r.lease_owner is None and r.finished_at is not None
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    assert rf.resolution == "verified_fixed" and all(rf.gates.values()) and not rf.is_active
    assert rf.severity_snapshot == "high" and rf.fingerprint_snapshot == finding.fingerprint

    ctx = db.scalar(select(RemediationContext).where(RemediationContext.remediation_id == r.id))
    assert ctx.redaction_verified and ctx.redaction_ruleset_version and ctx.file_paths == [finding.file]
    plan = db.scalar(select(RemediationPlan).where(RemediationPlan.remediation_id == r.id))
    assert plan.version == 1 and plan.strategy == "Parameterise the query." and plan.test_generation_status == "validated"
    assert plan.root_cause is None  # Model A does not produce one: never invented
    suite = db.scalar(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == r.id))
    assert (suite.validation_status, suite.baseline_status) == ("validated", "reproduced")
    cases = db.scalars(select(RemediationTestCase).where(RemediationTestCase.suite_id == suite.id)).all()
    assert {c.name for c in cases} == {"exploit blocked", "benign works"}
    assert {c.visibility for c in cases} == {"hidden"}

    attempt = db.scalar(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id))
    assert (attempt.attempt_no, attempt.validation_status, attempt.verification_status) == (1, "valid", "passed")
    assert attempt.fix_source == "llm_b" and attempt.invocation_id is not None
    patch = artifacts.read(db.get(RemediationArtifact, attempt.patch_artifact_id)).decode()
    assert validate_patch(patch) == [finding.file] and "@@ -10," in patch and "$1" in patch

    runs = db.scalars(select(RemediationVerificationRun).where(RemediationVerificationRun.remediation_id == r.id)).all()
    assert sorted(v.purpose for v in runs) == sorted(["baseline"] + ["gate_known_bad"] * N_BAD_FIXES
                                                     + ["candidate", "rescan"])
    candidate = next(v for v in runs if v.purpose == "candidate")
    results = db.scalars(select(RemediationTestResult).where(RemediationTestResult.verification_run_id == candidate.id)).all()
    assert {x.outcome for x in results} == {"passed"} and all(x.matches_expectation for x in results)
    re = db.scalar(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == r.id))
    assert (re.resolved_count, re.remaining_count, re.new_count) == (1, 1, 0)
    resolved = db.scalar(select(RemediationReanalysisFinding).where(
        RemediationReanalysisFinding.reanalysis_id == re.id, RemediationReanalysisFinding.change == "resolved"))
    assert resolved.original_finding_id == finding.id and resolved.targeted

    invocations = db.scalars(select(AiModelInvocation).where(AiModelInvocation.remediation_id == r.id)
                             .order_by(AiModelInvocation.sequence)).all()
    assert [i.role for i in invocations] == ["analysis", "patch_generation"]
    assert invocations[0].provider == "api.groq.com" and invocations[0].total_tokens == 18
    assert invocations[0].model_version == f"{MODEL_A}-2026" and all(i.status == "succeeded" for i in invocations)

    legacy = db.scalars(select(RemediationIteration).where(RemediationIteration.remediation_id == r.id)).all()
    assert len(legacy) == 1 and legacy[0].candidate_code is None  # source lives in the artifact store
    assert legacy[0].rescan_diff == {"fingerprint_gone": True, "new_fingerprints": []}

    assert stages(db, r.id) == ["preparing_context", "redacting", "analysis", "planning", "generating_tests",
                                "baseline_verification", "validating_tests", "generating_patch",
                                "validating_patch", "testing", "post_remediation_analysis"]
    events = [e.event_type for e in db.scalars(select(RemediationAuditEvent).where(
        RemediationAuditEvent.remediation_id == r.id).order_by(RemediationAuditEvent.seq)).all()]
    for expected in ("remediation_requested", "worker_claimed", "context_extracted", "redaction_completed",
                     "model_invoked", "plan_generated", "testbench_validated", "original_vulnerability_reproduced",
                     "patch_generated", "patch_accepted", "post_remediation_analysis_completed",
                     "remediation_completed"):
        assert expected in events
    assert events[-1] == "remediation_completed"
    report = store.report(db, r)
    assert report["verdict"] == "verified_fixed" and report["findings"][0]["resolution"] == "verified_fixed"


def test_the_simulated_runner_can_never_verify_a_fix(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = FakeSandboxRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.status) == ("inconclusive", "needs_human_review")
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    assert rf.resolution == "inconclusive" and rf.gates["real_sandbox_evidence"] is False
    assert "simulated" in rf.resolution_reason and rf.residual_risk


def test_failed_initial_patch_followed_by_a_correction(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_fail(), verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b(0), llm_b(1)]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert r.verdict == "verified_fixed" and r.attempts_total == 2
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)
                          .order_by(RemediationPatchAttempt.attempt_no)).all()
    assert [(a.attempt_no, a.verification_status) for a in attempts] == [(1, "failed"), (2, "passed")]
    assert "did not pass" in attempts[0].failure_reason
    s = stages(db, r.id)
    assert s[s.index("testing") + 1:s.index("testing") + 4] == ["analysing_failure", "retrying", "generating_patch"]


def test_three_attempts_is_the_maximum_and_the_database_enforces_it(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_fail(), verify_fail(), verify_fail()])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b(0), llm_b(1), llm_b(2)]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.stage, r.attempts_total) == ("human_review", "human_review", 3)
    batch = db.scalar(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == r.id))
    assert (batch.attempts_used, batch.max_attempts, batch.status) == (3, 3, "human_review")
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    assert rf.resolution == "human_review" and "attempt" in rf.resolution_reason
    # A 4th attempt is refused by the store and by the database itself.
    db.execute(update(Remediation).where(Remediation.id == r.id).values(stage="testing", lease_owner="w"))
    db.commit()
    with pytest.raises(store.AttemptLimitReached):
        store.start_attempt(db, r.id, "w", batch.id, plan=None)
    db.add(RemediationPatchAttempt(remediation_id=r.id, batch_id=batch.id, attempt_no=4, max_attempts=3,
                                   idempotency_key=f"{batch.id}:4"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_oscillation_goes_to_human_review(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_fail()])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b(0), llm_b(0)]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert r.verdict == "human_review"
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    assert "same candidate" in rf.resolution_reason
    last = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)
                      .order_by(RemediationPatchAttempt.attempt_no)).all()[-1]
    assert last.validation_status == "invalid" and "oscillation" in last.failure_reason


def test_partial_remediation_of_two_findings(db, monkeypatch):
    user, assessment, (f1, f2) = setup(db, files=("app/api/search/route.ts", "app/api/orders/route.ts"))
    run = start(db, user, assessment, [f1, f2])
    # Batch 1 fixed; batch 2's testbench never detects the bug (3 regenerations).
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp() + [f2.fingerprint])]
                                + [gate_bad(), gate_bad(), gate_bad()])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A] * 4, MODEL_B: [llm_b()]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.status) == ("partially_remediated", "needs_human_review")
    res = {rf.finding_id: rf.resolution for rf in db.scalars(
        select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))}
    assert res == {f1.id: "verified_fixed", f2.id: "inconclusive"}
    suites = db.scalars(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == r.id)).all()
    assert len(suites) == 4 and sorted(s.version for s in suites) == [1, 2, 3, 4]
    assert sum(s.baseline_status == "not_reproduced" for s in suites) == 3
    assert len(db.scalars(select(RemediationPlan).where(RemediationPlan.remediation_id == r.id)).all()) == 4


def test_two_fixed_batches_get_a_combined_rescan(db, monkeypatch):
    user, assessment, (f1, f2) = setup(db, files=("app/api/search/route.ts", "app/api/orders/route.ts"))
    run = start(db, user, assessment, [f1, f2])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp() + [f2.fingerprint])]
                                + gate_ok_runs() + [verify_pass(), rescan(other_fp() + [f1.fingerprint])]
                                + [rescan(other_fp() + ["n" * 32])])  # combined: a new finding appears
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A] * 2, MODEL_B: [llm_b(), llm_b()]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    combined = db.scalar(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == r.id,
                                                                RemediationReanalysisRun.scope == "combined"))
    assert combined.new_count == 1 and combined.resolved_count == 2
    # Each batch passed alone, but together they introduced a finding: not verified.
    assert r.verdict == "human_review"
    assert {rf.gates["no_new_findings"] for rf in db.scalars(
        select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))} == {False}


def test_inconclusive_when_the_testbench_never_validates(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner([gate_bad(), gate_bad(), gate_bad()])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A] * 3})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.stage, r.attempts_total) == ("inconclusive", "inconclusive", 0)
    rejected = db.scalars(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == r.id)).all()
    assert [s.validation_status for s in rejected] == ["rejected"] * 3


def test_reanalysis_that_finds_new_findings_is_never_a_fix(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    new = ["a" * 32]
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp() + new),
                                                  verify_pass(), rescan(other_fp() + new),
                                                  verify_pass(), rescan(other_fp() + new)])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b(0), llm_b(1), llm_b(2)]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert r.verdict == "human_review"
    new_rows = db.scalars(select(RemediationReanalysisFinding).join(RemediationReanalysisRun).where(
        RemediationReanalysisRun.remediation_id == r.id, RemediationReanalysisFinding.change == "new")).all()
    assert len(new_rows) == 3 and {x.fingerprint for x in new_rows} == {"a" * 32}


def test_cancellation_before_the_first_round(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    db.execute(update(Remediation).where(Remediation.id == run.id).values(cancel_requested=True))
    db.commit()
    run_job(monkeypatch, run, SandboxGradeRunner([]), {})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.status, r.stage) == ("cancelled", "cancelled", "cancelled")
    assert db.scalars(select(RemediationIteration).where(RemediationIteration.remediation_id == r.id)).all() == []


def test_cancel_of_an_unclaimed_run_finishes_it_immediately(db):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    store.request_cancel(db, run, user)
    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.status, r.cancelled_by) == ("cancelled", "cancelled", user.id)
    assert db.scalar(select(RemediationFinding.is_active).where(RemediationFinding.remediation_id == r.id)) is False


def test_missing_snapshot_and_missing_source_are_inconclusive(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    db.execute(update(SecurityFinding).where(SecurityFinding.id == finding.id).values(snapshot=None))
    db.commit()
    run_job(monkeypatch, run, SandboxGradeRunner([]), {})
    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.status) == ("inconclusive", RemediationStatus.NEEDS_HUMAN_REVIEW)
    assert "snapshot" in r.error

    user, assessment, (finding,) = setup(db, with_integration=False)
    run = start(db, user, assessment, [finding])
    run_job(monkeypatch, run, SandboxGradeRunner([]), {})
    db.expire_all()
    r = db.get(Remediation, run.id)
    assert r.verdict == "inconclusive" and "source reference" in r.error


def test_a_model_provider_failure_is_an_infrastructure_failure(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])

    def factory(*, endpoint, api_key, model, cache_mode, cache_dir, **_):
        return LLMClient(endpoint=endpoint, api_key=api_key, model=model, cache_mode="live",
                         transport=httpx.MockTransport(lambda r: httpx.Response(503, text="down")))
    monkeypatch.setattr(remediate, "LLMClient", factory)
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: SandboxGradeRunner([]))
    remediate.run_remediate_job(str(run.id))

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.failure_category, r.status) == ("failed", "infrastructure", "failed")
    inv = db.scalar(select(AiModelInvocation).where(AiModelInvocation.remediation_id == r.id))
    assert (inv.status, inv.error_category) == ("failed", "provider_error")


# ------------------------------------------------- concurrency and recovery
def test_duplicate_delivery_does_nothing(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    calls: list = []
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]}, calls)
    run_job(monkeypatch, run, SandboxGradeRunner([]), {}, calls)  # redelivered: no model or sandbox call
    assert len(calls) == 2
    assert len(db.scalars(select(RemediationPatchAttempt)
                          .where(RemediationPatchAttempt.remediation_id == run.id)).all()) == 1


def test_only_one_worker_can_hold_a_run(db):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    assert store.claim(db, run.id, "worker-a") is not None
    assert store.claim(db, run.id, "worker-b") is None
    with pytest.raises(store.LeaseLost):
        store.transition(db, run.id, "worker-b", "preparing_context")
    with pytest.raises(InvalidTransition):
        store.transition(db, run.id, "worker-a", "testing")  # queued -> testing is not a valid edge
    db.rollback()
    store.transition(db, run.id, "worker-a", "preparing_context")
    assert db.get(Remediation, run.id).version == 3


def test_a_crashed_worker_is_resumed_and_its_attempts_still_count(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    batch = db.scalar(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run.id))
    # Worker A got as far as starting attempt 1, then died.
    assert store.claim(db, run.id, "worker-a")
    for s in ("preparing_context", "redacting", "analysis", "planning", "generating_tests", "baseline_verification",
              "validating_tests", "generating_patch"):
        store.transition(db, run.id, "worker-a", s)
    store.start_attempt(db, run.id, "worker-a", batch.id, plan=None)
    db.execute(update(Remediation).where(Remediation.id == run.id)
               .values(lease_expires_at=utcnow() - timedelta(minutes=1)))
    db.commit()

    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]})

    db.expire_all()
    r = db.get(Remediation, run.id)
    assert r.verdict == "verified_fixed" and r.recovery_count == 1 and r.attempts_total == 2
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)
                          .order_by(RemediationPatchAttempt.attempt_no)).all()
    assert [(a.attempt_no, a.generation_status, a.verification_status) for a in attempts] == [
        (1, "abandoned", "error"), (2, "generated", "passed")]
    events = [e.event_type for e in db.scalars(select(RemediationAuditEvent)
                                               .where(RemediationAuditEvent.remediation_id == r.id))]
    assert "worker_resumed" in events and "patch_attempt_abandoned" in events


def test_a_run_interrupted_too_often_is_failed_not_retried_forever(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    db.execute(update(Remediation).where(Remediation.id == run.id).values(
        stage="testing", recovery_count=2, lease_owner="dead", lease_expires_at=utcnow() - timedelta(minutes=1)))
    db.commit()
    run_job(monkeypatch, run, SandboxGradeRunner([]), {})
    db.expire_all()
    r = db.get(Remediation, run.id)
    assert (r.verdict, r.failure_category) == ("failed", "infrastructure") and "interrupted" in r.error


def test_recovery_dispatch_goes_through_the_outbox(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    published: list = []
    fail = {"n": 1}

    def flaky(kind, job_id, **kw):
        if fail["n"]:
            fail["n"] -= 1
            raise ConnectionError("redis down")
        published.append((kind, str(job_id)))

    monkeypatch.setattr(queueing, "enqueue_job", flaky)
    # The worker test database is shared across tests: only look at this run's rows.
    db.execute(update(RemediationOutbox).where(RemediationOutbox.remediation_id != run.id)
               .values(status="published"))
    db.commit()
    assert outbox.relay(db) == 0  # broker down: stays pending, retried later
    row = db.scalar(select(RemediationOutbox).where(RemediationOutbox.remediation_id == run.id))
    assert (row.status, row.attempts) == ("pending", 1) and "redis down" in row.last_error
    db.execute(update(RemediationOutbox).values(available_at=utcnow()))
    db.commit()
    assert outbox.relay(db) == 1 and published == [("remediate", str(run.id))]
    assert store.recover_interrupted(db) == 1  # never claimed -> re-dispatched with a new key
    assert outbox.relay(db) == 1 and len(published) == 2


def test_writes_are_atomic(db):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    batch = db.scalar(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run.id))
    store.claim(db, run.id, "w")
    attempt = store.start_attempt(db, run.id, "w", batch.id, plan=None)
    leaked = 'const apiKey = "AKIAABCDEFGHIJKLMNOP";'
    with pytest.raises(artifacts.ArtifactRejected):
        store.finish_generation(db, run.id, "w", attempt.id, snapshot=finding.snapshot, candidate_code=leaked,
                                candidate_hash="h", fix_source="llm_b", fix_note=None, invocation_id=None, errors=[])
    db.rollback()
    db.expire_all()
    a = db.get(RemediationPatchAttempt, attempt.id)
    assert (a.generation_status, a.candidate_artifact_id) == ("pending", None)
    assert db.scalars(select(RemediationArtifact).where(RemediationArtifact.remediation_id == run.id,
                                                        RemediationArtifact.kind == "candidate")).all() == []


def test_one_active_run_per_finding_is_enforced_by_the_database(db):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    again, created = store.create_run(db, user=user, assessment=assessment, findings=[finding])
    assert again.id == run.id and not created
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == run.id))
    other = Remediation(finding_id=finding.id, project_id=assessment.project_id, assessment_id=assessment.id)
    db.add(other)
    db.flush()
    db.add(RemediationFinding(remediation_id=other.id, finding_id=finding.id, is_active=True,
                              severity_snapshot="high", confidence_snapshot="high",
                              fingerprint_snapshot=rf.fingerprint_snapshot, rule_id_snapshot=RULE_ID))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# ------------------------------------------------------------------ security
def test_no_credentials_or_source_in_model_records(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]})

    tables = ["ai_model_invocations", "remediation_audit_events", "remediations", "remediation_patch_attempts",
              "remediation_contexts", "remediation_plans", "remediation_iterations"]
    for table in tables:
        dump = db.execute(text(f"SELECT row_to_json(t)::text FROM {table} t")).scalars().all()
        blob = "\n".join(dump)
        assert API_KEY not in blob, table
        assert "pool.query" not in blob, table  # source code never lands in ordinary columns
    for art in db.scalars(select(RemediationArtifact).where(RemediationArtifact.remediation_id == run.id)).all():
        assert API_KEY not in artifacts.read(art).decode()


def test_unredactable_secrets_are_never_sent_to_a_model(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    # Simulate a redaction regression: LLM A's own redaction is bypassed.
    from worker.llm import llm_a

    monkeypatch.setattr(llm_a, "redact_for_llm", lambda t: (t + '\nconst apiKey = "AKIAABCDEFGHIJKLMNOP";', {}))
    calls: list = []
    run_job(monkeypatch, run, SandboxGradeRunner([]), {MODEL_A: [LLM_A]}, calls)

    db.expire_all()
    assert calls == []  # nothing left ROUTES
    inv = db.scalar(select(AiModelInvocation).where(AiModelInvocation.remediation_id == run.id))
    assert (inv.status, inv.error_category, inv.input_artifact_id) == ("blocked", "policy", None)
    r = db.get(Remediation, run.id)
    assert r.verdict == "human_review" and "blocked" in r.error


def test_audit_events_are_append_only(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("UPDATE remediation_audit_events SET event_type = 'x' WHERE remediation_id = :r"),
                   {"r": run.id})
    db.rollback()
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("DELETE FROM remediation_audit_events WHERE remediation_id = :r"), {"r": run.id})
    db.rollback()
    # Deleting the run itself (retention, project deletion) removes its history.
    db.execute(text("DELETE FROM remediations WHERE id = :r"), {"r": run.id})
    db.commit()
    assert db.scalars(select(RemediationAuditEvent).where(RemediationAuditEvent.remediation_id == run.id)).all() == []


def test_deleting_an_assessment_cascades_to_its_remediation_records(db, monkeypatch):
    user, assessment, (finding,) = setup(db)
    run = start(db, user, assessment, [finding])
    runner = SandboxGradeRunner(gate_ok_runs() + [verify_pass(), rescan(other_fp())])
    run_job(monkeypatch, run, runner, {MODEL_A: [LLM_A], MODEL_B: [llm_b()]})
    db.delete(db.get(Assessment, assessment.id))
    db.commit()
    assert db.scalar(select(func.count()).select_from(Remediation).where(Remediation.id == run.id)) == 0
    for model in (RemediationFinding, RemediationPatchAttempt, RemediationVerificationRun, RemediationArtifact,
                  AiModelInvocation, RemediationAuditEvent):
        assert db.scalars(select(model).where(model.remediation_id == run.id)).all() == []
    # The orphaned artifact directory is swept by retention (after its idle window).
    assert artifacts.purge_expired(db) >= 0
