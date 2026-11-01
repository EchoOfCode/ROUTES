"""Build & Run verifier wiring (BuildRunSandboxRunner + job + store).

MOCKED ENGINE: `ScriptedEngine` stands in for the Sandbox Manager HTTP API
and model replies are scripted. These tests prove the orchestration and what
gets persisted; they are not evidence that any fix works. The real-sandbox
proof is scripts/remediation_e2e.py, which runs the actual engine.
"""

import json
import uuid

import httpx
import pytest
from sqlalchemy import select, update

from app.models import (
    AiModelInvocation,
    Assessment,
    Project,
    ProjectIntegration,
    Remediation,
    RemediationFinding,
    RemediationPatchAttempt,
    RemediationPlan,
    RemediationReanalysisRun,
    RemediationTestCase,
    RemediationTestResult,
    RemediationTestSuite,
    RemediationVerificationRun,
    SecurityFinding,
    SourceAnalysisResult,
    User,
)
from app.services import lifecycle, queueing
from app.services import remediation_store as store
from worker.jobs import remediate
from worker.llm.client import LLMClient
from worker.sandbox.buildrun import BuildRunSandboxRunner, source_spec, SourceUnavailable
from worker.sandbox.runner import SourceRef

SHA = "c" * 40
FILE = "app/api/products/route.js"
CODE = ("export async function GET(request) {\n"
        '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
        "  const result = await pool.query(`SELECT id FROM products WHERE name ILIKE '%${q}%'`);\n"
        "  return NextResponse.json(result.rows);\n}")
FIXED = CODE.replace("pool.query(`SELECT id FROM products WHERE name ILIKE '%${q}%'`)",
                     "pool.query(\"SELECT id FROM products WHERE name ILIKE '%' || $1 || '%'\", [q])")
STILL_BAD = CODE.replace("const result", "const safe = q.replace(/;/g, '');\n  const result")

MODEL_A = "llama-3.3-70b-versatile"
MODEL_B = "qwen/qwen-2.5-coder-32b-instruct:free"
PLAN_REPLY = json.dumps({
    "prompt_for_fix": "Pass q as a bound parameter.", "root_cause": "q is interpolated into SQL.",
    "expected_behaviour": "Quotes in q are treated as data.", "security_test_scenarios": ["quote in q"],
    "functional_test_scenarios": ["listing products"], "regression_risks": ["ILIKE wildcard placement"],
    "required_context": ["lib/db.js pool"],
    "functional_tests": [{"id": "list", "name": "products list", "method": "GET", "path": "/api/products",
                          "expect_status": [200]},
                         {"id": "broken", "name": "fails on original", "method": "GET", "path": "/api/missing",
                          "expect_status": [200]},
                         {"id": "post", "name": "not allowed", "method": "POST", "path": "/api/products",
                          "expect_status": [200]}]})


def code_reply(code):
    return f"```js\n{code}\n```"


class ScriptedEngine:
    """MOCKED Sandbox Manager: behaves like the vulnerable fixture app."""

    def __init__(self, fingerprint):
        self.fingerprint, self.started, self.runs = fingerprint, [], {}

    def start(self, spec):
        rid = f"run-{len(self.started) + 1}"
        self.started.append(spec)
        self.runs[rid] = spec
        return {"id": rid, "status": "queued"}

    def get(self, rid):
        spec = self.runs[rid]
        patch = spec.get("patch") or ""
        fixed = "$1" in patch
        if spec["kind"] == "source":
            fps = [] if fixed else [self.fingerprint]
            return {"id": rid, "status": "completed", "finished_at": 1,
                    "result": {"findings": [{"fingerprint": f} for f in fps], "patch_applied": bool(patch),
                               "source_commit": SHA}}
        cases = []
        for t in spec["test_plan"]["tests"]:
            if t["category"] == "security":
                status = "passed" if fixed else "failed"
            else:
                status = "failed" if t["request"]["path"] == "/api/missing" else "passed"
            cases.append({"id": t["id"], "name": t["name"], "category": t["category"], "status": status,
                          "reasons": [] if status == "passed" else ["status 500 is not allowed"]})
        failed = any(c["status"] != "passed" for c in cases)
        return {"id": rid, "status": "completed", "finished_at": 2, "created_at": 1,
                "cleanup": {"status": "complete", "containers_removed": 3, "networks_removed": 2, "errors": []},
                "result": {"verification": "TESTS_FAILED" if failed else "VERIFIED_RUN",
                           "application": {"build": "passed", "startup": "passed"},
                           "stages": {"source": {"commit": SHA, "patch": {"applied": bool(patch)}},
                                      "database": {"status": "ready"}},
                           "cases": cases, "isolation": {"test_runner": []}, "duration_seconds": 30}}

    def cancel(self, rid):
        pass

    def upload_zip(self, path):
        raise AssertionError("not used")


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    from app.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(queueing, "enqueue_job", lambda *a, **k: None)
    yield
    get_settings.cache_clear()


def setup(db, *, commit=SHA):
    user = User(email=f"{uuid.uuid4().hex}@x.io", password_hash="x", display_name="")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="p", website_url="https://shop.example/", hostname="shop.example",
                      authorised_at=lifecycle.now(), authorisation_statement="ok")
    db.add(project)
    db.flush()
    db.add(ProjectIntegration(project_id=project.id, kind="github_public", repo_owner="acme", repo_name="shop",
                              repo_ref="main", match_status="confirmed"))
    a = Assessment(project_id=project.id, status="completed", target_url="https://shop.example/",
                   discovery_summary={"source_commit": commit} if commit else {})
    db.add(a)
    db.flush()
    db.add(SourceAnalysisResult(assessment_id=a.id, source_kind="github", support_status="supported",
                                routes=[{"path": "/api/products", "methods": ["GET"], "file": FILE, "line": 7}]))
    f = SecurityFinding(
        assessment_id=a.id, type="SQL Injection", status="potential", severity="high", confidence="high",
        title="User input in SQL", file=FILE, line=9, endpoint="/api/products", method="GET",
        rule_id="routes.sqli.pg-tainted-query", plain_description="q reaches pool.query.", evidence_summary="e",
        technical_details={"source": {"kind": "URL query parameter", "name": "q"}}, recommendation="r",
        fingerprint=uuid.uuid4().hex[:32], snapshot={"file": FILE, "start_line": 7, "end_line": 11, "code": CODE})
    db.add(f)
    db.commit()
    return user, a, f


def llm(scripts):
    remaining = {m: list(c) for m, c in scripts.items()}

    def factory(*, endpoint, api_key, model, cache_mode, cache_dir, **_):
        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": remaining[model].pop(0)}}]})
        return LLMClient(endpoint=endpoint, api_key=api_key, model=model, cache_mode="live",
                         transport=httpx.MockTransport(handler))
    return factory


def run(db, monkeypatch, f, user, a, engine, scripts):
    r, _ = store.create_run(db, user=user, assessment=a, findings=[f])
    runner = BuildRunSandboxRunner(client=engine, poll_seconds=0)
    monkeypatch.setattr(remediate, "LLMClient", llm(scripts))
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: runner)
    remediate.run_remediate_job(str(r.id))
    db.expire_all()
    return db.get(Remediation, r.id)


def test_build_run_flow_baseline_failed_patch_correction_and_rescan(db, monkeypatch):
    user, a, f = setup(db)
    engine = ScriptedEngine(f.fingerprint)
    r = run(db, monkeypatch, f, user, a, engine,
            {MODEL_A: [PLAN_REPLY], MODEL_B: [code_reply(STILL_BAD), code_reply(FIXED)]})

    assert r.source_commit_sha == SHA
    kinds = [(s["kind"], bool(s.get("patch"))) for s in engine.started]
    # baseline, failed candidate, corrected candidate, rescan of the corrected candidate
    assert kinds == [("build_run", False), ("build_run", True), ("build_run", True), ("source", True)]
    assert all(s["ref"] == SHA for s in engine.started)  # every run pinned to the analysed revision
    assert engine.started[1]["patch"].startswith(f"--- a/{FILE}") and "@@ -7," in engine.started[1]["patch"]
    plan_sent = engine.started[1]["test_plan"]["tests"]
    assert {t["id"] for t in plan_sent} >= {"sqli-01-quote", "ai-list"}
    assert "ai-broken" not in {t["id"] for t in plan_sent}  # failed on the original: pruned
    assert "ai-post" not in {t["id"] for t in engine.started[0]["test_plan"]["tests"]}  # non-GET refused

    # The mocked engine means this verdict proves wiring only (see module docstring).
    assert r.verdict == "verified_fixed" and r.attempts_total == 2
    plan = db.scalar(select(RemediationPlan).where(RemediationPlan.remediation_id == r.id))
    assert plan.root_cause == "q is interpolated into SQL." and "ILIKE" in plan.side_effects
    assert plan.expected_behaviour and plan.patch_scope.startswith("Required context")
    suite = db.scalar(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == r.id))
    assert (suite.suite_type, suite.generation_method, suite.baseline_status) == (
        "deterministic_security", "template+llm_a", "reproduced")
    assert suite.coverage["model_tests_rejected"]
    cases = {c.name: c.validation_status for c in db.scalars(select(RemediationTestCase)
                                                             .where(RemediationTestCase.suite_id == suite.id))}
    assert cases["fails on original"] == "rejected" and cases["products list"] == "validated"
    runs = db.scalars(select(RemediationVerificationRun).where(RemediationVerificationRun.remediation_id == r.id)
                      .order_by(RemediationVerificationRun.started_at)).all()
    assert [v.purpose for v in runs] == ["baseline", "candidate", "candidate", "rescan"]
    base = runs[0]
    assert (base.build_status, base.startup_status, base.database_status, base.sandbox_id) == (
        "passed", "passed", "ready", "run-1")
    assert base.resource_usage["commit"] == SHA and base.resource_usage["cleanup"]["status"] == "complete"
    assert base.evidence_grade == "sandbox" and base.sandbox_runner == "build_run"
    failed = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)
                        .order_by(RemediationPatchAttempt.attempt_no)).all()
    assert [x.verification_status for x in failed] == ["failed", "passed"]
    assert "status 500" in failed[0].failure_reason  # real failure evidence went to the correction step
    re = db.scalar(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == r.id))
    assert re.resolved_count >= 1 and re.new_count == 0
    inv = db.scalars(select(AiModelInvocation).where(AiModelInvocation.remediation_id == r.id)
                     .order_by(AiModelInvocation.sequence)).all()
    assert inv[0].prompt_template_version.startswith("llm_a_plan/")


def test_baseline_that_does_not_reproduce_is_inconclusive_without_regenerating(db, monkeypatch):
    user, a, f = setup(db)

    class FixedAlready(ScriptedEngine):
        def get(self, rid):
            state = super().get(rid)
            for c in state.get("result", {}).get("cases", []):
                c["status"] = "passed"
            state["result"]["verification"] = "VERIFIED_RUN"
            return state

    engine = FixedAlready(f.fingerprint)
    r = run(db, monkeypatch, f, user, a, engine, {MODEL_A: [PLAN_REPLY]})
    assert len(engine.started) == 1  # one baseline: regenerating Model A cannot change it
    assert r.verdict == "inconclusive" and r.attempts_total == 0
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    assert rf.gates["testbench_validated"] is False


def test_errors_never_count_as_reproducing_the_vulnerability(db, monkeypatch):
    user, a, f = setup(db)

    class Erroring(ScriptedEngine):
        def get(self, rid):
            state = super().get(rid)
            for c in state["result"]["cases"]:
                if c["category"] == "security":
                    c["status"] = "error"
            return state

    r = run(db, monkeypatch, f, user, a, Erroring(f.fingerprint), {MODEL_A: [PLAN_REPLY]})
    assert r.verdict == "inconclusive"
    errors = db.scalars(select(RemediationTestResult).join(RemediationVerificationRun).where(
        RemediationVerificationRun.remediation_id == r.id, RemediationTestResult.outcome == "error")).all()
    assert errors and all(not e.matches_expectation for e in errors)


def test_build_failure_of_a_candidate_is_fed_back_and_attempts_stay_capped(db, monkeypatch):
    user, a, f = setup(db)

    class BrokenBuilds(ScriptedEngine):
        def get(self, rid):
            state = super().get(rid)
            if self.runs[rid]["kind"] == "build_run" and self.runs[rid].get("patch"):
                state["result"].update(verification="BUILD_FAILED", failed_stage="build", cases=[],
                                       error="next build failed: SyntaxError in route.js")
                state["result"]["application"]["build"] = "failed"
            return state

    engine = BrokenBuilds(f.fingerprint)
    r = run(db, monkeypatch, f, user, a, engine,
            {MODEL_A: [PLAN_REPLY], MODEL_B: [code_reply(FIXED), code_reply(FIXED + "\n// v2\nvoid 0;"),
                                              code_reply(FIXED + "\nvoid 1;")]})
    assert r.verdict == "human_review" and r.attempts_total == 3
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)).all()
    assert len(attempts) == 3 and all("SyntaxError" in x.failure_reason for x in attempts)
    candidate = db.scalars(select(RemediationVerificationRun).where(
        RemediationVerificationRun.remediation_id == r.id, RemediationVerificationRun.purpose == "candidate")).all()
    assert {(v.build_status, v.failure_category) for v in candidate} == {("failed", "application")}


def test_unpinned_revision_or_untestable_finding_is_inconclusive(db, monkeypatch):
    user, a, f = setup(db, commit=None)
    engine = ScriptedEngine(f.fingerprint)
    r = run(db, monkeypatch, f, user, a, engine, {})
    assert r.verdict == "inconclusive" and engine.started == [] and "commit" in r.error

    user, a, f = setup(db)
    db.execute(update(SecurityFinding).where(SecurityFinding.id == f.id).values(endpoint=None))
    db.commit()
    db.expire_all()
    engine = ScriptedEngine(f.fingerprint)
    r = run(db, monkeypatch, f, user, a, engine, {})
    assert r.verdict == "inconclusive" and engine.started == [] and "deterministic security test" in r.error


def test_source_reconstruction_rules(tmp_path):
    with pytest.raises(SourceUnavailable, match="commit"):
        source_spec(SourceRef(kind="github", owner="a", repo="b", ref="main"))
    with pytest.raises(SourceUnavailable):
        source_spec(SourceRef(kind="zip", upload_id=None))
    archive = tmp_path / "src.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    import hashlib

    good = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert source_spec(SourceRef(kind="archive", archive_path=str(archive), sha256=good)).kind == "zip"
    with pytest.raises(SourceUnavailable, match="hash"):
        source_spec(SourceRef(kind="archive", archive_path=str(archive), sha256="0" * 64))
