"""Remediation job tests (real PostgreSQL): proves the job correctly wires
the loop controller (S8c) to real DB rows - fake LLM transports and a
scripted FakeSandboxRunner, no real network/sandbox calls. The loop's own
decision logic (rounds, oscillation, stop rules) is covered exhaustively in
test_loop.py; this file only covers the job's DB wiring.
"""

import json
import uuid

import httpx
from sqlalchemy import select

from routes_shared.enums import FindingRemediationStatus, RemediationStatus

from app.models import Assessment, Project, ProjectIntegration, Remediation, RemediationIteration, SecurityFinding, User
from app.services import lifecycle
from worker.gate_library import known_bad_fixes_for
from worker.jobs import remediate
from worker.llm.client import LLMClient
from worker.sandbox.fake import FakeSandboxRunner
from worker.sandbox.runner import SandboxRunResult, TestResult

SNAPSHOT = {
    "file": "app/api/search/route.ts", "start_line": 1, "end_line": 5,
    "code": (
        "export async function GET(request) {\n"
        '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
        "  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);\n"
        "  return NextResponse.json(result.rows);\n"
        "}\n"
    ),
}
RULE_ID = "routes.sqli.pg-tainted-query"
N_BAD_FIXES = len(known_bad_fixes_for(RULE_ID))
LLM_A_CONTENT = json.dumps({"prompt_for_fix": "Parameterise the query.", "testbench": "test('exploit', () => {})"})
LLM_B_CONTENT = (
    "```ts\n"
    "export async function GET(request) {\n"
    '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
    "  const result = await pool.query('SELECT * FROM products WHERE name ILIKE $1', [`%${q}%`]);\n"
    "  return NextResponse.json(result.rows);\n"
    "}\n"
    "```"
)


def _gated_ok() -> SandboxRunResult:
    return SandboxRunResult(
        status="failed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=False),
              TestResult(name="benign works", category="benign", passed=True)],
    )


def _verify_pass() -> SandboxRunResult:
    return SandboxRunResult(
        status="passed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=True),
              TestResult(name="benign works", category="benign", passed=True)],
    )


def _rescan(fingerprints: list[str]) -> SandboxRunResult:
    return SandboxRunResult(status="passed", rescan_fingerprints=fingerprints)


def _fake_llm_factory(contents_by_model: dict[str, list[str]]):
    remaining = {model: list(c) for model, c in contents_by_model.items()}

    def factory(*, endpoint, api_key, model, cache_mode, cache_dir, **_):
        def handler(request: httpx.Request) -> httpx.Response:
            queue = remaining[model]
            if not queue:
                raise AssertionError(f"ran out of scripted responses for {model}")
            return httpx.Response(200, json={"choices": [{"message": {"content": queue.pop(0)}}]})
        return LLMClient(endpoint=endpoint, api_key=api_key, model=model, cache_mode="live",
                         transport=httpx.MockTransport(handler))

    return factory


def make_finding(db, *, with_integration=True) -> SecurityFinding:
    user = User(email=f"{uuid.uuid4().hex}@x.io", password_hash="x", display_name="")
    db.add(user)
    db.flush()
    project = Project(
        owner_id=user.id, name="p", website_url="https://example.com/", hostname="example.com",
        authorised_at=lifecycle.now(), authorisation_statement="ok",
    )
    db.add(project)
    db.flush()
    if with_integration:
        db.add(ProjectIntegration(project_id=project.id, kind="github_public", repo_owner="acme", repo_name="shop",
                                  match_status="confirmed"))
    assessment = Assessment(project_id=project.id, status="completed", target_url="https://example.com/")
    db.add(assessment)
    db.flush()
    finding = SecurityFinding(
        assessment_id=assessment.id, type="SQL Injection", status="potential", severity="high", confidence="high",
        title="User input used to build a SQL query", file=SNAPSHOT["file"], line=3, endpoint="/api/search",
        method="GET", rule_id=RULE_ID, plain_description="Input reaches a database query without parameterisation.",
        evidence_summary="e", technical_details={}, recommendation="r", fingerprint=uuid.uuid4().hex[:32],
        snapshot=dict(SNAPSHOT),
    )
    db.add(finding)
    db.commit()
    return finding


def _remediation_for(db, finding) -> Remediation:
    remediation = Remediation(finding_id=finding.id, status=RemediationStatus.PENDING)
    db.add(remediation)
    db.commit()
    return remediation


def test_remediate_job_fixes_the_finding_and_persists_iterations(db, monkeypatch):
    finding = make_finding(db)
    remediation = _remediation_for(db, finding)

    monkeypatch.setattr(remediate, "LLMClient",
                        _fake_llm_factory({"llama-3.3-70b-versatile": [LLM_A_CONTENT],
                                          "qwen/qwen-2.5-coder-32b-instruct:free": [LLM_B_CONTENT]}))
    sandbox = FakeSandboxRunner([_gated_ok() for _ in range(1 + N_BAD_FIXES)] + [_verify_pass(), _rescan([])])
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: sandbox)

    remediate.run_remediate_job(str(remediation.id), str(finding.id))

    db.expire_all()
    row = db.get(Remediation, remediation.id)
    assert row.status == RemediationStatus.SUCCEEDED
    assert row.finding_status == FindingRemediationStatus.FIXED
    assert row.started_at is not None and row.finished_at is not None

    iterations = db.scalars(
        select(RemediationIteration).where(RemediationIteration.remediation_id == remediation.id)
    ).all()
    assert len(iterations) == 1
    assert iterations[0].round_no == 1
    assert iterations[0].candidate_hash is not None
    assert iterations[0].rescan_diff == {"fingerprint_gone": True, "new_fingerprints": []}


def test_remediate_job_needs_human_review_when_no_snapshot(db, monkeypatch):
    finding = make_finding(db)
    finding.snapshot = None
    db.commit()
    remediation = _remediation_for(db, finding)

    monkeypatch.setattr(remediate, "LLMClient", _fake_llm_factory({}))
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: FakeSandboxRunner([]))

    remediate.run_remediate_job(str(remediation.id), str(finding.id))

    db.expire_all()
    row = db.get(Remediation, remediation.id)
    assert row.status == RemediationStatus.NEEDS_HUMAN_REVIEW
    assert "snapshot" in row.error


def test_remediate_job_needs_human_review_when_no_source_ref(db, monkeypatch):
    finding = make_finding(db, with_integration=False)
    remediation = _remediation_for(db, finding)

    monkeypatch.setattr(remediate, "LLMClient", _fake_llm_factory({}))
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: FakeSandboxRunner([]))

    remediate.run_remediate_job(str(remediation.id), str(finding.id))

    db.expire_all()
    row = db.get(Remediation, remediation.id)
    assert row.status == RemediationStatus.NEEDS_HUMAN_REVIEW
    assert "source reference" in row.error


def test_remediate_job_is_idempotent_for_a_redelivered_terminal_job(db, monkeypatch):
    finding = make_finding(db)
    remediation = _remediation_for(db, finding)
    remediation.status = RemediationStatus.SUCCEEDED
    remediation.finding_status = FindingRemediationStatus.FIXED
    db.commit()

    monkeypatch.setattr(remediate, "LLMClient", _fake_llm_factory({}))
    monkeypatch.setattr(remediate, "build_sandbox_runner", lambda kind, **kw: FakeSandboxRunner([]))

    remediate.run_remediate_job(str(remediation.id), str(finding.id))  # should be a no-op, not re-run

    db.expire_all()
    row = db.get(Remediation, remediation.id)
    assert row.status == RemediationStatus.SUCCEEDED
