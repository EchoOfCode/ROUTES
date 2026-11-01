"""Real end-to-end remediation check: real sandboxes, scripted model replies.

What is REAL here:
  - the static analysis of the fixture app (analyzer sandbox: Semgrep,
    tree-sitter, data flow), which produces the SQL injection finding;
  - every verification: the Sandbox Manager's build_run engine installs,
    builds and starts the app with a synthetic PostgreSQL, and the trusted
    test runner sends the deterministic SQL injection probes over the
    private sandbox network;
  - the post-remediation rescan of the patched tree (analyzer sandbox);
  - the remediation job, store, state machine and verdict, on PostgreSQL.

What is SCRIPTED (labelled in the output): the replies of Model A and
Model B. Model B's first candidate is a plausible-but-wrong fix (it strips
semicolons); its correction parameterises the query. Nothing else is faked.

Only the local fixture (services/build_runner/tests/fixtures/shop-app) is
executed; no external repository and no external target is contacted.

Run inside the API/worker image with the engine and a throwaway database
reachable (see docs/REMEDIATION_VERIFICATION.md):
    python scripts/remediation_e2e.py
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import httpx

ROOT = Path(os.environ.get("ROUTES_ROOT", "/srv"))
FIXTURE = Path(os.environ.get("ROUTES_FIXTURE", "/fixtures/shop-app"))
WORK = Path(os.environ.get("E2E_WORK", "/tmp/e2e"))
DB_NAME = "routes_e2e"

BASE_URL = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
os.environ["DATABASE_URL"] = f"{BASE_URL}/{DB_NAME}"
os.environ.setdefault("ARTIFACTS_DIR", str(WORK / "artifacts"))

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def fresh_database() -> None:
    from sqlalchemy import create_engine, text

    admin = create_engine(f"{BASE_URL}/postgres", isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {DB_NAME}"))
        c.execute(text(f"CREATE DATABASE {DB_NAME}"))
    admin.dispose()
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT / "api", check=True,
                   capture_output=True)


def pack_fixture() -> tuple[Path, str]:
    WORK.mkdir(parents=True, exist_ok=True)
    archive = WORK / "shop-app.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(FIXTURE.rglob("*")):
            if path.is_file() and "node_modules" not in path.parts:
                z.write(path, path.relative_to(FIXTURE).as_posix())
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def analyse(engine, archive: Path) -> dict:
    from routes_core.runner import poll_run

    run = engine.start({"kind": "source", "source": "zip", "upload_id": engine.upload_zip(archive)["upload_id"]})
    final = poll_run(engine, run, deadline_seconds=900, poll_seconds=2)
    if final.get("status") != "completed":
        raise SystemExit(f"source analysis failed: {final.get('error')}")
    return final["result"]


def persist_assessment(db, result: dict, archive: Path, sha: str):
    from routes_core.mapping import source_records
    from routes_shared.contracts import SourceResult

    from app.models import (Assessment, DetectedTechnology, DiscoveredEndpoint, Project, ProjectIntegration,
                            SecurityFinding, SourceAnalysisResult, User)
    from app.services import lifecycle

    records = source_records(SourceResult.model_validate(result))
    user = User(email=f"e2e-{uuid.uuid4().hex[:8]}@routes.local", password_hash="x", display_name="e2e")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="shop-app fixture", website_url="https://shop-app.invalid/",
                      hostname="shop-app.invalid", authorised_at=lifecycle.now(), authorisation_statement="fixture")
    db.add(project)
    db.flush()
    db.add(ProjectIntegration(project_id=project.id, kind="zip", upload_filename=archive.name,
                              upload_size=archive.stat().st_size, upload_sha256=sha, match_status="confirmed"))
    a = Assessment(project_id=project.id, status="completed", target_url=project.website_url,
                   discovery_summary=records.summary)
    db.add(a)
    db.flush()
    db.add(SourceAnalysisResult(assessment_id=a.id, **records.analysis))
    for f in records.findings:
        db.add(SecurityFinding(assessment_id=a.id, **f))
    for t in records.technologies:
        db.add(DetectedTechnology(assessment_id=a.id, **t))
    for e in records.endpoints:
        db.add(DiscoveredEndpoint(assessment_id=a.id, **e))
    db.commit()
    return user, a


def scripted_llm(model: str, replies: list[str]):
    """SCRIPTED model replies (see module docstring)."""
    from worker.llm.client import LLMClient

    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        if not queue:
            raise AssertionError(f"no scripted reply left for {model}")
        return httpx.Response(200, json={"choices": [{"message": {"content": queue.pop(0)}}],
                                         "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                                         "model": f"{model} (scripted)"})
    return LLMClient(endpoint="https://scripted.invalid/v1/chat/completions", api_key="", model=model,
                     transport=httpx.MockTransport(handler))


def main() -> int:
    from routes_core.engine import EngineClient
    from sqlalchemy import select

    from app.core.config import get_settings
    from app.core.db import get_sessionmaker
    from app.models import (Remediation, RemediationFinding, RemediationPatchAttempt, RemediationReanalysisFinding,
                            RemediationReanalysisRun, RemediationTestResult, RemediationTestSuite,
                            RemediationVerificationRun, SecurityFinding)
    from app.services import remediation_store as store
    from worker.jobs.remediate import RemediationJob
    from worker.sandbox.buildrun import BuildRunSandboxRunner
    from worker.sandbox.runner import SourceRef

    started = time.monotonic()
    log("fresh database + migrations")
    fresh_database()
    archive, sha = pack_fixture()
    engine = EngineClient(os.environ["SANDBOX_MANAGER_URL"], os.environ["SANDBOX_MANAGER_TOKEN"], timeout=60)

    log("REAL static analysis of the fixture (analyzer sandbox)")
    result = analyse(engine, archive)
    db = get_sessionmaker()()
    user, assessment = persist_assessment(db, result, archive, sha)
    finding = next((f for f in db.scalars(select(SecurityFinding).where(SecurityFinding.assessment_id == assessment.id))
                    if f.rule_id.startswith("routes.sqli") and f.endpoint == "/api/products" and f.snapshot), None)
    check("analysis found the SQL injection in /api/products with a code snapshot", finding is not None)
    if finding is None:
        return 1
    code = finding.snapshot["code"]
    vulnerable = "pool.query(`SELECT id, name, price FROM products WHERE name ILIKE '%${q}%' ORDER BY id`)"
    check("snapshot contains the vulnerable query", vulnerable in code)
    fixed = code.replace(vulnerable, "pool.query(\"SELECT id, name, price FROM products WHERE name ILIKE "
                                     "'%' || $1 || '%' ORDER BY id\", [q])")
    still_bad = code.replace('const q = request.nextUrl.searchParams.get("q") ?? "";',
                             'const q = (request.nextUrl.searchParams.get("q") ?? "").replace(/;/g, "");')
    check("scripted candidates differ from the original", fixed != code and still_bad != code)

    plan_reply = json.dumps({
        "prompt_for_fix": "Pass the search term q to pool.query as a bound parameter ($1) instead of interpolating "
                          "it into the SQL text. Keep the ILIKE substring match and the response shape.",
        "root_cause": "The q query parameter is interpolated into the SQL string passed to pool.query.",
        "expected_behaviour": "Any q, including quotes and SQL fragments, is treated as data; matching products "
                              "are returned as JSON with status 200.",
        "security_test_scenarios": ["a single quote in q", "a stacked pg_sleep in q"],
        "functional_test_scenarios": ["listing all products", "searching for a product by name"],
        "regression_risks": ["moving the % wildcards into the parameter incorrectly"],
        "required_context": ["lib/db.js exports a pg Pool"],
        "functional_tests": [
            {"id": "list", "name": "product list still works", "method": "GET", "path": "/api/products",
             "expect_status": [200]},
            {"id": "search", "name": "search by name still works", "method": "GET", "path": "/api/products",
             "query": {"q": "Lamp"}, "expect_status": [200]}],
    })
    llm_a = scripted_llm("scripted-model-a", [plan_reply])
    llm_b = scripted_llm("scripted-model-b", [f"```js\n{still_bad}\n```", f"```js\n{fixed}\n```"])

    run, _ = store.create_run(db, user=user, assessment=assessment, findings=[finding])
    log(f"remediation run {run.id}: REAL Build & Run verification (baseline + candidates + rescan)")
    runner = BuildRunSandboxRunner(client=engine, cache_dir=str(WORK / "cache"))
    job = RemediationJob(run.id, get_settings(), runner, llm_a, llm_b)
    job.source_override = SourceRef(kind="archive", archive_path=str(archive), sha256=sha)
    job.run()

    db.expire_all()
    r = db.get(Remediation, run.id)
    vruns = db.scalars(select(RemediationVerificationRun).where(RemediationVerificationRun.remediation_id == r.id)
                       .order_by(RemediationVerificationRun.started_at)).all()
    print("\nVerification runs (all real sandbox executions):")
    for v in vruns:
        results = db.scalars(select(RemediationTestResult)
                             .where(RemediationTestResult.verification_run_id == v.id)).all()
        print(f"  {v.purpose:9} sandbox={v.sandbox_id} grade={v.evidence_grade} build={v.build_status} "
              f"start={v.startup_status} db={v.database_status} overall={v.overall_status} "
              f"cleanup={(v.resource_usage.get('cleanup') or {}).get('status')}")
        for t in results:
            print(f"      {t.category:8} {t.outcome:7} expected={t.expected_result:4} {t.test_name}")
    purposes = [v.purpose for v in vruns]
    check("verification sequence: baseline, failed candidate, corrected candidate, rescan",
          purposes == ["baseline", "candidate", "candidate", "rescan"], str(purposes))
    if purposes[:1] == ["baseline"]:
        base = vruns[0]
        sec = db.scalars(select(RemediationTestResult).where(RemediationTestResult.verification_run_id == base.id,
                                                             RemediationTestResult.category == "exploit")).all()
        check("baseline: the original app built and started in the sandbox",
              (base.build_status, base.startup_status) == ("passed", "passed"),
              f"{base.build_status}/{base.startup_status}")
        check("baseline: a security probe FAILED on the original code (vulnerability reproduced)",
              any(t.outcome == "failed" for t in sec), ", ".join(f"{t.test_name}={t.outcome}" for t in sec))
    suite = db.scalar(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == r.id))
    check("testbench validated against the original code", suite is not None and suite.validation_status ==
          "validated" and suite.baseline_status == "reproduced")
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == r.id)
                          .order_by(RemediationPatchAttempt.attempt_no)).all()
    check("attempt 1 (wrong fix) failed verification; attempt 2 passed",
          [a.verification_status for a in attempts] == ["failed", "passed"],
          str([(a.attempt_no, a.verification_status) for a in attempts]))
    if attempts:
        print(f"\n  failure evidence sent to the correction step:\n    {attempts[0].failure_reason}")
    candidates = [v for v in vruns if v.purpose == "candidate"]
    if len(candidates) == 2:
        check("the corrected patch changed the security test outcome in the real app",
              candidates[0].security_status == "failed" and candidates[1].security_status == "passed",
              f"{candidates[0].security_status} -> {candidates[1].security_status}")
    re = db.scalar(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == r.id))
    if re is not None:
        target = db.scalar(select(RemediationReanalysisFinding).where(
            RemediationReanalysisFinding.reanalysis_id == re.id,
            RemediationReanalysisFinding.fingerprint == finding.fingerprint))
        check("independent rescan of the patched tree: finding resolved, nothing new",
              target is not None and target.change == "resolved" and re.new_count == 0,
              f"resolved={re.resolved_count} remaining={re.remaining_count} new={re.new_count}")
    rf = db.scalar(select(RemediationFinding).where(RemediationFinding.remediation_id == r.id))
    check("final verdict verified_fixed from real sandbox evidence",
          r.verdict == "verified_fixed" and rf.gates.get("real_sandbox_evidence") is True,
          f"verdict={r.verdict}: {r.verdict_reason}; gates={rf.gates}")
    check("every sandbox reported complete cleanup",
          all((v.resource_usage.get("cleanup") or {}).get("status") == "complete" for v in vruns
              if v.purpose != "rescan"))
    print(f"\n{sum(ok for _, ok, _ in CHECKS)}/{len(CHECKS)} checks passed in {time.monotonic() - started:.0f}s "
          "(model replies scripted; analysis, builds, tests and rescan real)")
    db.close()
    return 0 if all(ok for _, ok, _ in CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
