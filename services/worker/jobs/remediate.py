"""Remediation job: worker-side entry point for the `remediate` queue.

Claims the run (lease), then for each patch batch: records the source
context and its redaction, runs the loop controller with an observer that
persists every step *as it happens* (model invocations, plans, testbench
versions, gate/baseline runs, patch attempts, verification runs, test
results, rescans), and finally lets the store decide the verdict from those
records. Each persistence call is its own short transaction; none is open
while a model provider or a sandbox is working.

A second delivery of the same job finds the lease held (or the run finished)
and does nothing. A run whose worker died is resumed: its attempt numbers
continue, and unfinished attempts count as used.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select

from routes_shared.fingerprint import finding_identity
from routes_shared.redaction import redact_for_llm, redact_text, unredacted_secret_count
from routes_shared.remediation import Snapshot
from routes_shared.remediation_workflow import InvalidTransition, Stage

from app.core.config import get_settings
from routes_core.testplan import generate as generate_test_plan

from app.models import (
    ProjectIntegration,
    Remediation,
    RemediationArtifact,
    RemediationFinding,
    RemediationPatchAttempt,
    RemediationPatchBatch,
    RemediationPlan,
    RemediationTestSuite,
    SecurityFinding,
    SourceAnalysisResult,
)
from app.services import artifacts, outbox
from app.services import remediation_store as store
from worker.jobs.common import db_session
from worker.llm import llm_a as llm_a_module
from worker.llm import llm_b as llm_b_module
from worker.llm.client import LLMClient, LLMError
from worker.loop import LoopObserver, RoundRecord, run_remediation_loop
from worker.sandbox import SandboxFile, SandboxRunRequest, SourceRef, build_sandbox_runner
from worker.sandbox.runner import SandboxRunner, SandboxRunResult

log = logging.getLogger("routes.worker.remediate")


def _tx(fn, *args, **kwargs):
    """Run one store operation in its own short transaction."""
    with db_session() as db:
        return fn(db, *args, **kwargs)


def _source_ref(integration: ProjectIntegration | None, commit_sha: str | None = None) -> SourceRef | None:
    if integration is None:
        return None
    if integration.kind in ("github_public", "github_private"):
        return SourceRef(kind="github", owner=integration.repo_owner, repo=integration.repo_name,
                         ref=integration.repo_ref, commit_sha=commit_sha)
    if integration.kind == "zip":
        # No upload_id is persisted past the original scan (only filename and
        # sha256 are kept), so a zip-sourced rescan has nothing stable to
        # re-fetch; the real backend reports that as an error.
        return SourceRef(kind="zip", upload_id=None)
    return None


def _execution(result: SandboxRunResult) -> store.Execution:
    return store.Execution(
        status=result.status, duration_ms=result.duration_ms, stdout=result.stdout, stderr=result.stderr,
        error_reason=result.error_reason, evidence=result.evidence,
        tests=[store.TestOutcome(name=t.name, category=t.category, passed=t.passed, message=t.message,
                                 outcome=t.outcome)
               for t in result.tests],
    )


def build_run_testbench(deterministic_plan: dict, finding: dict):
    """Testbench factory for the Build & Run verifier: the deterministic
    security tests ROUTES generated from the finding's data flow, plus the
    schema-validated functional tests Model A proposed (which the baseline
    still has to confirm). Returns (Model A result, Testbench)."""
    from routes_shared.buildrun import TestPlan
    from routes_shared.remediation import Testbench

    from worker.llm.llm_a_plan import call_llm_a_plan

    def factory(llm_a_client, _finding, snapshot):
        result = call_llm_a_plan(llm_a_client, finding, snapshot)
        tests = list(deterministic_plan["tests"])
        ids = {t["id"] for t in tests}
        for t in result.functional_tests:
            if t["id"] not in ids:
                tests.append(t)
                ids.add(t["id"])
        plan = TestPlan.model_validate({**deterministic_plan, "tests": tests}).model_dump(by_alias=True)
        return result, Testbench(path="routes-testplan.json", content=json.dumps(plan, sort_keys=True))
    return factory


@dataclass
class BatchState:
    batch_id: uuid.UUID
    finding_id: uuid.UUID
    snapshot: dict
    plan: RemediationPlan | None = None
    suite_id: uuid.UUID | None = None
    attempt_id: uuid.UUID | None = None
    candidate_runs: dict = field(default_factory=dict)


class RedactionBlocked(LLMError):
    """A model request still contained a secret-like value and was not sent."""


class RecordingLLMClient:
    """Wraps an LLMClient: refuses any request that still contains a
    secret-like value, and records every call (hashes, usage, timing; the
    redacted input/output only as access-controlled artifacts)."""

    def __init__(self, inner: LLMClient, *, role: str, run_id: uuid.UUID, worker_id: str, template_version: str,
                 batch: dict) -> None:
        self.inner, self.role, self.run_id, self.worker_id = inner, role, run_id, worker_id
        self.template_version = template_version
        self.batch = batch  # shared holder: {"id": current batch id}
        self.last_invocation_id: uuid.UUID | None = None

    def close(self) -> None:
        self.inner.close()

    def complete(self, messages: list[dict], *, temperature: float = 0.0) -> str:
        self.last_invocation_id = None
        input_text = json.dumps(messages, sort_keys=True, ensure_ascii=False)
        residual = sum(unredacted_secret_count(m.get("content", "")) for m in messages)
        if residual:
            _tx(store.invocation_blocked, self.run_id, self.worker_id, role=self.role, provider=self.inner.provider,
                model=self.inner.model, template_version=self.template_version,
                input_sha256=hashlib.sha256(input_text.encode()).hexdigest(), batch_id=self.batch.get("id"),
                reason=f"{residual} secret-like value(s) survived redaction; nothing was sent")
            raise RedactionBlocked("Refused to send a model request that still contains a secret-like value.")
        inv_id = _tx(store.invocation_started, self.run_id, self.worker_id, role=self.role,
                     provider=self.inner.provider, model=self.inner.model, template_version=self.template_version,
                     input_text=input_text, batch_id=self.batch.get("id"), cache_mode=self.inner.cache_mode)
        try:
            content = self.inner.complete(messages, temperature=temperature)
        except LLMError as exc:
            category = "cache_miss" if "replay mode" in str(exc) else "provider_error"
            _tx(store.invocation_finished, inv_id, status="failed", error_category=category, error_detail=str(exc))
            raise
        _tx(store.invocation_finished, inv_id, status="succeeded", output_text=content, usage=self.inner.last_usage)
        self.last_invocation_id = inv_id
        return content


class PersistingObserver(LoopObserver):
    """Persists every step of the loop for one patch batch."""

    def __init__(self, job: RemediationJob, state: BatchState) -> None:
        self.job, self.state = job, state

    # stage changes -------------------------------------------------------
    def stage(self, stage: str) -> None:
        self.job.transition(stage)

    # testbench -----------------------------------------------------------
    def testbench_generated(self, attempt, llm_a_result, testbench) -> None:
        j, st = self.job, self.state
        j.transition(Stage.PLANNING)
        structured = {k: getattr(llm_a_result, k, None) for k in (
            "root_cause", "expected_behaviour", "security_test_scenarios", "functional_test_scenarios",
            "regression_risks", "required_context")}
        st.plan = _tx(store.add_plan, j.run_id, j.worker_id, batch_id=st.batch_id,
                      strategy=llm_a_result.prompt_for_fix, files=[st.snapshot["file"]],
                      invocation_id=j.llm_a.last_invocation_id, structured=structured)
        j.transition(Stage.GENERATING_TESTS)
        if j.runner.kind == "build_run":
            suite = _tx(store.add_suite, j.run_id, j.worker_id, batch_id=st.batch_id, plan_id=st.plan.id,
                        testbench_path=testbench.path, testbench=testbench.content,
                        suite_type="deterministic_security", generation_method="template+llm_a",
                        coverage={"model_functional_tests": len(getattr(llm_a_result, "functional_tests", [])),
                                  "model_tests_rejected": getattr(llm_a_result, "rejected_tests", [])[:10]})
        else:
            suite = _tx(store.add_suite, j.run_id, j.worker_id, batch_id=st.batch_id, plan_id=st.plan.id,
                        testbench_path=testbench.path, testbench=testbench.content)
        st.suite_id = suite.id

    def gate_finished(self, attempt, testbench, gate_result) -> None:
        j, st = self.job, self.state
        baseline = None
        for i, (label, result) in enumerate(gate_result.runs):
            execution = _execution(result)
            purpose = "baseline" if label == "original" else "gate_known_bad"
            if purpose == "baseline":
                baseline = execution
            _tx(store.record_verification, j.run_id, j.worker_id, purpose=purpose,
                revision_label="original" if purpose == "baseline" else f"known_bad:{label}", execution=execution,
                runner_kind=j.runner.kind, evidence_grade=j.runner.evidence_grade,
                idempotency_key=f"{st.suite_id}:gate:{i}", batch_id=st.batch_id, suite_id=st.suite_id,
                expect_exploits_to_fail=True)
        _tx(store.finish_suite_validation, j.run_id, j.worker_id, st.suite_id, passed=gate_result.passed,
            failed_check=gate_result.failed_check, baseline=baseline, dropped=gate_result.dropped_tests)

    # patch attempts ------------------------------------------------------
    def round_started(self, round_no: int) -> None:
        j, st = self.job, self.state
        j.llm_b.last_invocation_id = None
        attempt = _tx(store.start_attempt, j.run_id, j.worker_id, st.batch_id, plan=st.plan)
        if attempt.attempt_no != round_no:
            log.warning("attempt number %s differs from loop round %s", attempt.attempt_no, round_no)
        st.attempt_id = attempt.id

    def candidate_ready(self, round_no: int, record: RoundRecord, errors: list[str]) -> list[str] | None:
        j, st = self.job, self.state
        from_model = record.fix_source == "llm_b"
        invocation_id = j.llm_b.last_invocation_id if from_model else None
        if record.candidate_code is None and invocation_id is not None:
            _tx(store.mark_invocation, invocation_id, "invalid_output", "; ".join(errors))
        attempt = _tx(store.finish_generation, j.run_id, j.worker_id, st.attempt_id, snapshot=st.snapshot,
                      candidate_code=record.candidate_code, candidate_hash=record.candidate_hash,
                      fix_source=record.fix_source, fix_note=record.fix_note, invocation_id=invocation_id,
                      errors=errors)
        if attempt.validation_status != "valid" and record.candidate_code is not None and not errors:
            return [attempt.failure_reason or "patch validation failed"]
        return None

    def verified(self, round_no, request: SandboxRunRequest, result: SandboxRunResult) -> None:
        j, st = self.job, self.state
        vr = _tx(store.record_verification, j.run_id, j.worker_id, purpose="candidate",
                 revision_label=f"candidate:{st.attempt_id}",
                 execution=_execution(result), runner_kind=j.runner.kind, evidence_grade=j.runner.evidence_grade,
                 idempotency_key=f"{st.attempt_id}:candidate", batch_id=st.batch_id, attempt_id=st.attempt_id,
                 suite_id=st.suite_id, sandbox_id=request.run_id)
        st.candidate_runs[st.attempt_id] = vr.id

    def rescanned(self, round_no, request: SandboxRunRequest, result: SandboxRunResult) -> None:
        j, st = self.job, self.state
        vr = _tx(store.record_verification, j.run_id, j.worker_id, purpose="rescan",
                 revision_label=f"candidate:{st.attempt_id}", execution=_execution(result),
                 runner_kind=j.runner.kind, evidence_grade=j.runner.evidence_grade,
                 idempotency_key=f"{st.attempt_id}:rescan", batch_id=st.batch_id, attempt_id=st.attempt_id,
                 sandbox_id=request.run_id)
        _tx(store.record_reanalysis, j.run_id, j.worker_id, attempt_id=st.attempt_id, verification_run_id=vr.id,
            candidate_revision=f"candidate:{st.attempt_id}", rescan_fingerprints=result.rescan_fingerprints,
            evidence_grade=j.runner.evidence_grade, engine_versions={"runner": j.runner.kind},
            rescan_findings=result.rescan_findings)

    def round_finished(self, record: RoundRecord, passed: bool) -> None:
        j, st = self.job, self.state
        if passed:
            status = "passed"
        elif record.test_results:
            status = "error" if record.test_results.get("status") in ("error", "timeout", "killed") else "failed"
        else:
            status = "skipped"
        _tx(store.finish_attempt, j.run_id, j.worker_id, st.attempt_id, verification_status=status,
            failure_reason=record.failure_output, test_results=record.test_results, rescan_diff=record.rescan_diff)


class RemediationJob:
    def __init__(self, run_id: uuid.UUID, settings, runner: SandboxRunner, llm_a_client: LLMClient,
                 llm_b_client: LLMClient) -> None:
        self.run_id = run_id
        self.settings = settings
        self.runner = runner
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.batch_holder: dict = {}
        self.llm_a = RecordingLLMClient(llm_a_client, role="analysis", run_id=run_id, worker_id=self.worker_id,
                                        template_version=llm_a_module.PROMPT_TEMPLATE_VERSION, batch=self.batch_holder)
        self.llm_b = RecordingLLMClient(llm_b_client, role="patch_generation", run_id=run_id,
                                        worker_id=self.worker_id,
                                        template_version=llm_b_module.PROMPT_TEMPLATE_VERSION,
                                        batch=self.batch_holder)
        self.hints: dict[str, dict] = {}
        # Tests (and the CLI) may supply an immutable retained archive instead
        # of the project integration.
        self.source_override: SourceRef | None = None
        if runner.kind == "build_run":
            from worker.llm.llm_a_plan import PROMPT_TEMPLATE_VERSION as PLAN_TEMPLATE

            self.llm_a.template_version = PLAN_TEMPLATE

    def transition(self, stage: str, *, resume: bool = False) -> None:
        _tx(store.transition, self.run_id, self.worker_id, stage, resume=resume)

    def should_cancel(self) -> bool:
        return _tx(store.cancel_requested, self.run_id)

    # ------------------------------------------------------------------
    def run(self) -> None:
        run = _tx(store.claim, self.run_id, self.worker_id)
        if run is None:
            log.info("remediation %s already claimed or finished; nothing to do", self.run_id)
            return
        resumed = run.stage != Stage.QUEUED
        try:
            self.transition(Stage.PREPARING_CONTEXT, resume=resumed)
            if resumed:
                _tx(store.abandon_open_attempts, self.run_id, self.worker_id)
            outcome = self._process()
            if outcome == "cancelled":
                _tx(store.finalize, self.run_id, worker_id=self.worker_id, hints=self.hints, cancelled=True)
            else:
                _tx(store.finalize, self.run_id, worker_id=self.worker_id, hints=self.hints)
        except store.LeaseLost:
            log.warning("remediation %s: lease lost, another worker continues", self.run_id)
        except RedactionBlocked:
            reason = ("A model request was blocked because a secret-like value survived redaction; nothing was "
                      "sent. A person needs to review the source context.")
            with db_session() as db:
                ids = db.scalars(select(RemediationFinding.finding_id)
                                 .where(RemediationFinding.remediation_id == self.run_id)).all()
            for fid in ids:
                self.hints.setdefault(str(fid), {})["human_review_reason"] = reason
            _tx(store.finalize, self.run_id, worker_id=self.worker_id, hints=self.hints)
        except LLMError as exc:
            message = str(exc)
            if "did not return" in message or "must both be strings" in message:
                # The provider answered, but not in the required shape.
                for client in (self.llm_a, self.llm_b):
                    _tx(store.mark_invocation, client.last_invocation_id, "invalid_output", message)
            self._fail(f"Model provider error: {redact_text(message, max_length=300)}")
        except InvalidTransition as exc:
            self._fail(f"Internal workflow error: {exc}")
            raise
        except Exception:
            self._fail("An internal error interrupted remediation.")
            raise
        finally:
            with db_session() as db:
                outbox.relay_safely(db)

    def _fail(self, message: str) -> None:
        try:
            _tx(store.finalize, self.run_id, worker_id=self.worker_id, hints=self.hints, infrastructure_error=message)
        except store.LeaseLost:
            pass

    def _process(self) -> str | None:
        with db_session() as db:
            run = db.get(Remediation, self.run_id)
            integration = db.scalar(select(ProjectIntegration)
                                    .where(ProjectIntegration.project_id == run.project_id))
            source_ref = self.source_override or _source_ref(integration, run.source_commit_sha)
            routes = []
            if self.runner.kind == "build_run":
                analysis = db.scalar(select(SourceAnalysisResult)
                                     .where(SourceAnalysisResult.assessment_id == run.assessment_id))
                routes = list(analysis.routes) if analysis is not None else []
            rows = db.execute(
                select(RemediationPatchBatch, RemediationFinding, SecurityFinding)
                .join(RemediationFinding, RemediationFinding.patch_batch_id == RemediationPatchBatch.id)
                .join(SecurityFinding, SecurityFinding.id == RemediationFinding.finding_id)
                .where(RemediationPatchBatch.remediation_id == self.run_id)
                .order_by(RemediationPatchBatch.sequence)
            ).all()
            batches = [(b.id, b.status, b.attempts_used, b.max_attempts, f.id, f.snapshot,
                        {"id": str(f.id), "rule_id": f.rule_id, "title": f.title, "type": f.type,
                         "status": f.status, "file": f.file, "line": f.line, "endpoint": f.endpoint,
                         "method": f.method, "technical_details": f.technical_details,
                         "plain_description": f.plain_description, "fingerprint": f.fingerprint})
                       for b, _rf, f in rows]
            originals = db.scalars(select(SecurityFinding)
                                   .where(SecurityFinding.assessment_id == run.assessment_id)).all()
            baseline = {f.fingerprint for f in originals}
            identities = {f.fingerprint: finding_identity({"rule_id": f.rule_id, "file": f.file,
                                                           "endpoint": f.endpoint, "method": f.method})
                          for f in originals}

        first = True
        accepted_batches = 0
        last_testbench = None
        for batch_id, status, used, max_attempts, finding_id, snapshot, finding_dict in batches:
            if status not in ("pending", "in_progress"):
                accepted_batches += status == "verified"
                continue  # finished by an earlier execution of this run
            if not first:
                self.transition(Stage.PREPARING_CONTEXT)
            first = False
            self.batch_holder["id"] = batch_id
            key = str(finding_id)
            if not snapshot:
                self.hints[key] = {"unsupported_reason": "No code snapshot is available for this finding."}
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "inconclusive")
                continue
            if source_ref is None:
                self.hints[key] = {"unsupported_reason": "No source reference is available to rescan against."}
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "inconclusive")
                continue
            if used >= max_attempts:
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "exhausted")
                continue

            # Context + redaction record. The loop's LLM A call redacts the
            # same snapshot with the same engine; this records and verifies it.
            self.transition(Stage.REDACTING)
            redacted, placeholder_map = redact_for_llm(snapshot["code"])
            ctx = _tx(store.record_context, self.run_id, self.worker_id, batch_id=batch_id, finding_id=finding_id,
                      snapshot=snapshot, redacted_code=redacted, placeholders=len(placeholder_map))
            if not ctx.redaction_verified:
                self.hints[key] = {"human_review_reason": (
                    "Redaction of the source context could not be verified, so no code was sent to a model. "
                    "A person needs to review the context first.")}
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "human_review")
                continue

            factory = None
            if self.runner.kind == "build_run":
                from worker.sandbox.buildrun import SourceUnavailable, source_spec

                try:
                    source_spec(source_ref)
                except SourceUnavailable as exc:
                    self.hints[key] = {"unsupported_reason": f"Dynamic verification is not possible: {exc}"}
                    _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "inconclusive")
                    continue
                generated = generate_test_plan(routes, [finding_dict])
                if not generated.flows_covered:
                    notes = "; ".join(generated.notes[:3])
                    self.hints[key] = {"unsupported_reason": (
                        "ROUTES could not generate a deterministic security test for this finding, so the original "
                        f"vulnerability cannot be reproduced ({notes or 'no HTTP route reaches it'}).")}
                    _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "inconclusive")
                    continue
                self.runner.bind(source_ref, self.should_cancel)
                factory = build_run_testbench(generated.plan, finding_dict)

            state = BatchState(batch_id=batch_id, finding_id=finding_id, snapshot=snapshot)
            outcome = run_remediation_loop(
                testbench_factory=factory, baseline_identities=identities,
                finding=finding_dict,
                snapshot=Snapshot(file=snapshot["file"], start_line=snapshot["start_line"],
                                  end_line=snapshot["end_line"], code=snapshot["code"]),
                llm_a_client=self.llm_a, llm_b_client=self.llm_b, sandbox_runner=self.runner,
                source_ref=source_ref, baseline_fingerprints=baseline, max_rounds=max_attempts,
                stagnation_rounds=self.settings.stagnation_rounds, should_cancel=self.should_cancel,
                observer=PersistingObserver(self, state), first_round=used + 1,
            )
            if outcome.status == "cancelled":
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "cancelled")
                return "cancelled"
            if outcome.status == "fixed":
                accepted_batches += 1
                last_testbench = state.suite_id
                _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "verified")
            else:
                reason = outcome.reason or ""
                if reason.startswith("oscillation"):
                    self.hints[key] = {"oscillation": True}
                    _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "human_review")
                elif "testbench" in reason:
                    _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "inconclusive")
                else:
                    _tx(store.finish_batch, self.run_id, self.worker_id, batch_id, "exhausted")

        if accepted_batches > 1:
            self._combined_rescan(source_ref, last_testbench)
        return None

    def _combined_rescan(self, source_ref: SourceRef, suite_id: uuid.UUID | None) -> None:
        """Rescan with every accepted candidate applied together, so fixes that
        only pass in isolation are caught."""
        with db_session() as db:
            accepted = db.execute(
                select(RemediationPatchAttempt, RemediationArtifact)
                .join(RemediationArtifact, RemediationArtifact.id == RemediationPatchAttempt.candidate_artifact_id)
                .where(RemediationPatchAttempt.remediation_id == self.run_id,
                       RemediationPatchAttempt.verification_status == "passed")
            ).all()
            files = []
            patches = []
            for attempt, art in accepted:
                rf = db.scalar(select(RemediationFinding).where(RemediationFinding.patch_batch_id == attempt.batch_id))
                finding = db.get(SecurityFinding, rf.finding_id)
                code = artifacts.read_text(art)
                patch = artifacts.read_text(db.get(RemediationArtifact, attempt.patch_artifact_id))                     if attempt.patch_artifact_id else None
                if code is None or patch is None:
                    return
                files.append(SandboxFile(path=finding.snapshot["file"], content=code))
                patches.append(patch)  # batches never share a file, so the diffs combine cleanly
            suite = db.get(RemediationTestSuite, suite_id) if suite_id else None
            testbench = artifacts.read_text(db.get(RemediationArtifact, suite.artifact_id)) if suite else ""
        self.transition(Stage.POST_REMEDIATION_ANALYSIS)
        request = SandboxRunRequest(run_id=str(uuid.uuid4()), finding_id="", round_no=0, files=files,
                                    testbench=SandboxFile(path="combined.test.ts", content=testbench or ""),
                                    source_ref=source_ref, patch="".join(patches))
        result = self.runner.run(request)
        vr = _tx(store.record_verification, self.run_id, self.worker_id, purpose="combined_rescan",
                 revision_label="combined:all accepted batches", execution=_execution(result),
                 runner_kind=self.runner.kind, evidence_grade=self.runner.evidence_grade,
                 idempotency_key=f"{self.run_id}:combined:{request.run_id}", sandbox_id=request.run_id)
        _tx(store.record_reanalysis, self.run_id, self.worker_id, attempt_id=None, verification_run_id=vr.id,
            candidate_revision="combined:all accepted batches", rescan_fingerprints=result.rescan_fingerprints,
            evidence_grade=self.runner.evidence_grade, scope="combined", engine_versions={"runner": self.runner.kind},
            rescan_findings=result.rescan_findings)


def run_remediate_job(job_id: str, finding_id: str | None = None) -> None:
    """RQ entry point. `finding_id` is accepted for compatibility with jobs
    enqueued before runs could target several findings; the run's findings
    are read from the database."""
    settings = get_settings()
    llm_a_client = LLMClient(endpoint=settings.llm_a_endpoint, api_key=settings.llm_a_api_key,
                             model=settings.llm_a_model, cache_mode=settings.llm_cache_mode,
                             cache_dir=settings.llm_cache_dir, proxy=settings.llm_proxy_url or None)
    llm_b_client = LLMClient(endpoint=settings.llm_b_endpoint, api_key=settings.llm_b_api_key,
                             model=settings.llm_b_model, cache_mode=settings.llm_cache_mode,
                             cache_dir=settings.llm_cache_dir, proxy=settings.llm_proxy_url or None)
    sandbox_runner = build_sandbox_runner(settings.sandbox_runner_kind, manager_url=settings.sandbox_manager_url,
                                          manager_token=settings.sandbox_manager_token,
                                          cache_dir=settings.verify_cache_dir)
    try:
        RemediationJob(uuid.UUID(job_id), settings, sandbox_runner, llm_a_client, llm_b_client).run()
    finally:
        llm_a_client.close()
        llm_b_client.close()
        close = getattr(sandbox_runner, "close", None)
        if close is not None:
            close()
