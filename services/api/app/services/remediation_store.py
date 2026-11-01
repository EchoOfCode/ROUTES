"""Remediation repository / data-access layer.

Every function here is one atomic unit of work: it takes a Session, makes all
of its related writes, appends the matching audit event and commits. The
worker calls these with a fresh short-lived session between external calls,
so no database transaction is ever held open while a model provider or a
sandbox is working.

Concurrency model:
  - A worker *claims* a run with a lease (conditional UPDATE). Only the lease
    owner may advance it; a second delivery of the same job finds the lease
    held and does nothing. A crashed worker's lease expires and the run can be
    resumed (bounded by REMEDIATION_MAX_RECOVERIES).
  - State changes lock the run row (SELECT ... FOR UPDATE), check the lease
    and the state machine, and bump ``version``.
  - Attempt numbers are allocated under a row lock on the batch, are unique
    per batch, and can never exceed the batch's limit (also a CHECK).
  - At most one active run per finding (partial unique index).

The final verdict is computed from the persisted evidence rows, never from
worker memory or from what a model claimed.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from routes_shared.buildrun import PatchRejected, validate_patch
from routes_shared.fingerprint import finding_identity, match_reanalysis
from routes_shared.patching import unified_diff
from routes_shared.redaction import (
    REDACTION_ENGINE,
    REDACTION_RULESET_VERSION,
    redact_structure,
    redact_text,
    unredacted_secret_count,
)
from routes_shared.remediation_workflow import (
    LEGACY_FINDING_STATUS,
    LEGACY_STATUS,
    TERMINAL_STAGES,
    VERDICT_STAGE,
    EvidenceGrade,
    FailureCategory,
    FindingEvidence,
    Resolution,
    Stage,
    Verdict,
    check_transition,
    decide_finding,
    decide_run,
)

from app.core.config import get_settings
from app.models import (
    AiModelInvocation,
    Assessment,
    ProjectIntegration,
    Remediation,
    RemediationArtifact,
    RemediationAuditEvent,
    RemediationBatchFile,
    RemediationContext,
    RemediationFinding,
    RemediationIteration,
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
from app.services import artifacts, outbox

SUPPORTED_RULE_PREFIXES = ("routes.sqli",)
MAX_FINDINGS_PER_RUN = 20
AUDIT_METADATA_MAX_CHARS = 4000


class RemediationError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class LeaseLost(Exception):
    """Another worker owns the run now (or it was finalised); stop working on it."""


class AttemptLimitReached(Exception):
    pass


# --------------------------------------------------------------------- audit
def audit(db: Session, run: Remediation, event_type: str, *, actor_type: str, actor_id: str | None = None,
          entity_type: str | None = None, entity_id: uuid.UUID | None = None, previous_state: str | None = None,
          new_state: str | None = None, details: dict | None = None) -> None:
    """Append an audit event to the caller's transaction. Metadata is
    redacted and size-capped; it must never carry source code or secrets."""
    clean = redact_structure(details or {}, max_length=500)
    if len(json.dumps(clean, default=str)) > AUDIT_METADATA_MAX_CHARS:
        clean = {"truncated": True, "keys": sorted(clean)[:50]}
    db.add(RemediationAuditEvent(
        remediation_id=run.id, event_type=event_type, entity_type=entity_type, entity_id=entity_id,
        actor_type=actor_type, actor_id=actor_id, previous_state=previous_state, new_state=new_state,
        correlation_id=run.correlation_id, details=clean,
    ))


# ------------------------------------------------------------ run creation
def create_run(db: Session, *, user: User, assessment: Assessment, findings: list[SecurityFinding],
               idempotency_key: str | None = None) -> tuple[Remediation, bool]:
    """Create a run for findings of one assessment the caller already owns.
    Returns (run, created). Re-sending the same idempotency key, or asking
    again for a single finding that already has an active run, returns that
    run instead of starting a second one."""
    if not findings:
        raise RemediationError(422, "no_findings", "Select at least one finding.")
    if len(findings) > MAX_FINDINGS_PER_RUN:
        raise RemediationError(422, "too_many_findings", f"At most {MAX_FINDINGS_PER_RUN} findings per run.")
    if len({f.id for f in findings}) != len(findings):
        raise RemediationError(422, "duplicate_findings", "A finding was selected more than once.")
    for f in findings:
        if f.assessment_id != assessment.id:
            raise RemediationError(404, "not_found", "Finding not found.")
        if not f.rule_id.startswith(SUPPORTED_RULE_PREFIXES):
            raise RemediationError(422, "unsupported_finding",
                                   "Automatic remediation is only available for SQL injection findings right now.")
        if not f.snapshot:
            raise RemediationError(422, "no_snapshot", "No code snapshot is available for this finding.")

    if idempotency_key:
        existing = db.scalar(select(Remediation).where(Remediation.project_id == assessment.project_id,
                                                       Remediation.idempotency_key == idempotency_key))
        if existing is not None:
            return existing, False

    ids = [f.id for f in findings]
    # Serialise concurrent requests for the same findings.
    db.execute(select(SecurityFinding.id).where(SecurityFinding.id.in_(ids)).with_for_update())
    active = db.scalars(select(RemediationFinding).where(RemediationFinding.finding_id.in_(ids),
                                                         RemediationFinding.is_active)).all()
    if active:
        if len(findings) == 1:
            return db.get(Remediation, active[0].remediation_id), False
        raise RemediationError(409, "remediation_active",
                               "One of the selected findings already has a remediation in progress.")

    by_file: dict[str, SecurityFinding] = {}
    for f in findings:
        path = f.snapshot["file"]
        if path in by_file:
            raise RemediationError(
                422, "overlapping_findings",
                "Two selected findings are in the same file. Their fixes would overlap, so start them as "
                "separate remediation runs.")
        by_file[path] = f

    settings = get_settings()
    integration = db.scalar(select(ProjectIntegration).where(ProjectIntegration.project_id == assessment.project_id))
    primary = findings[0]
    now = utcnow()
    run = Remediation(
        finding_id=primary.id, project_id=assessment.project_id, assessment_id=assessment.id, requested_by=user.id,
        actor_type="user", status="pending", finding_status="open", stage=Stage.QUEUED, stage_entered_at=now,
        max_attempts=settings.max_rounds, source_kind=integration.kind if integration else None,
        source_ref=(integration.repo_ref or None) if integration else None, idempotency_key=idempotency_key,
        # The exact revision the assessment analysed: every verification and
        # rescan of this run is pinned to it.
        source_commit_sha=(assessment.discovery_summary or {}).get("source_commit"),
    )
    db.add(run)
    db.flush()
    for seq, f in enumerate(findings, start=1):
        path = f.snapshot["file"]
        batch = RemediationPatchBatch(
            remediation_id=run.id, sequence=seq, max_attempts=run.max_attempts,
            change_description=f"{f.title} in {path} (lines {f.snapshot['start_line']}-{f.snapshot['end_line']})",
            depends_on_batch_id=None,
        )
        db.add(batch)
        db.flush()
        db.add(RemediationBatchFile(batch_id=batch.id, file_path=path, remediation_id=run.id))
        db.add(RemediationFinding(
            remediation_id=run.id, finding_id=f.id, is_primary=f.id == primary.id, is_active=True,
            severity_snapshot=f.severity, confidence_snapshot=f.confidence, fingerprint_snapshot=f.fingerprint,
            rule_id_snapshot=f.rule_id, resolution=Resolution.PENDING, patch_batch_id=batch.id,
        ))
    audit(db, run, "remediation_requested", actor_type="user", actor_id=str(user.id), new_state=Stage.QUEUED,
          details={"findings": len(findings), "batches": len(findings), "max_attempts": run.max_attempts})
    outbox.add(db, remediation_id=run.id, job_kind="remediate", dedupe_key=f"remediate:{run.id}:start",
               payload={"finding_id": str(primary.id)})
    try:
        db.commit()
    except IntegrityError:
        # A concurrent request won the race for one of these findings.
        db.rollback()
        if len(findings) == 1:
            rf = db.scalar(select(RemediationFinding).where(RemediationFinding.finding_id == primary.id,
                                                            RemediationFinding.is_active))
            if rf is not None:
                return db.get(Remediation, rf.remediation_id), False
        raise RemediationError(409, "remediation_active",
                               "One of the selected findings already has a remediation in progress.") from None
    return run, True


# ------------------------------------------------------ worker lease / stage
def claim(db: Session, run_id: uuid.UUID, worker_id: str) -> Remediation | None:
    """Take the run's lease. Returns None if another live worker holds it or
    the run is already finished (duplicate delivery)."""
    settings = get_settings()
    terminal = [s.value for s in TERMINAL_STAGES]
    row = db.execute(
        update(Remediation)
        .where(Remediation.id == run_id, Remediation.stage.not_in(terminal),
               (Remediation.lease_owner.is_(None)) | (Remediation.lease_expires_at < func.now()))
        .values(lease_owner=worker_id,
                lease_expires_at=func.now() + timedelta(seconds=settings.remediation_lease_seconds),
                status="running", version=Remediation.version + 1,
                started_at=func.coalesce(Remediation.started_at, func.now()))
        .returning(Remediation.id, Remediation.stage, Remediation.recovery_count)
    ).first()
    if row is None:
        db.commit()
        return None
    run = db.get(Remediation, run_id, populate_existing=True)
    resumed = run.stage != Stage.QUEUED
    if resumed:
        run.recovery_count += 1
    audit(db, run, "worker_resumed" if resumed else "worker_claimed", actor_type="worker", actor_id=worker_id,
          previous_state=run.stage, new_state=run.stage, details={"recovery": run.recovery_count})
    db.commit()
    if resumed and run.recovery_count > settings.remediation_max_recoveries:
        finalize(db, run.id, worker_id=worker_id, infrastructure_error=(
            "The run was interrupted more times than allowed; it was stopped instead of being resumed again."))
        return None
    return run


def _locked_run(db: Session, run_id: uuid.UUID, worker_id: str | None) -> Remediation:
    run = db.get(Remediation, run_id, with_for_update=True, populate_existing=True)
    if run is None:
        raise LeaseLost("the run no longer exists")
    if worker_id is not None and run.lease_owner != worker_id:
        raise LeaseLost("another worker owns this run")
    return run


def transition(db: Session, run_id: uuid.UUID, worker_id: str, new_stage: str, *, resume: bool = False,
               details: dict | None = None, entity_type: str | None = None,
               entity_id: uuid.UUID | None = None) -> Remediation:
    """Move the run to a new workflow stage (validated), renew the lease and
    append the audit event, atomically."""
    run = _locked_run(db, run_id, worker_id)
    if run.stage == new_stage and not resume:
        db.commit()
        return run  # idempotent re-entry (e.g. a resumed worker)
    check_transition(run.stage, new_stage, resume=resume)
    previous = run.stage
    run.stage = new_stage
    run.stage_entered_at = utcnow()
    run.version += 1
    run.lease_expires_at = utcnow() + timedelta(seconds=get_settings().remediation_lease_seconds)
    audit(db, run, "stage_changed", actor_type="worker", actor_id=worker_id, previous_state=previous,
          new_state=new_stage, entity_type=entity_type, entity_id=entity_id, details=details)
    db.commit()
    return run


def cancel_requested(db: Session, run_id: uuid.UUID) -> bool:
    value = db.scalar(select(Remediation.cancel_requested).where(Remediation.id == run_id))
    db.commit()
    return bool(value)


def request_cancel(db: Session, run: Remediation, user: User) -> Remediation:
    run = db.get(Remediation, run.id, with_for_update=True, populate_existing=True)
    if run.stage in TERMINAL_STAGES or run.cancel_requested:
        db.commit()
        return run
    run.cancel_requested = True
    run.cancelled_by = user.id
    run.version += 1
    audit(db, run, "cancel_requested", actor_type="user", actor_id=str(user.id), previous_state=run.stage,
          new_state=run.stage)
    unclaimed = run.lease_owner is None or (run.lease_expires_at is not None and run.lease_expires_at < utcnow())
    db.commit()
    if run.stage == Stage.QUEUED and unclaimed:
        # No worker has it: finish now rather than wait for one.
        finalize(db, run.id, worker_id=None, cancelled=True, actor_type="api", actor_id=str(user.id))
        db.refresh(run)
    return run


# --------------------------------------------------------------- recorders
def record_context(db: Session, run_id: uuid.UUID, worker_id: str, *, batch_id: uuid.UUID, finding_id: uuid.UUID,
                   snapshot: dict, redacted_code: str, placeholders: int, retention_days: int | None = None
                   ) -> RemediationContext:
    run = _locked_run(db, run_id, worker_id)
    residual = unredacted_secret_count(redacted_code)
    artifact = None
    if residual == 0:
        artifact = artifacts.store(db, run.id, "context_snapshot", redacted_code, redaction_status="redacted",
                                   contains_source=True)
    ctx = RemediationContext(
        remediation_id=run.id, patch_batch_id=batch_id, finding_id=finding_id,
        source_commit_sha=run.source_commit_sha, snapshot_artifact_id=artifact.id if artifact else None,
        file_paths=[snapshot["file"]], symbols=[], line_start=snapshot["start_line"], line_end=snapshot["end_line"],
        extraction_method="scan_time_enclosing_function",  # source_analyzer VulnClass.build_snapshot
        context_bytes=len(redacted_code.encode()),
        content_sha256=artifact.sha256 if artifact else _sha256(redacted_code),
        redaction_status="redacted" if residual == 0 else "failed", redaction_engine=REDACTION_ENGINE,
        redaction_ruleset_version=REDACTION_RULESET_VERSION, redaction_verified=residual == 0,
        redaction_verification=("independent re-scan found no secret-like value" if residual == 0
                                else f"independent re-scan still found {residual} secret-like value(s)"),
        redaction_findings_count=placeholders,
        expires_at=utcnow() + timedelta(days=retention_days or get_settings().remediation_artifact_retention_days),
    )
    db.add(ctx)
    db.flush()
    audit(db, run, "context_extracted", actor_type="worker", actor_id=worker_id, entity_type="context",
          entity_id=ctx.id, details={"files": 1, "bytes": ctx.context_bytes})
    audit(db, run, "redaction_completed" if residual == 0 else "redaction_failed", actor_type="worker",
          actor_id=worker_id, entity_type="context", entity_id=ctx.id,
          details={"placeholders": placeholders, "residual": residual, "ruleset": REDACTION_RULESET_VERSION})
    db.commit()
    return ctx


def invocation_started(db: Session, run_id: uuid.UUID, worker_id: str, *, role: str, provider: str, model: str,
                       template_version: str, input_text: str, batch_id: uuid.UUID | None, cache_mode: str,
                       retry_of_id: uuid.UUID | None = None) -> uuid.UUID:
    run = _locked_run(db, run_id, worker_id)
    seq = (db.scalar(select(func.max(AiModelInvocation.sequence))
                     .where(AiModelInvocation.remediation_id == run.id)) or 0) + 1
    input_artifact = None
    if get_settings().remediation_retain_model_io:
        input_artifact = artifacts.store(db, run.id, "model_input", input_text, redaction_status="redacted",
                                         contains_source=True, media_type="application/json")
    inv = AiModelInvocation(
        remediation_id=run.id, patch_batch_id=batch_id, role=role, provider=provider, model=model,
        prompt_template_version=template_version, input_sha256=_sha256(input_text),
        input_artifact_id=input_artifact.id if input_artifact else None, status="started", cache_mode=cache_mode,
        sequence=seq, retry_of_id=retry_of_id, correlation_id=run.correlation_id,
    )
    db.add(inv)
    db.flush()
    audit(db, run, "model_invoked", actor_type="worker", actor_id=worker_id, entity_type="ai_model_invocation",
          entity_id=inv.id, details={"role": role, "provider": provider, "model": model, "sequence": seq})
    db.commit()
    return inv.id


def invocation_blocked(db: Session, run_id: uuid.UUID, worker_id: str, *, role: str, provider: str, model: str,
                       template_version: str, input_sha256: str, batch_id: uuid.UUID | None, reason: str) -> None:
    """The pre-send guard refused a request: recorded, nothing was sent."""
    run = _locked_run(db, run_id, worker_id)
    seq = (db.scalar(select(func.max(AiModelInvocation.sequence))
                     .where(AiModelInvocation.remediation_id == run.id)) or 0) + 1
    inv = AiModelInvocation(
        remediation_id=run.id, patch_batch_id=batch_id, role=role, provider=provider, model=model,
        prompt_template_version=template_version, input_sha256=input_sha256, status="blocked", sequence=seq,
        completed_at=utcnow(), duration_ms=0, error_category="policy", error_detail=reason[:500],
        correlation_id=run.correlation_id,
    )
    db.add(inv)
    db.flush()
    audit(db, run, "model_request_blocked", actor_type="worker", actor_id=worker_id,
          entity_type="ai_model_invocation", entity_id=inv.id, details={"role": role, "reason": reason})
    db.commit()


def invocation_finished(db: Session, invocation_id: uuid.UUID, *, status: str, output_text: str | None = None,
                        usage: dict | None = None, error_category: str | None = None,
                        error_detail: str | None = None) -> None:
    inv = db.get(AiModelInvocation, invocation_id, with_for_update=True)
    inv.status = status
    inv.completed_at = utcnow()
    inv.duration_ms = int((inv.completed_at - inv.started_at).total_seconds() * 1000)
    if output_text is not None:
        inv.output_sha256 = _sha256(output_text)
        if get_settings().remediation_retain_model_io:
            try:
                out = artifacts.store(db, inv.remediation_id, "model_output", output_text,
                                      redaction_status="derived", contains_source=True)
                inv.output_artifact_id = out.id
            except artifacts.ArtifactRejected as exc:
                inv.error_detail = f"output not retained: {exc}"[:500]
    usage = usage or {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if isinstance(usage.get(key), int):
            setattr(inv, key, usage[key])
    if isinstance(usage.get("model_version"), str):
        inv.model_version = usage["model_version"][:100]
    if error_category:
        inv.error_category = error_category[:32]
    if error_detail:
        inv.error_detail = redact_text(error_detail, max_length=500)
    db.commit()


def mark_invocation(db: Session, invocation_id: uuid.UUID | None, status: str, detail: str) -> None:
    if invocation_id is None:
        return
    inv = db.get(AiModelInvocation, invocation_id, with_for_update=True)
    if inv is not None and inv.status == "succeeded":
        inv.status = status
        inv.error_category = "invalid_output"
        inv.error_detail = redact_text(detail, max_length=500)
    db.commit()


def add_plan(db: Session, run_id: uuid.UUID, worker_id: str, *, batch_id: uuid.UUID, strategy: str,
             files: list[str], invocation_id: uuid.UUID | None, structured: dict | None = None) -> RemediationPlan:
    """`structured` holds the validated optional fields Model A actually
    returned (root_cause, expected_behaviour, ...); absent ones stay NULL."""
    run = _locked_run(db, run_id, worker_id)
    version = (db.scalar(select(func.max(RemediationPlan.version))
                         .where(RemediationPlan.remediation_id == run.id)) or 0) + 1
    structured = {k: v for k, v in (structured or {}).items() if v not in (None, [], "")}
    body = json.dumps({"strategy": strategy, **structured}, indent=2) if structured else strategy
    art = artifacts.store(db, run.id, "plan", body, redaction_status="derived", contains_source=False,
                          media_type="application/json" if structured else "text/plain")

    def text_of(key: str) -> str | None:
        value = structured.get(key)
        if isinstance(value, list):
            value = "\n".join(f"- {v}" for v in value)
        return redact_text(value, max_length=8000) if value else None

    plan = RemediationPlan(
        remediation_id=run.id, patch_batch_id=batch_id, version=version, strategy=redact_text(strategy, max_length=8000),
        root_cause=text_of("root_cause"), expected_behaviour=text_of("expected_behaviour"),
        side_effects=text_of("regression_risks"),
        patch_scope=("Required context:\n" + text_of("required_context")) if structured.get("required_context") else None,
        files_involved=files, functions_involved=[], test_generation_status="generated", schema_valid=True,
        artifact_id=art.id, invocation_id=invocation_id,
    )
    db.add(plan)
    db.flush()
    audit(db, run, "plan_generated", actor_type="worker", actor_id=worker_id, entity_type="plan", entity_id=plan.id,
          details={"version": version})
    db.commit()
    return plan


def add_suite(db: Session, run_id: uuid.UUID, worker_id: str, *, batch_id: uuid.UUID, plan_id: uuid.UUID | None,
              testbench_path: str, testbench: str, suite_type: str = "ai_generated",
              generation_method: str = "llm_a", coverage: dict | None = None) -> RemediationTestSuite:
    run = _locked_run(db, run_id, worker_id)
    version = (db.scalar(select(func.max(RemediationTestSuite.version))
                         .where(RemediationTestSuite.remediation_id == run.id)) or 0) + 1
    art = artifacts.store(db, run.id, "testbench", testbench, redaction_status="derived", contains_source=True)
    suite = RemediationTestSuite(
        remediation_id=run.id, patch_batch_id=batch_id, plan_id=plan_id, version=version, suite_type=suite_type,
        generation_method=generation_method, artifact_id=art.id,
        coverage={"testbench_path": testbench_path, "provided_to_patch_model": False, **(coverage or {})},
    )
    db.add(suite)
    db.flush()
    audit(db, run, "testbench_generated", actor_type="worker", actor_id=worker_id, entity_type="test_suite",
          entity_id=suite.id, details={"version": version})
    db.commit()
    return suite


@dataclass
class TestOutcome:
    name: str
    category: str
    passed: bool
    message: str = ""
    outcome: str | None = None   # passed | failed | error (an error is never a pass)


@dataclass
class Execution:
    """One sandbox execution as reported by the runner."""

    status: str  # passed | failed | error | timeout | killed
    tests: list[TestOutcome]
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    error_reason: str | None = None
    # Structured evidence from a real Build & Run sandbox (see
    # routes_core.verification.BuildVerification), or None.
    evidence: dict | None = None


def _outcome(t: TestOutcome) -> str:
    return t.outcome if t.outcome in ("passed", "failed", "error") else ("passed" if t.passed else "failed")


def record_verification(db: Session, run_id: uuid.UUID, worker_id: str, *, purpose: str, revision_label: str,
                        execution: Execution, runner_kind: str, evidence_grade: str, idempotency_key: str,
                        batch_id: uuid.UUID | None = None, attempt_id: uuid.UUID | None = None,
                        suite_id: uuid.UUID | None = None, sandbox_id: str | None = None,
                        expect_exploits_to_fail: bool = False) -> RemediationVerificationRun:
    """Persist a sandbox execution and every test outcome in it. Idempotent
    by key: a replayed delivery returns the existing record."""
    run = _locked_run(db, run_id, worker_id)
    existing = db.scalar(select(RemediationVerificationRun)
                         .where(RemediationVerificationRun.idempotency_key == idempotency_key))
    if existing is not None:
        db.commit()
        return existing
    overall = execution.status if execution.status in ("passed", "failed", "error", "timeout", "killed") else "error"
    build_failed = (execution.evidence or {}).get("verification") == "BUILD_FAILED"
    if overall in ("passed", "failed") and not execution.tests and purpose in ("baseline", "gate_known_bad",
                                                                                 "candidate"):
        # A test run that produced no test result proves nothing, unless the
        # sandbox showed the application itself did not build or start.
        overall = "failed" if build_failed and overall == "failed" else "error"
    failure = None
    if overall in ("error", "killed"):
        failure = FailureCategory.INFRASTRUCTURE
    elif overall == "timeout":
        failure = FailureCategory.TIMEOUT
    elif overall == "failed" and purpose == "candidate":
        failure = FailureCategory.APPLICATION
    log_art = None
    log_text = "\n".join(p for p in (execution.stdout, execution.stderr) if p)
    if log_text:
        log_art = artifacts.store(db, run.id, "sandbox_log", redact_text(log_text, max_length=200_000),
                                  redaction_status="redacted", contains_source=False)

    def status_of(category_set: set[str]) -> str:
        ts = [t for t in execution.tests if t.category in category_set]
        if not ts:
            return "not_run"
        return "passed" if all(t.passed for t in ts) else "failed"

    ev = execution.evidence or {}
    usage = {"duration_ms": execution.duration_ms} if execution.duration_ms else {}
    for key in ("duration_seconds", "cleanup", "commit", "patch_applied", "isolation_violations", "verification",
                "failed_stage", "status", "findings"):
        if ev.get(key) not in (None, [], {}):
            usage[key] = ev[key]
    vr = RemediationVerificationRun(
        remediation_id=run.id, patch_batch_id=batch_id, attempt_id=attempt_id, suite_id=suite_id, purpose=purpose,
        revision_label=revision_label[:200], sandbox_id=(ev.get("run_id") or sandbox_id),
        sandbox_runner=runner_kind, sandbox_profile=runner_kind[:64], evidence_grade=evidence_grade,
        build_status=str(ev.get("build") or "not_applicable")[:16],
        startup_status=str(ev.get("startup") or "not_applicable")[:16],
        database_status=str(ev.get("database") or "not_applicable")[:16],
        functional_status=status_of({"benign", "functional", "regression", "edge_case"}),
        security_status=status_of({"exploit", "security"}), overall_status=overall,
        failure_category=failure, error_reason=redact_text(execution.error_reason, max_length=500) or None,
        log_artifact_id=log_art.id if log_art else None, idempotency_key=idempotency_key,
        ended_at=utcnow(), duration_ms=execution.duration_ms or None,
        resource_usage=usage,
    )
    db.add(vr)
    db.flush()
    cases: dict[str, RemediationTestCase] = {}
    if suite_id is not None:
        cases = {c.name: c for c in db.scalars(select(RemediationTestCase)
                                               .where(RemediationTestCase.suite_id == suite_id)).all()}
    seen: set[str] = set()
    for t in execution.tests:
        name = (t.name or "unnamed test")[:300]
        if name in seen:
            continue
        seen.add(name)
        category = t.category if t.category in ("exploit", "benign") else "functional"
        case = cases.get(name)
        if case is None and suite_id is not None:
            case = RemediationTestCase(
                suite_id=suite_id, name=name, category=category,
                expected_behaviour=("blocked on fixed code; fails on the original" if category == "exploit"
                                    else "passes on original and fixed code"),
                visibility="hidden",
            )
            db.add(case)
            db.flush()
            cases[name] = case
        expected = "fail" if (expect_exploits_to_fail and category == "exploit") else "pass"
        outcome = _outcome(t)
        actual = {"passed": "pass", "failed": "fail"}.get(outcome, "error")
        db.add(RemediationTestResult(
            verification_run_id=vr.id, test_case_id=case.id if case else None, test_name=name, category=category,
            outcome=outcome, expected_result=expected, actual_result=actual,
            matches_expectation=expected == actual, error_category="test_error" if outcome == "error" else None,
            error_detail=redact_text(t.message, max_length=500) or None,
        ))
    cleanup = ev.get("cleanup") or {}
    if cleanup and cleanup.get("status") != "complete":
        audit(db, run, "sandbox_cleanup_incomplete", actor_type="worker", actor_id=worker_id,
              entity_type="verification_run", entity_id=vr.id, details={"errors": cleanup.get("errors", [])[:5]})
    audit(db, run, "verification_recorded", actor_type="worker", actor_id=worker_id,
          entity_type="verification_run", entity_id=vr.id,
          details={"purpose": purpose, "status": overall, "evidence": evidence_grade, "tests": len(seen)})
    db.commit()
    return vr


def finish_suite_validation(db: Session, run_id: uuid.UUID, worker_id: str, suite_id: uuid.UUID, *,
                            passed: bool, failed_check: str | None, baseline: Execution | None,
                            dropped: list[str] | None = None) -> None:
    run = _locked_run(db, run_id, worker_id)
    suite = db.get(RemediationTestSuite, suite_id, with_for_update=True)
    if baseline is None or baseline.status in ("error", "timeout", "killed") or not baseline.tests:
        suite.baseline_status = "error"
    else:
        reproduced = any(t.category == "exploit" and _outcome(t) == "failed" for t in baseline.tests)
        suite.baseline_status = "reproduced" if reproduced else "not_reproduced"
    suite.validation_status = "validated" if passed else ("error" if suite.baseline_status == "error" else "rejected")
    suite.validation_detail = redact_text(failed_check, max_length=1000) if failed_check else None
    baseline_by_name = {t.name: t for t in (baseline.tests if baseline else [])}
    dropped_names = set(dropped or [])
    for case in db.scalars(select(RemediationTestCase).where(RemediationTestCase.suite_id == suite_id)).all():
        b = baseline_by_name.get(case.name)
        if b is not None:
            case.baseline_outcome = "passed" if b.passed else "failed"
        case.validation_status = "validated" if passed and case.name not in dropped_names else "rejected"
    if suite.plan_id is not None:
        plan = db.get(RemediationPlan, suite.plan_id)
        plan.test_generation_status = "validated" if passed else "rejected"
    audit(db, run, "testbench_validated" if passed else "testbench_rejected", actor_type="worker",
          actor_id=worker_id, entity_type="test_suite", entity_id=suite.id,
          details={"baseline": suite.baseline_status, "failed_check": failed_check,
                   "dropped_tests": len(dropped or [])})
    if suite.baseline_status == "reproduced":
        audit(db, run, "original_vulnerability_reproduced", actor_type="worker", actor_id=worker_id,
              entity_type="test_suite", entity_id=suite.id)
    db.commit()


def start_attempt(db: Session, run_id: uuid.UUID, worker_id: str, batch_id: uuid.UUID, *,
                  plan: RemediationPlan | None) -> RemediationPatchAttempt:
    """Allocate the next attempt number of a batch under a row lock. Raises
    AttemptLimitReached when the batch has used its allowed attempts."""
    run = _locked_run(db, run_id, worker_id)
    batch = db.get(RemediationPatchBatch, batch_id, with_for_update=True, populate_existing=True)
    if batch.attempts_used >= batch.max_attempts:
        db.commit()
        raise AttemptLimitReached(f"batch {batch.sequence} already used {batch.attempts_used} attempt(s)")
    attempt_no = batch.attempts_used + 1
    attempt = RemediationPatchAttempt(
        remediation_id=run.id, batch_id=batch.id, attempt_no=attempt_no, max_attempts=batch.max_attempts,
        plan_id=plan.id if plan else None, plan_version=plan.version if plan else None,
        source_commit_sha=run.source_commit_sha, idempotency_key=f"{batch.id}:{attempt_no}",
    )
    db.add(attempt)
    batch.attempts_used = attempt_no
    batch.status = "in_progress"
    run.attempts_total += 1
    db.flush()
    audit(db, run, "patch_attempt_started", actor_type="worker", actor_id=worker_id, entity_type="patch_attempt",
          entity_id=attempt.id, details={"batch": batch.sequence, "attempt": attempt_no,
                                         "of": batch.max_attempts})
    db.commit()
    return attempt


def finish_generation(db: Session, run_id: uuid.UUID, worker_id: str, attempt_id: uuid.UUID, *,
                      snapshot: dict, candidate_code: str | None, candidate_hash: str | None,
                      fix_source: str | None, fix_note: str | None, invocation_id: uuid.UUID | None,
                      errors: list[str]) -> RemediationPatchAttempt:
    """Record what the generator produced and validate it as a patch."""
    run = _locked_run(db, run_id, worker_id)
    attempt = db.get(RemediationPatchAttempt, attempt_id, with_for_update=True)
    attempt.fix_source = fix_source
    attempt.fix_note = fix_note
    attempt.invocation_id = invocation_id
    attempt.candidate_hash = candidate_hash
    allowed = {f.file_path for f in db.scalars(select(RemediationBatchFile)
                                                .where(RemediationBatchFile.batch_id == attempt.batch_id)).all()}
    if candidate_code is None:
        attempt.generation_status = "invalid_output"
        attempt.validation_status = "invalid"
        attempt.failure_reason = redact_text("; ".join(errors) or "no candidate was produced", max_length=2000)
        event = "patch_rejected"
    else:
        cand = artifacts.store(db, run.id, "candidate", candidate_code, redaction_status="derived",
                               contains_source=True)
        attempt.candidate_artifact_id = cand.id
        attempt.generation_status = "generated"
        # The snapshot is a region inside the file, so both sides end in a
        # newline: never claim "no newline at end of file" mid-file.
        diff = unified_diff(snapshot["file"], snapshot["start_line"], snapshot["code"].rstrip("\n") + "\n",
                            candidate_code.rstrip("\n") + "\n")
        problems: list[str] = []
        files: list[str] = []
        try:
            files = validate_patch(diff) if diff else []
            if not files:
                problems.append("the candidate does not change the code")
        except PatchRejected as exc:
            problems.append(str(exc))
        outside = sorted(set(files) - allowed)
        if outside:
            problems.append(f"the patch changes files outside the batch scope: {outside}")
        if diff:
            patch = artifacts.store(db, run.id, "patch", diff, redaction_status="derived", contains_source=True,
                                    media_type="text/x-diff")
            attempt.patch_artifact_id = patch.id
            attempt.patch_sha256 = patch.sha256
        attempt.files_changed = len(files)
        attempt.patch_format = "unified_diff"
        if problems or errors:
            attempt.validation_status = "invalid"
            attempt.failure_reason = redact_text("; ".join(problems + errors), max_length=2000)
            event = "patch_rejected"
        else:
            attempt.validation_status = "valid"
            event = "patch_generated"
    audit(db, run, event, actor_type="worker", actor_id=worker_id, entity_type="patch_attempt", entity_id=attempt.id,
          details={"attempt": attempt.attempt_no, "source": fix_source, "valid": attempt.validation_status == "valid"})
    db.commit()
    return attempt


def finish_attempt(db: Session, run_id: uuid.UUID, worker_id: str, attempt_id: uuid.UUID, *, verification_status: str,
                   failure_reason: str | None, test_results: dict, rescan_diff: dict) -> None:
    """Close an attempt and write the matching legacy iteration row."""
    run = _locked_run(db, run_id, worker_id)
    attempt = db.get(RemediationPatchAttempt, attempt_id, with_for_update=True)
    attempt.verification_status = verification_status
    if failure_reason:
        attempt.failure_reason = redact_text(failure_reason, max_length=2000)
    attempt.completed_at = utcnow()
    batch = db.get(RemediationPatchBatch, attempt.batch_id)
    iteration_no = (db.scalar(select(func.max(RemediationIteration.iteration_no))
                              .where(RemediationIteration.remediation_id == run.id)) or 0) + 1
    legacy = RemediationIteration(
        remediation_id=run.id, iteration_no=iteration_no, round_no=attempt.attempt_no, batch_id=str(batch.id),
        candidate_hash=attempt.candidate_hash, candidate_code=None, fix_source=attempt.fix_source,
        fix_note=attempt.fix_note, test_results=redact_structure(test_results, max_length=500),
        rescan_diff=rescan_diff, failure_output=attempt.failure_reason,
    )
    db.add(legacy)
    db.flush()
    attempt.legacy_iteration_id = legacy.id
    event = "patch_accepted" if verification_status == "passed" else "patch_attempt_failed"
    audit(db, run, event, actor_type="worker", actor_id=worker_id, entity_type="patch_attempt", entity_id=attempt.id,
          details={"attempt": attempt.attempt_no, "verification": verification_status})
    db.commit()


def abandon_open_attempts(db: Session, run_id: uuid.UUID, worker_id: str) -> int:
    """After a crash: attempts that never finished count as used and failed,
    so a crash loop can never exceed the attempt limit."""
    run = _locked_run(db, run_id, worker_id)
    open_attempts = db.scalars(select(RemediationPatchAttempt).where(
        RemediationPatchAttempt.remediation_id == run.id, RemediationPatchAttempt.completed_at.is_(None))).all()
    for a in open_attempts:
        if a.generation_status == "pending":
            a.generation_status = "abandoned"
        if a.verification_status == "pending":
            a.verification_status = "error"
        a.failure_reason = "The worker was interrupted during this attempt."
        a.completed_at = utcnow()
        audit(db, run, "patch_attempt_abandoned", actor_type="worker", actor_id=worker_id,
              entity_type="patch_attempt", entity_id=a.id, details={"attempt": a.attempt_no})
    db.commit()
    return len(open_attempts)


def record_reanalysis(db: Session, run_id: uuid.UUID, worker_id: str, *, attempt_id: uuid.UUID | None,
                      verification_run_id: uuid.UUID | None, candidate_revision: str,
                      rescan_fingerprints: list[str] | None, evidence_grade: str, scope: str = "batch",
                      engine_versions: dict | None = None,
                      rescan_findings: list[dict] | None = None) -> RemediationReanalysisRun:
    """Compare the original assessment's findings with an independent rescan
    of the patched code: resolved, remaining and newly introduced findings."""
    run = _locked_run(db, run_id, worker_id)
    baseline = dict(db.execute(select(SecurityFinding.fingerprint, SecurityFinding.id)
                               .where(SecurityFinding.assessment_id == run.assessment_id)).all())
    targeted = set(db.scalars(select(RemediationFinding.fingerprint_snapshot)
                              .where(RemediationFinding.remediation_id == run.id)).all())
    re = RemediationReanalysisRun(
        remediation_id=run.id, assessment_id=run.assessment_id, attempt_id=attempt_id,
        verification_run_id=verification_run_id, scope=scope, candidate_revision=candidate_revision[:200],
        engine_versions=engine_versions or {}, evidence_grade=evidence_grade,
        status="completed" if rescan_fingerprints is not None else "error", findings_before=len(baseline),
        findings_after=len(rescan_fingerprints) if rescan_fingerprints is not None else None,
        completed_at=utcnow(),
    )
    db.add(re)
    db.flush()
    if rescan_fingerprints is not None and rescan_findings is not None:
        identities = {f.fingerprint: finding_identity({"rule_id": f.rule_id, "file": f.file, "endpoint": f.endpoint,
                                                       "method": f.method})
                      for f in db.scalars(select(SecurityFinding)
                                          .where(SecurityFinding.assessment_id == run.assessment_id)).all()}
        m = match_reanalysis(identities, targeted, [(f["fingerprint"], finding_identity(f)) for f in rescan_findings])
        still = set(m["targeted_still_present"])
        for fp in m["resolved"]:
            db.add(RemediationReanalysisFinding(reanalysis_id=re.id, fingerprint=fp, original_finding_id=baseline[fp],
                                                change="resolved", targeted=fp in targeted))
        for fp in m["remaining"]:
            db.add(RemediationReanalysisFinding(reanalysis_id=re.id, fingerprint=fp, original_finding_id=baseline[fp],
                                                change="remaining", targeted=fp in targeted or fp in still))
        for fp in m["new"]:
            db.add(RemediationReanalysisFinding(reanalysis_id=re.id, fingerprint=fp[:64], change="new"))
        re.new_count, re.resolved_count, re.remaining_count = len(m["new"]), len(m["resolved"]), len(m["remaining"])
        re.engine_versions = {**re.engine_versions, "matching": "fingerprint+identity",
                              "carried_over": len(m["carried"])}
    elif rescan_fingerprints is not None:
        after = set(rescan_fingerprints)
        for fp, fid in baseline.items():
            change = "remaining" if fp in after else "resolved"
            db.add(RemediationReanalysisFinding(reanalysis_id=re.id, fingerprint=fp, original_finding_id=fid,
                                                change=change, targeted=fp in targeted))
        new = sorted(after - set(baseline))
        for fp in new:
            db.add(RemediationReanalysisFinding(reanalysis_id=re.id, fingerprint=fp[:64], change="new"))
        re.new_count = len(new)
        re.resolved_count = sum(1 for fp in baseline if fp not in after)
        re.remaining_count = sum(1 for fp in baseline if fp in after)
    audit(db, run, "post_remediation_analysis_completed", actor_type="worker", actor_id=worker_id,
          entity_type="reanalysis", entity_id=re.id,
          details={"scope": scope, "status": re.status, "new": re.new_count, "resolved": re.resolved_count})
    db.commit()
    return re


def finish_batch(db: Session, run_id: uuid.UUID, worker_id: str, batch_id: uuid.UUID, status: str) -> None:
    run = _locked_run(db, run_id, worker_id)
    batch = db.get(RemediationPatchBatch, batch_id, with_for_update=True)
    batch.status = status
    batch.completed_at = utcnow()
    audit(db, run, "patch_batch_finished", actor_type="worker", actor_id=worker_id, entity_type="patch_batch",
          entity_id=batch.id, details={"batch": batch.sequence, "status": status})
    db.commit()


def human_review_requested(db: Session, run_id: uuid.UUID, worker_id: str, reason: str) -> None:
    run = _locked_run(db, run_id, worker_id)
    audit(db, run, "human_review_requested", actor_type="worker", actor_id=worker_id, details={"reason": reason})
    db.commit()


# ---------------------------------------------------------------- evidence
def finding_evidence(db: Session, rf: RemediationFinding, hint: dict | None = None) -> FindingEvidence:
    """Build a finding's evidence from persisted rows only. Hints from the
    worker (oscillation, unsupported setup, infrastructure error) can only
    explain a non-fix; they never satisfy a gate."""
    hint = hint or {}
    ev = FindingEvidence(oscillation=bool(hint.get("oscillation")),
                         unsupported_reason=hint.get("unsupported_reason"),
                         human_review_reason=hint.get("human_review_reason"),
                         infrastructure_error=hint.get("infrastructure_error"))
    if rf.patch_batch_id is None:
        return ev
    batch = db.get(RemediationPatchBatch, rf.patch_batch_id)
    if batch.status == "human_review" and not (ev.human_review_reason or ev.oscillation):
        # Recorded by an earlier worker execution of this run (see audit).
        ev.human_review_reason = "This batch was sent to human review; see the audit trail for why."
    suites = db.scalars(select(RemediationTestSuite).where(RemediationTestSuite.patch_batch_id == batch.id)).all()
    validated = [s for s in suites if s.validation_status == "validated"]
    ev.testbench_validated = bool(validated)
    ev.baseline_reproduced = any(s.baseline_status == "reproduced" for s in validated)
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.batch_id == batch.id)
                          .order_by(RemediationPatchAttempt.attempt_no)).all()
    ev.attempts_exhausted = batch.attempts_used >= batch.max_attempts
    accepted = next((a for a in reversed(attempts) if a.verification_status == "passed"), None)
    if accepted is None:
        return ev
    runs = db.scalars(select(RemediationVerificationRun)
                      .where(RemediationVerificationRun.attempt_id == accepted.id)).all()
    candidate_runs = [r for r in runs if r.purpose == "candidate"]
    ev.verification_passed = bool(candidate_runs) and all(r.overall_status == "passed" for r in candidate_runs)
    reanalyses = db.scalars(select(RemediationReanalysisRun).where(RemediationReanalysisRun.attempt_id == accepted.id)
                            .order_by(RemediationReanalysisRun.started_at)).all()
    combined = db.scalars(select(RemediationReanalysisRun).where(
        RemediationReanalysisRun.remediation_id == rf.remediation_id, RemediationReanalysisRun.scope == "combined")
        .order_by(RemediationReanalysisRun.started_at.desc())).first()
    checks = [r for r in reanalyses if r.status == "completed"] + ([combined] if combined is not None else [])
    grades = {r.evidence_grade for r in runs} | {r.evidence_grade for r in checks}
    if checks and all(r.status == "completed" for r in checks):
        ev.reanalysis_ran = True
        gone = True
        for r in checks:
            row = db.scalar(select(RemediationReanalysisFinding).where(
                RemediationReanalysisFinding.reanalysis_id == r.id,
                RemediationReanalysisFinding.fingerprint == rf.fingerprint_snapshot))
            gone = gone and (row is None or row.change == "resolved")
        ev.reanalysis_fingerprint_gone = gone
        ev.reanalysis_new_findings = max(r.new_count for r in checks)
    ev.evidence_grade = EvidenceGrade.SANDBOX if grades == {EvidenceGrade.SANDBOX} else EvidenceGrade.SIMULATED
    return ev


def finalize(db: Session, run_id: uuid.UUID, *, worker_id: str | None, hints: dict[str, dict] | None = None,
             cancelled: bool = False, infrastructure_error: str | None = None, actor_type: str = "worker",
             actor_id: str | None = None) -> Remediation:
    """Decide every finding's resolution and the run's verdict from the
    recorded evidence, and close the run. Idempotent: a finished run is
    returned unchanged."""
    run = db.get(Remediation, run_id, with_for_update=True, populate_existing=True)
    if run.stage in TERMINAL_STAGES:
        db.commit()
        return run
    if worker_id is not None and run.lease_owner != worker_id:
        raise LeaseLost("another worker owns this run")
    hints = hints or {}
    rfs = db.scalars(select(RemediationFinding).where(RemediationFinding.remediation_id == run.id)).all()
    resolutions = []
    now = utcnow()
    for rf in rfs:
        hint = dict(hints.get(str(rf.finding_id), {}))
        if infrastructure_error and not hint.get("infrastructure_error"):
            hint["infrastructure_error"] = infrastructure_error
        ev = finding_evidence(db, rf, hint)
        ev.cancelled = cancelled and rf.resolution in (Resolution.PENDING, Resolution.IN_PROGRESS)
        decision = decide_finding(ev)
        rf.resolution = decision.resolution
        rf.resolution_reason = decision.reason
        rf.gates = decision.gates
        rf.verification_outcome = ("passed" if decision.gates.get("verification_passed")
                                   else "not_verified")
        if decision.resolution is not Resolution.VERIFIED_FIXED:
            rf.residual_risk = ("The original finding should still be treated as present: "
                                + decision.reason)
        rf.is_active = False
        rf.completed_at = now
        resolutions.append(decision.resolution)
        if rf.patch_batch_id is not None:
            batch = db.get(RemediationPatchBatch, rf.patch_batch_id)
            # The final batch status follows the evidence-based decision; the
            # worker's interim status is only a resume marker.
            batch.status = {"verified_fixed": "verified", "cancelled": "cancelled", "failed": "failed",
                                "human_review": "human_review", "not_fixed": "exhausted"}.get(
                                    decision.resolution, "inconclusive")
            batch.completed_at = batch.completed_at or now
        if rf.is_primary:
            run.finding_status = LEGACY_FINDING_STATUS[decision.resolution]
    verdict, reason = decide_run(resolutions, cancelled=cancelled, infrastructure_error=infrastructure_error)
    previous = run.stage
    new_stage = VERDICT_STAGE[verdict]
    check_transition(previous, new_stage)
    run.stage = new_stage
    run.stage_entered_at = now
    run.verdict = verdict
    run.verdict_reason = reason
    run.status = LEGACY_STATUS[verdict]
    if verdict is Verdict.FAILED:
        run.failure_category = FailureCategory.INFRASTRUCTURE if infrastructure_error else FailureCategory.APPLICATION
        run.error = infrastructure_error or reason
    elif verdict is not Verdict.VERIFIED_FIXED:
        run.error = next((rf.resolution_reason for rf in rfs if rf.resolution_reason), reason)
    else:
        run.error = None
    if verdict is Verdict.CANCELLED:
        run.cancelled_at = now
    run.finished_at = now
    run.version += 1
    run.lease_owner = None
    run.lease_expires_at = None
    if verdict is Verdict.HUMAN_REVIEW or verdict is Verdict.PARTIALLY_REMEDIATED:
        audit(db, run, "human_review_requested", actor_type=actor_type, actor_id=actor_id or worker_id,
              details={"reason": reason})
    audit(db, run, "remediation_completed", actor_type=actor_type, actor_id=actor_id or worker_id,
          previous_state=previous, new_state=new_stage,
          details={"verdict": verdict.value, "resolutions": [r.value for r in resolutions]})
    db.commit()
    return run


# ----------------------------------------------------------------- recovery
def recover_interrupted(db: Session) -> int:
    """At startup: re-dispatch runs whose worker disappeared (lease expired or
    never claimed). The worker resumes them; claim() stops a run that has
    been interrupted too often."""
    rows = db.scalars(select(Remediation).where(
        Remediation.stage.not_in([s.value for s in TERMINAL_STAGES]),
        (Remediation.lease_owner.is_(None)) | (Remediation.lease_expires_at < func.now()))).all()
    for run in rows:
        outbox.add(db, remediation_id=run.id, job_kind="remediate",
                   dedupe_key=f"remediate:{run.id}:recover:{run.version}",
                   payload={"finding_id": str(run.finding_id)})
        audit(db, run, "recovery_dispatched", actor_type="system", previous_state=run.stage, new_state=run.stage)
    db.commit()
    return len(rows)


# ------------------------------------------------------------------- reads
def report(db: Session, run: Remediation) -> dict:
    """The remediation report, assembled only from persisted records."""
    rfs = db.execute(select(RemediationFinding, SecurityFinding)
                     .join(SecurityFinding, SecurityFinding.id == RemediationFinding.finding_id)
                     .where(RemediationFinding.remediation_id == run.id)).all()
    batches = db.scalars(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run.id)
                         .order_by(RemediationPatchBatch.sequence)).all()
    attempts = db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == run.id)
                          .order_by(RemediationPatchAttempt.created_at)).all()
    invocations = db.scalars(select(AiModelInvocation).where(AiModelInvocation.remediation_id == run.id)
                             .order_by(AiModelInvocation.sequence)).all()
    verifications = db.scalars(select(RemediationVerificationRun)
                               .where(RemediationVerificationRun.remediation_id == run.id)
                               .order_by(RemediationVerificationRun.started_at)).all()
    reanalyses = db.scalars(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == run.id)
                            .order_by(RemediationReanalysisRun.started_at)).all()
    contexts = db.scalars(select(RemediationContext).where(RemediationContext.remediation_id == run.id)).all()
    return {
        "remediation_id": str(run.id), "project_id": str(run.project_id), "assessment_id": str(run.assessment_id),
        "requested_by": str(run.requested_by) if run.requested_by else None, "correlation_id": run.correlation_id,
        "source": {"kind": run.source_kind, "ref": run.source_ref, "commit_sha": run.source_commit_sha},
        "verdict": run.verdict, "verdict_reason": run.verdict_reason, "stage": run.stage, "status": run.status,
        "failure_category": run.failure_category, "attempts_total": run.attempts_total,
        "max_attempts_per_batch": run.max_attempts,
        "started_at": _iso(run.started_at), "finished_at": _iso(run.finished_at),
        "findings": [{
            "finding_id": str(f.id), "title": f.title, "rule_id": rf.rule_id_snapshot,
            "severity": rf.severity_snapshot, "confidence": rf.confidence_snapshot, "file": f.file, "line": f.line,
            "resolution": rf.resolution, "reason": rf.resolution_reason, "gates": rf.gates,
            "residual_risk": rf.residual_risk,
        } for rf, f in rfs],
        "context": [{"files": c.file_paths, "bytes": c.context_bytes, "redaction_verified": c.redaction_verified,
                     "redaction_ruleset": c.redaction_ruleset_version, "placeholders": c.redaction_findings_count}
                    for c in contexts],
        "models": [{"role": i.role, "provider": i.provider, "model": i.model, "status": i.status,
                    "duration_ms": i.duration_ms, "total_tokens": i.total_tokens} for i in invocations],
        "batches": [{"sequence": b.sequence, "status": b.status, "attempts_used": b.attempts_used,
                     "max_attempts": b.max_attempts} for b in batches],
        "attempts": [{"attempt_no": a.attempt_no, "fix_source": a.fix_source, "validation": a.validation_status,
                      "verification": a.verification_status, "failure_reason": a.failure_reason,
                      "patch_sha256": a.patch_sha256} for a in attempts],
        "verification_runs": [{"purpose": v.purpose, "revision": v.revision_label, "status": v.overall_status,
                               "evidence_grade": v.evidence_grade, "runner": v.sandbox_runner,
                               "failure_category": v.failure_category} for v in verifications],
        "reanalysis": [{"scope": r.scope, "status": r.status, "evidence_grade": r.evidence_grade,
                        "findings_before": r.findings_before, "findings_after": r.findings_after,
                        "resolved": r.resolved_count, "remaining": r.remaining_count, "new": r.new_count}
                       for r in reanalyses],
    }


def artifact_for_run(db: Session, run: Remediation, artifact_id: uuid.UUID) -> RemediationArtifact | None:
    return db.scalar(select(RemediationArtifact).where(RemediationArtifact.id == artifact_id,
                                                       RemediationArtifact.remediation_id == run.id))


def _sha256(text_value: str) -> str:
    import hashlib

    return hashlib.sha256(text_value.encode("utf-8")).hexdigest()


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def lock_timeout(db: Session, ms: int = 5000) -> None:
    db.execute(text(f"SET LOCAL lock_timeout = {int(ms)}"))
