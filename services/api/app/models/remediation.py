"""Remediation persistence.

``remediations`` is the remediation *run* (one complete execution). It
existed before this schema was extended and keeps its id, its ``finding_id``
(now "the primary finding") and its coarse ``status`` / ``finding_status``
columns, which the existing frontend reads. Everything else hangs off it:

  remediation_findings        the findings a run targets (canonical resolution)
  remediation_artifacts       metadata of files in the private artifact store
  remediation_contexts        source context + redaction record
  ai_model_invocations        every model call (no prompts, no keys)
  remediation_plans           Model A output, versioned
  remediation_test_suites     testbench versions
  remediation_test_cases      individual tests of a suite
  remediation_patch_batches   logical units of change (+ their files)
  remediation_patch_attempts  every patch generation / correction (max 3)
  remediation_verification_runs  every sandbox execution
  remediation_test_results    every test outcome of a verification run
  remediation_reanalysis_runs     independent rescans (+ per-fingerprint diff)
  remediation_audit_events    append-only history (UPDATE refused by trigger)
  remediation_outbox          queue publications that must not be lost

``remediation_iterations`` is the legacy per-round table. It is still written
(one row per patch attempt) so older clients keep working, but its
``candidate_code`` column is no longer filled: candidate source lives in the
artifact store.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin, utcnow


def _fk(target: str, ondelete: str = "CASCADE", nullable: bool = False, index: bool = True):
    return mapped_column(UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable, index=index)


def _run_fk():
    return _fk("remediations.id")


def _artifact_fk():
    return _fk("remediation_artifacts.id", ondelete="SET NULL", nullable=True, index=False)


ACTIVE_RUN_STATUS_SQL = "status IN ('pending','running')"


class Remediation(IdMixin, TimestampMixin, Base):
    __tablename__ = "remediations"

    # The primary finding: the one the run was started from. All targeted
    # findings (including this one) are in remediation_findings.
    finding_id: Mapped[uuid.UUID] = _fk("security_findings.id")
    project_id: Mapped[uuid.UUID] = _fk("projects.id")
    assessment_id: Mapped[uuid.UUID] = _fk("assessments.id")
    requested_by: Mapped[uuid.UUID | None] = _fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="user")

    # Coarse legacy status (pending/running/succeeded/needs_human_review/
    # failed/cancelled), derived from stage + verdict by the store.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    finding_status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    stage: Mapped[str] = mapped_column(String(40), nullable=False, default="queued")
    stage_entered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str | None] = mapped_column(String(32))
    verdict_reason: Mapped[str | None] = mapped_column(Text)
    failure_category: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(Text)

    source_kind: Mapped[str | None] = mapped_column(String(32))
    source_ref: Mapped[str | None] = mapped_column(String(255))
    source_commit_sha: Mapped[str | None] = mapped_column(String(64))

    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    attempts_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_by: Mapped[uuid.UUID | None] = _fk("users.id", ondelete="SET NULL", nullable=True, index=False)

    # Concurrency: `version` increases on every state change (optimistic
    # check for clients); the lease names the one worker allowed to advance
    # the run and expires so a crashed worker's run can be resumed.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovery_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, default=lambda: uuid.uuid4().hex)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    iterations = relationship(
        "RemediationIteration", back_populates="remediation", cascade="all, delete-orphan",
        passive_deletes=True, order_by="RemediationIteration.iteration_no",
    )

    __table_args__ = (
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="max_attempts_range"),
        CheckConstraint("attempts_total >= 0", name="attempts_total_nonneg"),
        Index("ix_remediations_project_created", "project_id", "created_at"),
        Index("ix_remediations_assessment_created", "assessment_id", "created_at"),
        Index("ix_remediations_status_created", "status", "created_at"),
        Index("ix_remediations_correlation_id", "correlation_id"),
        Index("uq_remediations_project_idempotency", "project_id", "idempotency_key", unique=True,
              postgresql_where=text("idempotency_key IS NOT NULL")),
    )


class RemediationIteration(IdMixin, TimestampMixin, Base):
    __tablename__ = "remediation_iterations"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    iteration_no: Mapped[int] = mapped_column(Integer, nullable=False)
    round_no: Mapped[int | None] = mapped_column(Integer)
    batch_id: Mapped[str | None] = mapped_column(String(64))
    candidate_hash: Mapped[str | None] = mapped_column(String(64))
    candidate_code: Mapped[str | None] = mapped_column(Text)  # legacy rows only; see module docstring
    fix_source: Mapped[str | None] = mapped_column(String(64))
    fix_note: Mapped[str | None] = mapped_column(Text)
    test_results: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rescan_diff: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    failure_output: Mapped[str | None] = mapped_column(Text)

    remediation = relationship("Remediation", back_populates="iterations")

    __table_args__ = (
        UniqueConstraint("remediation_id", "iteration_no", name="uq_remediation_iterations_remediation_no"),
    )


class RemediationArtifact(IdMixin, Base):
    """Metadata of one immutable file in the private artifact store. The
    content itself is never in the database."""

    __tablename__ = "remediation_artifacts"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False, default="text/plain")
    storage_key: Mapped[str] = mapped_column(String(300), nullable=False)
    # redacted: sanitised before storage; derived: produced from redacted
    # input (model output, patches); none_needed: contains no source code.
    redaction_status: Mapped[str] = mapped_column(String(16), nullable=False)
    contains_source: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("remediation_id", "kind", "sha256", name="uq_remediation_artifacts_run_kind_sha"),
        CheckConstraint("redaction_status IN ('redacted','derived','none_needed')", name="redaction_status"),
        CheckConstraint("size_bytes >= 0", name="size_nonneg"),
        Index("ix_remediation_artifacts_expires", "expires_at", postgresql_where=text("deleted_at IS NULL")),
    )


class RemediationPatchBatch(IdMixin, TimestampMixin, Base):
    __tablename__ = "remediation_patch_batches"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    change_description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    attempts_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    depends_on_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", ondelete="SET NULL",
                                                        nullable=True, index=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    files = relationship("RemediationBatchFile", cascade="all, delete-orphan", passive_deletes=True,
                         order_by="RemediationBatchFile.file_path")

    __table_args__ = (
        UniqueConstraint("remediation_id", "sequence", name="uq_remediation_patch_batches_run_seq"),
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="max_attempts_range"),
        CheckConstraint("attempts_used >= 0 AND attempts_used <= max_attempts", name="attempts_used_range"),
        CheckConstraint("status IN ('pending','in_progress','verified','failed','exhausted','human_review',"
                        "'inconclusive','cancelled')", name="status"),
    )


class RemediationBatchFile(Base):
    """The files a batch may change. Unique per run: two batches of one run
    can never touch the same file, so their patches cannot overwrite each
    other."""

    __tablename__ = "remediation_batch_files"

    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_patch_batches.id", ondelete="CASCADE"), primary_key=True
    )
    file_path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    remediation_id: Mapped[uuid.UUID] = _run_fk()

    __table_args__ = (UniqueConstraint("remediation_id", "file_path", name="uq_remediation_batch_files_run_file"),)


class RemediationFinding(IdMixin, TimestampMixin, Base):
    """A finding targeted by a run. ``resolution`` is the one canonical
    per-run resolution status; ``remediations.finding_status`` is only a
    legacy mirror of the primary finding's resolution, written by the same
    store function."""

    __tablename__ = "remediation_findings"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    finding_id: Mapped[uuid.UUID] = _fk("security_findings.id")
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # True while the run may still change this finding; at most one active
    # run per finding (partial unique index below).
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity_snapshot: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence_snapshot: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint_snapshot: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id_snapshot: Mapped[str] = mapped_column(String(200), nullable=False)
    resolution: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    resolution_reason: Mapped[str | None] = mapped_column(Text)
    verification_outcome: Mapped[str | None] = mapped_column(String(32))
    gates: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", ondelete="SET NULL",
                                                   nullable=True)
    residual_risk: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("remediation_id", "finding_id", name="uq_remediation_findings_run_finding"),
        Index("uq_remediation_findings_one_active", "finding_id", unique=True,
              postgresql_where=text("is_active")),
        CheckConstraint("resolution IN ('pending','in_progress','verified_fixed','not_fixed','human_review',"
                        "'inconclusive','cancelled','failed')", name="resolution"),
    )


class RemediationContext(IdMixin, Base):
    __tablename__ = "remediation_contexts"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", nullable=True)
    finding_id: Mapped[uuid.UUID | None] = _fk("security_findings.id", ondelete="SET NULL", nullable=True,
                                               index=False)
    source_commit_sha: Mapped[str | None] = mapped_column(String(64))
    snapshot_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    file_paths: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    symbols: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    extraction_method: Mapped[str] = mapped_column(String(64), nullable=False)
    context_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(16), nullable=False)  # redacted | failed
    redaction_engine: Mapped[str] = mapped_column(String(100), nullable=False)
    redaction_ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    redaction_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redaction_verification: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    redaction_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AiModelInvocation(IdMixin, Base):
    """One call to an external model. Never stores the prompt, the response
    or any credential: only hashes, artifact references and usage."""

    __tablename__ = "ai_model_invocations"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", ondelete="SET NULL",
                                                   nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(100))
    prompt_template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    input_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    output_sha256: Mapped[str | None] = mapped_column(String(64))
    output_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="started")
    cache_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="live")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    retry_of_id: Mapped[uuid.UUID | None] = _fk("ai_model_invocations.id", ondelete="SET NULL", nullable=True,
                                                index=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(32))
    error_detail: Mapped[str | None] = mapped_column(String(500))
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("remediation_id", "sequence", name="uq_ai_model_invocations_run_seq"),
        CheckConstraint("role IN ('analysis','patch_generation')", name="role"),
        CheckConstraint("status IN ('started','succeeded','failed','invalid_output','blocked')", name="status"),
        Index("ix_ai_model_invocations_provider_model", "provider", "model", "started_at"),
    )


class RemediationPlan(IdMixin, Base):
    __tablename__ = "remediation_plans"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Only what Model A actually returned is stored; fields it does not
    # produce stay NULL rather than being invented.
    root_cause: Mapped[str | None] = mapped_column(Text)
    vulnerability_explanation: Mapped[str | None] = mapped_column(Text)
    strategy: Mapped[str | None] = mapped_column(Text)
    files_involved: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    functions_involved: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    expected_behaviour: Mapped[str | None] = mapped_column(Text)
    side_effects: Mapped[str | None] = mapped_column(Text)
    patch_scope: Mapped[str | None] = mapped_column(Text)
    test_generation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    schema_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    invocation_id: Mapped[uuid.UUID | None] = _fk("ai_model_invocations.id", ondelete="SET NULL", nullable=True,
                                                  index=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)

    __table_args__ = (UniqueConstraint("remediation_id", "version", name="uq_remediation_plans_run_version"),)


class RemediationTestSuite(IdMixin, Base):
    __tablename__ = "remediation_test_suites"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", nullable=True)
    plan_id: Mapped[uuid.UUID | None] = _fk("remediation_plans.id", ondelete="SET NULL", nullable=True,
                                            index=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    suite_type: Mapped[str] = mapped_column(String(32), nullable=False)
    generation_method: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    validation_detail: Mapped[str | None] = mapped_column(Text)
    baseline_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_run")
    coverage: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)

    __table_args__ = (
        UniqueConstraint("remediation_id", "version", name="uq_remediation_test_suites_run_version"),
        CheckConstraint("suite_type IN ('deterministic_security','ai_generated','repository','regression')",
                        name="suite_type"),
        CheckConstraint("validation_status IN ('pending','validated','rejected','error')", name="validation_status"),
        CheckConstraint("baseline_status IN ('not_run','reproduced','not_reproduced','error')",
                        name="baseline_status"),
    )


class RemediationTestCase(IdMixin, Base):
    __tablename__ = "remediation_test_cases"

    suite_id: Mapped[uuid.UUID] = _fk("remediation_test_suites.id")
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_behaviour: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    baseline_outcome: Mapped[str | None] = mapped_column(String(16))
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    # hidden: the patch model never sees this test's implementation.
    visibility: Mapped[str] = mapped_column(String(24), nullable=False, default="hidden")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)

    __table_args__ = (
        UniqueConstraint("suite_id", "name", name="uq_remediation_test_cases_suite_name"),
        CheckConstraint("visibility IN ('hidden','provided_to_model')", name="visibility"),
        CheckConstraint("category IN ('exploit','benign','security','functional','regression','edge_case')",
                        name="category"),
    )


class RemediationPatchAttempt(IdMixin, Base):
    __tablename__ = "remediation_patch_attempts"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    batch_id: Mapped[uuid.UUID] = _fk("remediation_patch_batches.id")
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    invocation_id: Mapped[uuid.UUID | None] = _fk("ai_model_invocations.id", ondelete="SET NULL", nullable=True,
                                                  index=False)
    fix_source: Mapped[str | None] = mapped_column(String(64))
    plan_id: Mapped[uuid.UUID | None] = _fk("remediation_plans.id", ondelete="SET NULL", nullable=True,
                                            index=False)
    plan_version: Mapped[int | None] = mapped_column(Integer)
    source_commit_sha: Mapped[str | None] = mapped_column(String(64))
    patch_format: Mapped[str] = mapped_column(String(32), nullable=False, default="unified_diff")
    patch_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    patch_sha256: Mapped[str | None] = mapped_column(String(64))
    candidate_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    candidate_hash: Mapped[str | None] = mapped_column(String(64))
    files_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    failure_reason: Mapped[str | None] = mapped_column(Text)
    fix_note: Mapped[str | None] = mapped_column(Text)
    legacy_iteration_id: Mapped[uuid.UUID | None] = _fk("remediation_iterations.id", ondelete="SET NULL",
                                                        nullable=True, index=False)
    idempotency_key: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("batch_id", "attempt_no", name="uq_remediation_patch_attempts_batch_no"),
        CheckConstraint("attempt_no >= 1 AND attempt_no <= max_attempts", name="attempt_within_limit"),
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="max_attempts_range"),
        CheckConstraint("generation_status IN ('pending','generated','invalid_output','error','abandoned')",
                        name="generation_status"),
        CheckConstraint("validation_status IN ('pending','valid','invalid','skipped')", name="validation_status"),
        CheckConstraint("verification_status IN ('pending','passed','failed','error','skipped')",
                        name="verification_status"),
    )


class RemediationVerificationRun(IdMixin, Base):
    __tablename__ = "remediation_verification_runs"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    patch_batch_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_batches.id", nullable=True)
    attempt_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_attempts.id", nullable=True)
    suite_id: Mapped[uuid.UUID | None] = _fk("remediation_test_suites.id", ondelete="SET NULL", nullable=True)
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    revision_label: Mapped[str] = mapped_column(String(200), nullable=False)
    sandbox_id: Mapped[str | None] = mapped_column(String(100))
    sandbox_runner: Mapped[str] = mapped_column(String(32), nullable=False)
    sandbox_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_grade: Mapped[str] = mapped_column(String(16), nullable=False)
    build_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_applicable")
    startup_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_applicable")
    database_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_applicable")
    functional_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_run")
    security_status: Mapped[str] = mapped_column(String(16), nullable=False, default="not_run")
    overall_status: Mapped[str] = mapped_column(String(16), nullable=False)
    failure_category: Mapped[str | None] = mapped_column(String(32))
    error_reason: Mapped[str | None] = mapped_column(String(500))
    resource_usage: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    log_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        CheckConstraint("purpose IN ('baseline','gate_known_bad','candidate','rescan','combined_rescan')",
                        name="purpose"),
        CheckConstraint("evidence_grade IN ('sandbox','simulated')", name="evidence_grade"),
        CheckConstraint("overall_status IN ('passed','failed','error','timeout','killed','not_run')",
                        name="overall_status"),
        Index("ix_remediation_verification_runs_run_started", "remediation_id", "started_at"),
    )


class RemediationTestResult(IdMixin, Base):
    __tablename__ = "remediation_test_results"

    verification_run_id: Mapped[uuid.UUID] = _fk("remediation_verification_runs.id")
    test_case_id: Mapped[uuid.UUID | None] = _fk("remediation_test_cases.id", ondelete="SET NULL", nullable=True)
    test_name: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    expected_result: Mapped[str] = mapped_column(String(16), nullable=False)
    actual_result: Mapped[str] = mapped_column(String(16), nullable=False)
    matches_expectation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_category: Mapped[str | None] = mapped_column(String(32))
    error_detail: Mapped[str | None] = mapped_column(String(500))
    evidence_artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("verification_run_id", "test_name", name="uq_remediation_test_results_run_name"),
        CheckConstraint("outcome IN ('passed','failed','error','skipped','inconclusive')", name="outcome"),
    )


class RemediationReanalysisRun(IdMixin, Base):
    __tablename__ = "remediation_reanalysis_runs"

    remediation_id: Mapped[uuid.UUID] = _run_fk()
    assessment_id: Mapped[uuid.UUID] = _fk("assessments.id")
    attempt_id: Mapped[uuid.UUID | None] = _fk("remediation_patch_attempts.id", nullable=True)
    verification_run_id: Mapped[uuid.UUID | None] = _fk("remediation_verification_runs.id", ondelete="SET NULL",
                                                        nullable=True, index=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="batch")  # batch | combined
    candidate_revision: Mapped[str] = mapped_column(String(200), nullable=False)
    engine_versions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    evidence_grade: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    findings_before: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_after: Mapped[int | None] = mapped_column(Integer)
    new_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remaining_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    artifact_id: Mapped[uuid.UUID | None] = _artifact_fk()
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('completed','error','not_run')", name="status"),
        CheckConstraint("evidence_grade IN ('sandbox','simulated')", name="evidence_grade"),
    )


class RemediationReanalysisFinding(IdMixin, Base):
    """Traceability between an original finding and its post-remediation
    counterpart, by content fingerprint."""

    __tablename__ = "remediation_reanalysis_findings"

    reanalysis_id: Mapped[uuid.UUID] = _fk("remediation_reanalysis_runs.id")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    original_finding_id: Mapped[uuid.UUID | None] = _fk("security_findings.id", ondelete="SET NULL",
                                                        nullable=True)
    change: Mapped[str] = mapped_column(String(16), nullable=False)
    targeted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint("reanalysis_id", "fingerprint", name="uq_remediation_reanalysis_findings_run_fp"),
        CheckConstraint("change IN ('resolved','remaining','new')", name="change"),
    )


class RemediationAuditEvent(IdMixin, Base):
    """Append-only. A database trigger refuses UPDATE, and refuses DELETE
    unless the parent run is being deleted (retention / project deletion)."""

    __tablename__ = "remediation_audit_events"

    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), nullable=False, unique=True)
    remediation_id: Mapped[uuid.UUID] = _fk("remediations.id", index=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(48))
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128))
    previous_state: Mapped[str | None] = mapped_column(String(40))
    new_state: Mapped[str | None] = mapped_column(String(40))
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)

    __table_args__ = (
        Index("ix_remediation_audit_events_run_seq", "remediation_id", "seq"),
        Index("ix_remediation_audit_events_correlation", "correlation_id"),
        CheckConstraint("actor_type IN ('user','worker','api','system')", name="actor_type"),
    )


class RemediationOutbox(IdMixin, Base):
    """Queue publications written in the same transaction as the state change
    that needs them; a relay publishes them and retries failures."""

    __tablename__ = "remediation_outbox"

    remediation_id: Mapped[uuid.UUID | None] = _fk("remediations.id", nullable=True)
    topic: Mapped[str] = mapped_column(String(32), nullable=False)
    job_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500))
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now(), default=utcnow)

    __table_args__ = (
        CheckConstraint("status IN ('pending','published','failed')", name="status"),
        Index("ix_remediation_outbox_pending", "available_at", postgresql_where=text("status = 'pending'")),
    )
