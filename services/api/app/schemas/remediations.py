import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RemediationIterationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    round_no: int | None
    candidate_hash: str | None
    # Served from the private artifact store for runs recorded after
    # migration 0008 (the column itself is no longer filled).
    candidate_code: str | None
    test_results: dict
    rescan_diff: dict
    failure_output: str | None
    fix_source: str | None
    fix_note: str | None
    created_at: datetime


class RemediationFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: uuid.UUID
    is_primary: bool
    severity_snapshot: str
    confidence_snapshot: str
    rule_id_snapshot: str
    resolution: str
    resolution_reason: str | None
    verification_outcome: str | None
    gates: dict
    patch_batch_id: uuid.UUID | None
    residual_risk: str | None
    completed_at: datetime | None


class RemediationOut(BaseModel):
    """Backwards compatible: every field the frontend already used is kept
    with the same meaning; the rest is additive."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    finding_status: str
    cancel_requested: bool
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    iterations: list[RemediationIterationOut] = []

    project_id: uuid.UUID
    assessment_id: uuid.UUID
    stage: str
    stage_entered_at: datetime | None
    verdict: str | None
    verdict_reason: str | None
    failure_category: str | None
    source_kind: str | None
    source_ref: str | None
    source_commit_sha: str | None
    attempts_total: int
    max_attempts: int
    version: int
    correlation_id: str
    findings: list[RemediationFindingOut] = []


class RemediationSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    stage: str
    verdict: str | None
    attempts_total: int
    created_at: datetime
    finished_at: datetime | None


class RemediationPage(BaseModel):
    items: list[RemediationSummaryOut]
    total: int
    limit: int
    offset: int


class RemediationCreate(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class _Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PlanOut(_Row):
    id: uuid.UUID
    version: int
    patch_batch_id: uuid.UUID | None
    root_cause: str | None
    vulnerability_explanation: str | None
    strategy: str | None
    files_involved: list
    functions_involved: list
    expected_behaviour: str | None
    side_effects: str | None
    patch_scope: str | None
    test_generation_status: str
    schema_valid: bool
    artifact_id: uuid.UUID | None
    invocation_id: uuid.UUID | None
    created_at: datetime


class TestCaseOut(_Row):
    id: uuid.UUID
    name: str
    category: str
    expected_behaviour: str
    baseline_outcome: str | None
    validation_status: str
    visibility: str
    artifact_id: uuid.UUID | None


class TestSuiteOut(_Row):
    id: uuid.UUID
    version: int
    patch_batch_id: uuid.UUID | None
    plan_id: uuid.UUID | None
    suite_type: str
    generation_method: str
    validation_status: str
    validation_detail: str | None
    baseline_status: str
    coverage: dict
    artifact_id: uuid.UUID | None
    created_at: datetime
    cases: list[TestCaseOut] = []


class PatchBatchOut(_Row):
    id: uuid.UUID
    sequence: int
    change_description: str
    status: str
    max_attempts: int
    attempts_used: int
    files: list[str] = []
    completed_at: datetime | None


class PatchAttemptOut(_Row):
    id: uuid.UUID
    batch_id: uuid.UUID
    attempt_no: int
    max_attempts: int
    fix_source: str | None
    plan_version: int | None
    source_commit_sha: str | None
    patch_format: str
    patch_artifact_id: uuid.UUID | None
    patch_sha256: str | None
    candidate_artifact_id: uuid.UUID | None
    files_changed: int
    generation_status: str
    validation_status: str
    verification_status: str
    failure_reason: str | None
    invocation_id: uuid.UUID | None
    created_at: datetime
    completed_at: datetime | None


class InvocationOut(_Row):
    id: uuid.UUID
    sequence: int
    role: str
    provider: str
    model: str
    model_version: str | None
    prompt_template_version: str
    input_sha256: str
    output_sha256: str | None
    status: str
    cache_mode: str
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    error_category: str | None
    error_detail: str | None


class TestResultOut(_Row):
    test_case_id: uuid.UUID | None
    test_name: str
    category: str
    outcome: str
    expected_result: str
    actual_result: str
    matches_expectation: bool
    error_detail: str | None


class VerificationRunOut(_Row):
    id: uuid.UUID
    purpose: str
    revision_label: str
    patch_batch_id: uuid.UUID | None
    attempt_id: uuid.UUID | None
    sandbox_id: str | None
    sandbox_runner: str
    sandbox_profile: str
    evidence_grade: str
    build_status: str
    startup_status: str
    database_status: str
    functional_status: str
    security_status: str
    overall_status: str
    failure_category: str | None
    error_reason: str | None
    log_artifact_id: uuid.UUID | None
    started_at: datetime
    ended_at: datetime | None
    duration_ms: int | None
    results: list[TestResultOut] = []


class ReanalysisFindingOut(_Row):
    fingerprint: str
    original_finding_id: uuid.UUID | None
    change: str
    targeted: bool


class ReanalysisOut(_Row):
    id: uuid.UUID
    scope: str
    attempt_id: uuid.UUID | None
    candidate_revision: str
    evidence_grade: str
    status: str
    findings_before: int
    findings_after: int | None
    new_count: int
    resolved_count: int
    remaining_count: int
    started_at: datetime
    completed_at: datetime | None
    findings: list[ReanalysisFindingOut] = []


class ContextOut(_Row):
    id: uuid.UUID
    patch_batch_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    file_paths: list
    line_start: int | None
    line_end: int | None
    extraction_method: str
    context_bytes: int
    content_sha256: str
    redaction_status: str
    redaction_engine: str
    redaction_ruleset_version: str
    redaction_verified: bool
    redaction_verification: str
    redaction_findings_count: int
    snapshot_artifact_id: uuid.UUID | None
    created_at: datetime
    expires_at: datetime | None


class AuditEventOut(_Row):
    seq: int
    event_type: str
    entity_type: str | None
    entity_id: uuid.UUID | None
    actor_type: str
    actor_id: str | None
    previous_state: str | None
    new_state: str | None
    correlation_id: str
    details: dict = Field(serialization_alias="metadata")
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_after_seq: int | None
