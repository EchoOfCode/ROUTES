"""remediation_lifecycle

Persistent records for the whole remediation lifecycle. Additive only: every
existing table, column and identifier is kept. ``remediations`` becomes the
remediation *run* and gains its project / assessment / actor links, workflow
stage, verdict, attempt limit, lease and version columns; existing rows are
backfilled from their finding. The new tables are documented in
app/models/remediation.py and docs/REMEDIATION_DATA_MODEL.md.

Backfill of existing runs:
  - project_id / assessment_id from the finding's assessment;
  - stage / verdict from the legacy status. Legacy 'succeeded' runs get stage
    'completed' but verdict NULL and resolution 'inconclusive': they predate
    recorded evidence and are NOT retro-labelled verified_fixed;
  - one remediation_findings row per run (the primary finding); only the
    newest pending/running run of a finding stays active;
  - one 'migrated' audit event per run.

Downgrade drops the new tables and columns. It restores the exact pre-0008
schema and keeps every pre-0008 value, but everything recorded after the
upgrade (attempts, plans, audit history, artifacts metadata) is lost: take a
backup first. Artifact files on disk are not touched by either direction.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-01 13:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

AUDIT_GUARD = """
CREATE OR REPLACE FUNCTION remediation_audit_events_append_only() RETURNS trigger AS $fn$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'remediation_audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- DELETE is allowed only as part of deleting the parent run (the FK
    -- cascade from retention or project deletion), never on its own.
    IF EXISTS (SELECT 1 FROM remediations WHERE id = OLD.remediation_id) THEN
        RAISE EXCEPTION 'remediation_audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN OLD;
END;
$fn$ LANGUAGE plpgsql;
CREATE TRIGGER trg_remediation_audit_events_append_only
    BEFORE UPDATE OR DELETE ON remediation_audit_events
    FOR EACH ROW EXECUTE FUNCTION remediation_audit_events_append_only();
"""

# name, type, default used only to fill existing rows (then removed)
NEW_RUN_COLUMNS = [
    ('project_id', sa.UUID(), None),
    ('assessment_id', sa.UUID(), None),
    ('requested_by', sa.UUID(), None),
    ('actor_type', sa.String(length=16), 'user'),
    ('stage', sa.String(length=40), 'queued'),
    ('stage_entered_at', sa.DateTime(timezone=True), None),
    ('verdict', sa.String(length=32), None),
    ('verdict_reason', sa.Text(), None),
    ('failure_category', sa.String(length=32), None),
    ('source_kind', sa.String(length=32), None),
    ('source_ref', sa.String(length=255), None),
    ('source_commit_sha', sa.String(length=64), None),
    ('max_attempts', sa.Integer(), '3'),
    ('attempts_total', sa.Integer(), '0'),
    ('cancelled_at', sa.DateTime(timezone=True), None),
    ('cancelled_by', sa.UUID(), None),
    ('version', sa.Integer(), '1'),
    ('lease_owner', sa.String(length=128), None),
    ('lease_expires_at', sa.DateTime(timezone=True), None),
    ('recovery_count', sa.Integer(), '0'),
    ('correlation_id', sa.String(length=64), None),
    ('idempotency_key', sa.String(length=128), None),
]
NOT_NULL_AFTER_BACKFILL = ('project_id', 'assessment_id', 'actor_type', 'stage', 'max_attempts', 'attempts_total',
                           'version', 'recovery_count', 'correlation_id')

BACKFILL = [
    """UPDATE remediations r SET assessment_id = f.assessment_id, project_id = a.project_id
         FROM security_findings f JOIN assessments a ON a.id = f.assessment_id
        WHERE f.id = r.finding_id""",
    "UPDATE remediations SET correlation_id = replace(id::text, '-', '')",
    "UPDATE remediations SET stage_entered_at = COALESCE(finished_at, started_at, created_at)",
    """UPDATE remediations SET attempts_total = (SELECT count(*) FROM remediation_iterations i
                                                 WHERE i.remediation_id = remediations.id)""",
    """UPDATE remediations SET
         stage = CASE status
                   WHEN 'pending' THEN 'queued'
                   WHEN 'running' THEN 'preparing_context'
                   WHEN 'succeeded' THEN 'completed'
                   WHEN 'needs_human_review' THEN 'human_review'
                   WHEN 'cancelled' THEN 'cancelled'
                   ELSE 'failed' END,
         verdict = CASE status
                   WHEN 'needs_human_review' THEN 'human_review'
                   WHEN 'failed' THEN 'failed'
                   WHEN 'cancelled' THEN 'cancelled'
                   ELSE NULL END,
         verdict_reason = CASE WHEN status NOT IN ('pending','running')
                   THEN 'Recorded before evidence-based verdicts (migration 0008); legacy status: ' || status
                   ELSE NULL END,
         cancelled_at = CASE WHEN status = 'cancelled' THEN finished_at ELSE NULL END""",
    """INSERT INTO remediation_findings (id, remediation_id, finding_id, is_primary, is_active, severity_snapshot,
                                         confidence_snapshot, fingerprint_snapshot, rule_id_snapshot, resolution,
                                         resolution_reason, gates, completed_at, created_at, updated_at)
       SELECT gen_random_uuid(), r.id, r.finding_id, true,
              r.status IN ('pending','running') AND r.id = (
                  SELECT r2.id FROM remediations r2
                   WHERE r2.finding_id = r.finding_id AND r2.status IN ('pending','running')
                   ORDER BY r2.created_at DESC LIMIT 1),
              f.severity, f.confidence, f.fingerprint, f.rule_id,
              CASE r.status WHEN 'pending' THEN 'pending' WHEN 'running' THEN 'in_progress'
                            WHEN 'needs_human_review' THEN 'human_review' WHEN 'cancelled' THEN 'cancelled'
                            WHEN 'failed' THEN 'failed'
                            ELSE 'inconclusive' END,
              CASE WHEN r.status = 'succeeded'
                   THEN 'Legacy run reported success before verification evidence was recorded; re-run to verify.'
                   ELSE NULL END,
              '{}'::jsonb, r.finished_at, r.created_at, now()
         FROM remediations r JOIN security_findings f ON f.id = r.finding_id""",
    """INSERT INTO remediation_audit_events (id, remediation_id, event_type, actor_type, actor_id, previous_state,
                                             new_state, correlation_id, metadata, created_at)
       SELECT gen_random_uuid(), id, 'migrated', 'system', 'alembic:0008', NULL, stage, correlation_id,
              jsonb_build_object('legacy_status', status), now()
         FROM remediations""",
]


def upgrade() -> None:
    op.create_table('remediation_artifacts',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('media_type', sa.String(length=64), nullable=False),
    sa.Column('storage_key', sa.String(length=300), nullable=False),
    sa.Column('redaction_status', sa.String(length=16), nullable=False),
    sa.Column('contains_source', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("redaction_status IN ('redacted','derived','none_needed')", name=op.f('ck_remediation_artifacts_redaction_status')),
    sa.CheckConstraint('size_bytes >= 0', name=op.f('ck_remediation_artifacts_size_nonneg')),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_artifacts_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_artifacts')),
    sa.UniqueConstraint('remediation_id', 'kind', 'sha256', name='uq_remediation_artifacts_run_kind_sha')
    )
    op.create_index('ix_remediation_artifacts_expires', 'remediation_artifacts', ['expires_at'], unique=False, postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index(op.f('ix_remediation_artifacts_remediation_id'), 'remediation_artifacts', ['remediation_id'], unique=False)
    op.create_table('remediation_audit_events',
    sa.Column('seq', sa.BigInteger(), sa.Identity(always=True), nullable=False),
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('entity_type', sa.String(length=48), nullable=True),
    sa.Column('entity_id', sa.UUID(), nullable=True),
    sa.Column('actor_type', sa.String(length=16), nullable=False),
    sa.Column('actor_id', sa.String(length=128), nullable=True),
    sa.Column('previous_state', sa.String(length=40), nullable=True),
    sa.Column('new_state', sa.String(length=40), nullable=True),
    sa.Column('correlation_id', sa.String(length=64), nullable=False),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("actor_type IN ('user','worker','api','system')", name=op.f('ck_remediation_audit_events_actor_type')),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_audit_events_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_audit_events')),
    sa.UniqueConstraint('seq', name=op.f('uq_remediation_audit_events_seq'))
    )
    op.create_index('ix_remediation_audit_events_correlation', 'remediation_audit_events', ['correlation_id'], unique=False)
    op.create_index('ix_remediation_audit_events_run_seq', 'remediation_audit_events', ['remediation_id', 'seq'], unique=False)
    op.create_table('remediation_outbox',
    sa.Column('remediation_id', sa.UUID(), nullable=True),
    sa.Column('topic', sa.String(length=32), nullable=False),
    sa.Column('job_kind', sa.String(length=32), nullable=False),
    sa.Column('job_id', sa.String(length=64), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('dedupe_key', sa.String(length=160), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=500), nullable=True),
    sa.Column('available_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("status IN ('pending','published','failed')", name=op.f('ck_remediation_outbox_status')),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_outbox_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_outbox')),
    sa.UniqueConstraint('dedupe_key', name=op.f('uq_remediation_outbox_dedupe_key'))
    )
    op.create_index('ix_remediation_outbox_pending', 'remediation_outbox', ['available_at'], unique=False, postgresql_where=sa.text("status = 'pending'"))
    op.create_index(op.f('ix_remediation_outbox_remediation_id'), 'remediation_outbox', ['remediation_id'], unique=False)
    op.create_table('remediation_patch_batches',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('change_description', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('max_attempts', sa.Integer(), nullable=False),
    sa.Column('attempts_used', sa.Integer(), nullable=False),
    sa.Column('depends_on_batch_id', sa.UUID(), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending','in_progress','verified','failed','exhausted','human_review','inconclusive','cancelled')", name=op.f('ck_remediation_patch_batches_status')),
    sa.CheckConstraint('attempts_used >= 0 AND attempts_used <= max_attempts', name=op.f('ck_remediation_patch_batches_attempts_used_range')),
    sa.CheckConstraint('max_attempts BETWEEN 1 AND 10', name=op.f('ck_remediation_patch_batches_max_attempts_range')),
    sa.ForeignKeyConstraint(['depends_on_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_patch_batches_depends_on_batch_id_remediation_patch_batches'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_patch_batches_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_patch_batches')),
    sa.UniqueConstraint('remediation_id', 'sequence', name='uq_remediation_patch_batches_run_seq')
    )
    op.create_index(op.f('ix_remediation_patch_batches_remediation_id'), 'remediation_patch_batches', ['remediation_id'], unique=False)
    op.create_table('ai_model_invocations',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('provider', sa.String(length=100), nullable=False),
    sa.Column('model', sa.String(length=200), nullable=False),
    sa.Column('model_version', sa.String(length=100), nullable=True),
    sa.Column('prompt_template_version', sa.String(length=32), nullable=False),
    sa.Column('input_sha256', sa.String(length=64), nullable=False),
    sa.Column('input_artifact_id', sa.UUID(), nullable=True),
    sa.Column('output_sha256', sa.String(length=64), nullable=True),
    sa.Column('output_artifact_id', sa.UUID(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('cache_mode', sa.String(length=16), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('prompt_tokens', sa.Integer(), nullable=True),
    sa.Column('completion_tokens', sa.Integer(), nullable=True),
    sa.Column('total_tokens', sa.Integer(), nullable=True),
    sa.Column('retry_of_id', sa.UUID(), nullable=True),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('error_category', sa.String(length=32), nullable=True),
    sa.Column('error_detail', sa.String(length=500), nullable=True),
    sa.Column('correlation_id', sa.String(length=64), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("role IN ('analysis','patch_generation')", name=op.f('ck_ai_model_invocations_role')),
    sa.CheckConstraint("status IN ('started','succeeded','failed','invalid_output','blocked')", name=op.f('ck_ai_model_invocations_status')),
    sa.ForeignKeyConstraint(['input_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_ai_model_invocations_input_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['output_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_ai_model_invocations_output_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_ai_model_invocations_patch_batch_id_remediation_patch_batches'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_ai_model_invocations_remediation_id_remediations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['retry_of_id'], ['ai_model_invocations.id'], name=op.f('fk_ai_model_invocations_retry_of_id_ai_model_invocations'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_model_invocations')),
    sa.UniqueConstraint('remediation_id', 'sequence', name='uq_ai_model_invocations_run_seq')
    )
    op.create_index(op.f('ix_ai_model_invocations_correlation_id'), 'ai_model_invocations', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_ai_model_invocations_patch_batch_id'), 'ai_model_invocations', ['patch_batch_id'], unique=False)
    op.create_index('ix_ai_model_invocations_provider_model', 'ai_model_invocations', ['provider', 'model', 'started_at'], unique=False)
    op.create_index(op.f('ix_ai_model_invocations_remediation_id'), 'ai_model_invocations', ['remediation_id'], unique=False)
    op.create_table('remediation_batch_files',
    sa.Column('batch_id', sa.UUID(), nullable=False),
    sa.Column('file_path', sa.String(length=1024), nullable=False),
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_batch_files_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_batch_files_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('batch_id', 'file_path', name=op.f('pk_remediation_batch_files')),
    sa.UniqueConstraint('remediation_id', 'file_path', name='uq_remediation_batch_files_run_file')
    )
    op.create_index(op.f('ix_remediation_batch_files_remediation_id'), 'remediation_batch_files', ['remediation_id'], unique=False)
    op.create_table('remediation_contexts',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('finding_id', sa.UUID(), nullable=True),
    sa.Column('source_commit_sha', sa.String(length=64), nullable=True),
    sa.Column('snapshot_artifact_id', sa.UUID(), nullable=True),
    sa.Column('file_paths', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('symbols', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('line_start', sa.Integer(), nullable=True),
    sa.Column('line_end', sa.Integer(), nullable=True),
    sa.Column('extraction_method', sa.String(length=64), nullable=False),
    sa.Column('context_bytes', sa.Integer(), nullable=False),
    sa.Column('content_sha256', sa.String(length=64), nullable=False),
    sa.Column('redaction_status', sa.String(length=16), nullable=False),
    sa.Column('redaction_engine', sa.String(length=100), nullable=False),
    sa.Column('redaction_ruleset_version', sa.String(length=32), nullable=False),
    sa.Column('redaction_verified', sa.Boolean(), nullable=False),
    sa.Column('redaction_verification', sa.String(length=200), nullable=False),
    sa.Column('redaction_findings_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['security_findings.id'], name=op.f('fk_remediation_contexts_finding_id_security_findings'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_contexts_patch_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_contexts_remediation_id_remediations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['snapshot_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_contexts_snapshot_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_contexts'))
    )
    op.create_index(op.f('ix_remediation_contexts_patch_batch_id'), 'remediation_contexts', ['patch_batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_contexts_remediation_id'), 'remediation_contexts', ['remediation_id'], unique=False)
    op.create_table('remediation_findings',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('finding_id', sa.UUID(), nullable=False),
    sa.Column('is_primary', sa.Boolean(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('severity_snapshot', sa.String(length=16), nullable=False),
    sa.Column('confidence_snapshot', sa.String(length=16), nullable=False),
    sa.Column('fingerprint_snapshot', sa.String(length=64), nullable=False),
    sa.Column('rule_id_snapshot', sa.String(length=200), nullable=False),
    sa.Column('resolution', sa.String(length=32), nullable=False),
    sa.Column('resolution_reason', sa.Text(), nullable=True),
    sa.Column('verification_outcome', sa.String(length=32), nullable=True),
    sa.Column('gates', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('residual_risk', sa.Text(), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("resolution IN ('pending','in_progress','verified_fixed','not_fixed','human_review','inconclusive','cancelled','failed')", name=op.f('ck_remediation_findings_resolution')),
    sa.ForeignKeyConstraint(['finding_id'], ['security_findings.id'], name=op.f('fk_remediation_findings_finding_id_security_findings'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_findings_patch_batch_id_remediation_patch_batches'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_findings_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_findings')),
    sa.UniqueConstraint('remediation_id', 'finding_id', name='uq_remediation_findings_run_finding')
    )
    op.create_index(op.f('ix_remediation_findings_finding_id'), 'remediation_findings', ['finding_id'], unique=False)
    op.create_index(op.f('ix_remediation_findings_patch_batch_id'), 'remediation_findings', ['patch_batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_findings_remediation_id'), 'remediation_findings', ['remediation_id'], unique=False)
    op.create_index('uq_remediation_findings_one_active', 'remediation_findings', ['finding_id'], unique=True, postgresql_where=sa.text('is_active'))
    op.create_table('remediation_plans',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('root_cause', sa.Text(), nullable=True),
    sa.Column('vulnerability_explanation', sa.Text(), nullable=True),
    sa.Column('strategy', sa.Text(), nullable=True),
    sa.Column('files_involved', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('functions_involved', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('expected_behaviour', sa.Text(), nullable=True),
    sa.Column('side_effects', sa.Text(), nullable=True),
    sa.Column('patch_scope', sa.Text(), nullable=True),
    sa.Column('test_generation_status', sa.String(length=32), nullable=False),
    sa.Column('schema_valid', sa.Boolean(), nullable=False),
    sa.Column('artifact_id', sa.UUID(), nullable=True),
    sa.Column('invocation_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_plans_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['invocation_id'], ['ai_model_invocations.id'], name=op.f('fk_remediation_plans_invocation_id_ai_model_invocations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_plans_patch_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_plans_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_plans')),
    sa.UniqueConstraint('remediation_id', 'version', name='uq_remediation_plans_run_version')
    )
    op.create_index(op.f('ix_remediation_plans_patch_batch_id'), 'remediation_plans', ['patch_batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_plans_remediation_id'), 'remediation_plans', ['remediation_id'], unique=False)
    op.create_table('remediation_patch_attempts',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('batch_id', sa.UUID(), nullable=False),
    sa.Column('attempt_no', sa.Integer(), nullable=False),
    sa.Column('max_attempts', sa.Integer(), nullable=False),
    sa.Column('invocation_id', sa.UUID(), nullable=True),
    sa.Column('fix_source', sa.String(length=64), nullable=True),
    sa.Column('plan_id', sa.UUID(), nullable=True),
    sa.Column('plan_version', sa.Integer(), nullable=True),
    sa.Column('source_commit_sha', sa.String(length=64), nullable=True),
    sa.Column('patch_format', sa.String(length=32), nullable=False),
    sa.Column('patch_artifact_id', sa.UUID(), nullable=True),
    sa.Column('patch_sha256', sa.String(length=64), nullable=True),
    sa.Column('candidate_artifact_id', sa.UUID(), nullable=True),
    sa.Column('candidate_hash', sa.String(length=64), nullable=True),
    sa.Column('files_changed', sa.Integer(), nullable=False),
    sa.Column('generation_status', sa.String(length=16), nullable=False),
    sa.Column('validation_status', sa.String(length=16), nullable=False),
    sa.Column('verification_status', sa.String(length=16), nullable=False),
    sa.Column('failure_reason', sa.Text(), nullable=True),
    sa.Column('fix_note', sa.Text(), nullable=True),
    sa.Column('legacy_iteration_id', sa.UUID(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=160), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("generation_status IN ('pending','generated','invalid_output','error','abandoned')", name=op.f('ck_remediation_patch_attempts_generation_status')),
    sa.CheckConstraint("validation_status IN ('pending','valid','invalid','skipped')", name=op.f('ck_remediation_patch_attempts_validation_status')),
    sa.CheckConstraint("verification_status IN ('pending','passed','failed','error','skipped')", name=op.f('ck_remediation_patch_attempts_verification_status')),
    sa.CheckConstraint('attempt_no >= 1 AND attempt_no <= max_attempts', name=op.f('ck_remediation_patch_attempts_attempt_within_limit')),
    sa.CheckConstraint('max_attempts BETWEEN 1 AND 10', name=op.f('ck_remediation_patch_attempts_max_attempts_range')),
    sa.ForeignKeyConstraint(['batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_patch_attempts_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['candidate_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_patch_attempts_candidate_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['invocation_id'], ['ai_model_invocations.id'], name=op.f('fk_remediation_patch_attempts_invocation_id_ai_model_invocations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['legacy_iteration_id'], ['remediation_iterations.id'], name=op.f('fk_remediation_patch_attempts_legacy_iteration_id_remediation_iterations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_patch_attempts_patch_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['plan_id'], ['remediation_plans.id'], name=op.f('fk_remediation_patch_attempts_plan_id_remediation_plans'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_patch_attempts_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_patch_attempts')),
    sa.UniqueConstraint('batch_id', 'attempt_no', name='uq_remediation_patch_attempts_batch_no'),
    sa.UniqueConstraint('idempotency_key', name=op.f('uq_remediation_patch_attempts_idempotency_key'))
    )
    op.create_index(op.f('ix_remediation_patch_attempts_batch_id'), 'remediation_patch_attempts', ['batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_patch_attempts_remediation_id'), 'remediation_patch_attempts', ['remediation_id'], unique=False)
    op.create_table('remediation_test_suites',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('plan_id', sa.UUID(), nullable=True),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('suite_type', sa.String(length=32), nullable=False),
    sa.Column('generation_method', sa.String(length=32), nullable=False),
    sa.Column('validation_status', sa.String(length=16), nullable=False),
    sa.Column('validation_detail', sa.Text(), nullable=True),
    sa.Column('baseline_status', sa.String(length=16), nullable=False),
    sa.Column('coverage', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('artifact_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("baseline_status IN ('not_run','reproduced','not_reproduced','error')", name=op.f('ck_remediation_test_suites_baseline_status')),
    sa.CheckConstraint("suite_type IN ('deterministic_security','ai_generated','repository','regression')", name=op.f('ck_remediation_test_suites_suite_type')),
    sa.CheckConstraint("validation_status IN ('pending','validated','rejected','error')", name=op.f('ck_remediation_test_suites_validation_status')),
    sa.ForeignKeyConstraint(['artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_test_suites_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_test_suites_patch_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['plan_id'], ['remediation_plans.id'], name=op.f('fk_remediation_test_suites_plan_id_remediation_plans'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_test_suites_remediation_id_remediations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_test_suites')),
    sa.UniqueConstraint('remediation_id', 'version', name='uq_remediation_test_suites_run_version')
    )
    op.create_index(op.f('ix_remediation_test_suites_patch_batch_id'), 'remediation_test_suites', ['patch_batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_test_suites_remediation_id'), 'remediation_test_suites', ['remediation_id'], unique=False)
    op.create_table('remediation_test_cases',
    sa.Column('suite_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=300), nullable=False),
    sa.Column('category', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('expected_behaviour', sa.String(length=300), nullable=False),
    sa.Column('artifact_id', sa.UUID(), nullable=True),
    sa.Column('baseline_outcome', sa.String(length=16), nullable=True),
    sa.Column('validation_status', sa.String(length=16), nullable=False),
    sa.Column('visibility', sa.String(length=24), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("category IN ('exploit','benign','security','functional','regression','edge_case')", name=op.f('ck_remediation_test_cases_category')),
    sa.CheckConstraint("visibility IN ('hidden','provided_to_model')", name=op.f('ck_remediation_test_cases_visibility')),
    sa.ForeignKeyConstraint(['artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_test_cases_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['suite_id'], ['remediation_test_suites.id'], name=op.f('fk_remediation_test_cases_suite_id_remediation_test_suites'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_test_cases')),
    sa.UniqueConstraint('suite_id', 'name', name='uq_remediation_test_cases_suite_name')
    )
    op.create_index(op.f('ix_remediation_test_cases_suite_id'), 'remediation_test_cases', ['suite_id'], unique=False)
    op.create_table('remediation_verification_runs',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('patch_batch_id', sa.UUID(), nullable=True),
    sa.Column('attempt_id', sa.UUID(), nullable=True),
    sa.Column('suite_id', sa.UUID(), nullable=True),
    sa.Column('purpose', sa.String(length=24), nullable=False),
    sa.Column('revision_label', sa.String(length=200), nullable=False),
    sa.Column('sandbox_id', sa.String(length=100), nullable=True),
    sa.Column('sandbox_runner', sa.String(length=32), nullable=False),
    sa.Column('sandbox_profile', sa.String(length=64), nullable=False),
    sa.Column('evidence_grade', sa.String(length=16), nullable=False),
    sa.Column('build_status', sa.String(length=16), nullable=False),
    sa.Column('startup_status', sa.String(length=16), nullable=False),
    sa.Column('database_status', sa.String(length=16), nullable=False),
    sa.Column('functional_status', sa.String(length=16), nullable=False),
    sa.Column('security_status', sa.String(length=16), nullable=False),
    sa.Column('overall_status', sa.String(length=16), nullable=False),
    sa.Column('failure_category', sa.String(length=32), nullable=True),
    sa.Column('error_reason', sa.String(length=500), nullable=True),
    sa.Column('resource_usage', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('log_artifact_id', sa.UUID(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=200), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("evidence_grade IN ('sandbox','simulated')", name=op.f('ck_remediation_verification_runs_evidence_grade')),
    sa.CheckConstraint("overall_status IN ('passed','failed','error','timeout','killed','not_run')", name=op.f('ck_remediation_verification_runs_overall_status')),
    sa.CheckConstraint("purpose IN ('baseline','gate_known_bad','candidate','rescan','combined_rescan')", name=op.f('ck_remediation_verification_runs_purpose')),
    sa.ForeignKeyConstraint(['attempt_id'], ['remediation_patch_attempts.id'], name=op.f('fk_remediation_verification_runs_attempt_id_remediation_patch_attempts'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['log_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_verification_runs_log_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['patch_batch_id'], ['remediation_patch_batches.id'], name=op.f('fk_remediation_verification_runs_patch_batch_id_remediation_patch_batches'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_verification_runs_remediation_id_remediations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['suite_id'], ['remediation_test_suites.id'], name=op.f('fk_remediation_verification_runs_suite_id_remediation_test_suites'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_verification_runs')),
    sa.UniqueConstraint('idempotency_key', name=op.f('uq_remediation_verification_runs_idempotency_key'))
    )
    op.create_index(op.f('ix_remediation_verification_runs_attempt_id'), 'remediation_verification_runs', ['attempt_id'], unique=False)
    op.create_index(op.f('ix_remediation_verification_runs_patch_batch_id'), 'remediation_verification_runs', ['patch_batch_id'], unique=False)
    op.create_index(op.f('ix_remediation_verification_runs_remediation_id'), 'remediation_verification_runs', ['remediation_id'], unique=False)
    op.create_index('ix_remediation_verification_runs_run_started', 'remediation_verification_runs', ['remediation_id', 'started_at'], unique=False)
    op.create_index(op.f('ix_remediation_verification_runs_suite_id'), 'remediation_verification_runs', ['suite_id'], unique=False)
    op.create_table('remediation_reanalysis_runs',
    sa.Column('remediation_id', sa.UUID(), nullable=False),
    sa.Column('assessment_id', sa.UUID(), nullable=False),
    sa.Column('attempt_id', sa.UUID(), nullable=True),
    sa.Column('verification_run_id', sa.UUID(), nullable=True),
    sa.Column('scope', sa.String(length=16), nullable=False),
    sa.Column('candidate_revision', sa.String(length=200), nullable=False),
    sa.Column('engine_versions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('evidence_grade', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('findings_before', sa.Integer(), nullable=False),
    sa.Column('findings_after', sa.Integer(), nullable=True),
    sa.Column('new_count', sa.Integer(), nullable=False),
    sa.Column('resolved_count', sa.Integer(), nullable=False),
    sa.Column('remaining_count', sa.Integer(), nullable=False),
    sa.Column('artifact_id', sa.UUID(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("evidence_grade IN ('sandbox','simulated')", name=op.f('ck_remediation_reanalysis_runs_evidence_grade')),
    sa.CheckConstraint("status IN ('completed','error','not_run')", name=op.f('ck_remediation_reanalysis_runs_status')),
    sa.ForeignKeyConstraint(['artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_reanalysis_runs_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['assessment_id'], ['assessments.id'], name=op.f('fk_remediation_reanalysis_runs_assessment_id_assessments'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['attempt_id'], ['remediation_patch_attempts.id'], name=op.f('fk_remediation_reanalysis_runs_attempt_id_remediation_patch_attempts'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], name=op.f('fk_remediation_reanalysis_runs_remediation_id_remediations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['verification_run_id'], ['remediation_verification_runs.id'], name=op.f('fk_remediation_reanalysis_runs_verification_run_id_remediation_verification_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_reanalysis_runs'))
    )
    op.create_index(op.f('ix_remediation_reanalysis_runs_assessment_id'), 'remediation_reanalysis_runs', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_remediation_reanalysis_runs_attempt_id'), 'remediation_reanalysis_runs', ['attempt_id'], unique=False)
    op.create_index(op.f('ix_remediation_reanalysis_runs_remediation_id'), 'remediation_reanalysis_runs', ['remediation_id'], unique=False)
    op.create_table('remediation_test_results',
    sa.Column('verification_run_id', sa.UUID(), nullable=False),
    sa.Column('test_case_id', sa.UUID(), nullable=True),
    sa.Column('test_name', sa.String(length=300), nullable=False),
    sa.Column('category', sa.String(length=32), nullable=False),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('expected_result', sa.String(length=16), nullable=False),
    sa.Column('actual_result', sa.String(length=16), nullable=False),
    sa.Column('matches_expectation', sa.Boolean(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('error_category', sa.String(length=32), nullable=True),
    sa.Column('error_detail', sa.String(length=500), nullable=True),
    sa.Column('evidence_artifact_id', sa.UUID(), nullable=True),
    sa.Column('executed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("outcome IN ('passed','failed','error','skipped','inconclusive')", name=op.f('ck_remediation_test_results_outcome')),
    sa.ForeignKeyConstraint(['evidence_artifact_id'], ['remediation_artifacts.id'], name=op.f('fk_remediation_test_results_evidence_artifact_id_remediation_artifacts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['test_case_id'], ['remediation_test_cases.id'], name=op.f('fk_remediation_test_results_test_case_id_remediation_test_cases'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['verification_run_id'], ['remediation_verification_runs.id'], name=op.f('fk_remediation_test_results_verification_run_id_remediation_verification_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_test_results')),
    sa.UniqueConstraint('verification_run_id', 'test_name', name='uq_remediation_test_results_run_name')
    )
    op.create_index(op.f('ix_remediation_test_results_test_case_id'), 'remediation_test_results', ['test_case_id'], unique=False)
    op.create_index(op.f('ix_remediation_test_results_verification_run_id'), 'remediation_test_results', ['verification_run_id'], unique=False)
    op.create_table('remediation_reanalysis_findings',
    sa.Column('reanalysis_id', sa.UUID(), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('original_finding_id', sa.UUID(), nullable=True),
    sa.Column('change', sa.String(length=16), nullable=False),
    sa.Column('targeted', sa.Boolean(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.CheckConstraint("change IN ('resolved','remaining','new')", name=op.f('ck_remediation_reanalysis_findings_change')),
    sa.ForeignKeyConstraint(['original_finding_id'], ['security_findings.id'], name=op.f('fk_remediation_reanalysis_findings_original_finding_id_security_findings'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reanalysis_id'], ['remediation_reanalysis_runs.id'], name=op.f('fk_remediation_reanalysis_findings_reanalysis_id_remediation_reanalysis_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_reanalysis_findings')),
    sa.UniqueConstraint('reanalysis_id', 'fingerprint', name='uq_remediation_reanalysis_findings_run_fp')
    )
    op.create_index(op.f('ix_remediation_reanalysis_findings_original_finding_id'), 'remediation_reanalysis_findings', ['original_finding_id'], unique=False)
    op.create_index(op.f('ix_remediation_reanalysis_findings_reanalysis_id'), 'remediation_reanalysis_findings', ['reanalysis_id'], unique=False)

    for name, type_, default in NEW_RUN_COLUMNS:
        server_default = None if default is None else sa.text(default if default.isdigit() else f"'{default}'")
        op.add_column('remediations', sa.Column(name, type_, nullable=True, server_default=server_default))
    op.execute(AUDIT_GUARD)
    for statement in BACKFILL:
        op.execute(statement)
    for name in NOT_NULL_AFTER_BACKFILL:
        op.alter_column('remediations', name, nullable=False)
    for name, _, default in NEW_RUN_COLUMNS:
        if default is not None:
            op.alter_column('remediations', name, server_default=None)
    op.create_check_constraint('max_attempts_range', 'remediations', 'max_attempts BETWEEN 1 AND 10')
    op.create_check_constraint('attempts_total_nonneg', 'remediations', 'attempts_total >= 0')
    op.create_index('ix_remediations_assessment_created', 'remediations', ['assessment_id', 'created_at'], unique=False)
    op.create_index(op.f('ix_remediations_assessment_id'), 'remediations', ['assessment_id'], unique=False)
    op.create_index('ix_remediations_correlation_id', 'remediations', ['correlation_id'], unique=False)
    op.create_index('ix_remediations_project_created', 'remediations', ['project_id', 'created_at'], unique=False)
    op.create_index(op.f('ix_remediations_project_id'), 'remediations', ['project_id'], unique=False)
    op.create_index('ix_remediations_status_created', 'remediations', ['status', 'created_at'], unique=False)
    op.create_index('uq_remediations_project_idempotency', 'remediations', ['project_id', 'idempotency_key'], unique=True, postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    op.create_foreign_key(op.f('fk_remediations_requested_by_users'), 'remediations', 'users', ['requested_by'], ['id'], ondelete='SET NULL')
    op.create_foreign_key(op.f('fk_remediations_assessment_id_assessments'), 'remediations', 'assessments', ['assessment_id'], ['id'], ondelete='CASCADE')
    op.create_foreign_key(op.f('fk_remediations_project_id_projects'), 'remediations', 'projects', ['project_id'], ['id'], ondelete='CASCADE')
    op.create_foreign_key(op.f('fk_remediations_cancelled_by_users'), 'remediations', 'users', ['cancelled_by'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_remediation_audit_events_append_only ON remediation_audit_events")
    op.execute("DROP FUNCTION IF EXISTS remediation_audit_events_append_only()")
    op.drop_constraint('attempts_total_nonneg', 'remediations', type_='check')
    op.drop_constraint('max_attempts_range', 'remediations', type_='check')
    op.drop_constraint(op.f('fk_remediations_cancelled_by_users'), 'remediations', type_='foreignkey')
    op.drop_constraint(op.f('fk_remediations_project_id_projects'), 'remediations', type_='foreignkey')
    op.drop_constraint(op.f('fk_remediations_assessment_id_assessments'), 'remediations', type_='foreignkey')
    op.drop_constraint(op.f('fk_remediations_requested_by_users'), 'remediations', type_='foreignkey')
    op.drop_index('uq_remediations_project_idempotency', table_name='remediations', postgresql_where=sa.text('idempotency_key IS NOT NULL'))
    op.drop_index('ix_remediations_status_created', table_name='remediations')
    op.drop_index(op.f('ix_remediations_project_id'), table_name='remediations')
    op.drop_index('ix_remediations_project_created', table_name='remediations')
    op.drop_index('ix_remediations_correlation_id', table_name='remediations')
    op.drop_index(op.f('ix_remediations_assessment_id'), table_name='remediations')
    op.drop_index('ix_remediations_assessment_created', table_name='remediations')
    op.drop_column('remediations', 'idempotency_key')
    op.drop_column('remediations', 'correlation_id')
    op.drop_column('remediations', 'recovery_count')
    op.drop_column('remediations', 'lease_expires_at')
    op.drop_column('remediations', 'lease_owner')
    op.drop_column('remediations', 'version')
    op.drop_column('remediations', 'cancelled_by')
    op.drop_column('remediations', 'cancelled_at')
    op.drop_column('remediations', 'attempts_total')
    op.drop_column('remediations', 'max_attempts')
    op.drop_column('remediations', 'source_commit_sha')
    op.drop_column('remediations', 'source_ref')
    op.drop_column('remediations', 'source_kind')
    op.drop_column('remediations', 'failure_category')
    op.drop_column('remediations', 'verdict_reason')
    op.drop_column('remediations', 'verdict')
    op.drop_column('remediations', 'stage_entered_at')
    op.drop_column('remediations', 'stage')
    op.drop_column('remediations', 'actor_type')
    op.drop_column('remediations', 'requested_by')
    op.drop_column('remediations', 'assessment_id')
    op.drop_column('remediations', 'project_id')
    op.drop_index(op.f('ix_remediation_reanalysis_findings_reanalysis_id'), table_name='remediation_reanalysis_findings')
    op.drop_index(op.f('ix_remediation_reanalysis_findings_original_finding_id'), table_name='remediation_reanalysis_findings')
    op.drop_table('remediation_reanalysis_findings')
    op.drop_index(op.f('ix_remediation_test_results_verification_run_id'), table_name='remediation_test_results')
    op.drop_index(op.f('ix_remediation_test_results_test_case_id'), table_name='remediation_test_results')
    op.drop_table('remediation_test_results')
    op.drop_index(op.f('ix_remediation_reanalysis_runs_remediation_id'), table_name='remediation_reanalysis_runs')
    op.drop_index(op.f('ix_remediation_reanalysis_runs_attempt_id'), table_name='remediation_reanalysis_runs')
    op.drop_index(op.f('ix_remediation_reanalysis_runs_assessment_id'), table_name='remediation_reanalysis_runs')
    op.drop_table('remediation_reanalysis_runs')
    op.drop_index(op.f('ix_remediation_verification_runs_suite_id'), table_name='remediation_verification_runs')
    op.drop_index('ix_remediation_verification_runs_run_started', table_name='remediation_verification_runs')
    op.drop_index(op.f('ix_remediation_verification_runs_remediation_id'), table_name='remediation_verification_runs')
    op.drop_index(op.f('ix_remediation_verification_runs_patch_batch_id'), table_name='remediation_verification_runs')
    op.drop_index(op.f('ix_remediation_verification_runs_attempt_id'), table_name='remediation_verification_runs')
    op.drop_table('remediation_verification_runs')
    op.drop_index(op.f('ix_remediation_test_cases_suite_id'), table_name='remediation_test_cases')
    op.drop_table('remediation_test_cases')
    op.drop_index(op.f('ix_remediation_test_suites_remediation_id'), table_name='remediation_test_suites')
    op.drop_index(op.f('ix_remediation_test_suites_patch_batch_id'), table_name='remediation_test_suites')
    op.drop_table('remediation_test_suites')
    op.drop_index(op.f('ix_remediation_patch_attempts_remediation_id'), table_name='remediation_patch_attempts')
    op.drop_index(op.f('ix_remediation_patch_attempts_batch_id'), table_name='remediation_patch_attempts')
    op.drop_table('remediation_patch_attempts')
    op.drop_index(op.f('ix_remediation_plans_remediation_id'), table_name='remediation_plans')
    op.drop_index(op.f('ix_remediation_plans_patch_batch_id'), table_name='remediation_plans')
    op.drop_table('remediation_plans')
    op.drop_index('uq_remediation_findings_one_active', table_name='remediation_findings', postgresql_where=sa.text('is_active'))
    op.drop_index(op.f('ix_remediation_findings_remediation_id'), table_name='remediation_findings')
    op.drop_index(op.f('ix_remediation_findings_patch_batch_id'), table_name='remediation_findings')
    op.drop_index(op.f('ix_remediation_findings_finding_id'), table_name='remediation_findings')
    op.drop_table('remediation_findings')
    op.drop_index(op.f('ix_remediation_contexts_remediation_id'), table_name='remediation_contexts')
    op.drop_index(op.f('ix_remediation_contexts_patch_batch_id'), table_name='remediation_contexts')
    op.drop_table('remediation_contexts')
    op.drop_index(op.f('ix_remediation_batch_files_remediation_id'), table_name='remediation_batch_files')
    op.drop_table('remediation_batch_files')
    op.drop_index(op.f('ix_ai_model_invocations_remediation_id'), table_name='ai_model_invocations')
    op.drop_index('ix_ai_model_invocations_provider_model', table_name='ai_model_invocations')
    op.drop_index(op.f('ix_ai_model_invocations_patch_batch_id'), table_name='ai_model_invocations')
    op.drop_index(op.f('ix_ai_model_invocations_correlation_id'), table_name='ai_model_invocations')
    op.drop_table('ai_model_invocations')
    op.drop_index(op.f('ix_remediation_patch_batches_remediation_id'), table_name='remediation_patch_batches')
    op.drop_table('remediation_patch_batches')
    op.drop_index(op.f('ix_remediation_outbox_remediation_id'), table_name='remediation_outbox')
    op.drop_index('ix_remediation_outbox_pending', table_name='remediation_outbox', postgresql_where=sa.text("status = 'pending'"))
    op.drop_table('remediation_outbox')
    op.drop_index('ix_remediation_audit_events_run_seq', table_name='remediation_audit_events')
    op.drop_index('ix_remediation_audit_events_correlation', table_name='remediation_audit_events')
    op.drop_table('remediation_audit_events')
    op.drop_index(op.f('ix_remediation_artifacts_remediation_id'), table_name='remediation_artifacts')
    op.drop_index('ix_remediation_artifacts_expires', table_name='remediation_artifacts', postgresql_where=sa.text('deleted_at IS NULL'))
    op.drop_table('remediation_artifacts')
