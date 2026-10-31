"""Remediation job: worker-side entry point for the `remediate` queue.

Fetches the finding + its persisted snapshot (S8a), builds the LLM clients
and sandbox runner from config, runs the loop controller (S8c), and persists
every round as a RemediationIteration row.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select

from routes_shared.enums import FindingRemediationStatus, RemediationStatus
from routes_shared.remediation import Snapshot

from app.core.config import get_settings
from app.models import Assessment, ProjectIntegration, Remediation, RemediationIteration, SecurityFinding
from app.services import lifecycle
from worker.jobs.common import db_session
from worker.llm.client import LLMClient
from worker.loop import run_remediation_loop
from worker.sandbox import SourceRef, build_sandbox_runner

log = logging.getLogger("routes.worker.remediate")


def _source_ref(integration: ProjectIntegration | None) -> SourceRef | None:
    if integration is None:
        return None
    if integration.kind in ("github_public", "github_private"):
        return SourceRef(kind="github", owner=integration.repo_owner, repo=integration.repo_name,
                         ref=integration.repo_ref)
    if integration.kind == "zip":
        # No upload_id is persisted anywhere past the original scan (only
        # filename/sha256 are kept on ProjectIntegration) - a zip-sourced
        # rescan has nothing stable to re-fetch from yet. Flagged in
        # docs/PROGRESS.md; this returns a ref the real backend cannot
        # actually use until that's resolved.
        return SourceRef(kind="zip", upload_id=None)
    return None


def run_remediate_job(job_id: str, finding_id: str) -> None:
    settings = get_settings()
    llm_a_client = LLMClient(endpoint=settings.llm_a_endpoint, api_key=settings.llm_a_api_key,
                             model=settings.llm_a_model, cache_mode=settings.llm_cache_mode,
                             cache_dir=settings.llm_cache_dir)
    llm_b_client = LLMClient(endpoint=settings.llm_b_endpoint, api_key=settings.llm_b_api_key,
                             model=settings.llm_b_model, cache_mode=settings.llm_cache_mode,
                             cache_dir=settings.llm_cache_dir)
    sandbox_runner = build_sandbox_runner(settings.sandbox_runner_kind, manager_url=settings.sandbox_manager_url,
                                          manager_token=settings.sandbox_manager_token)
    try:
        with db_session() as db:
            remediation = db.get(Remediation, uuid.UUID(job_id), with_for_update=True)
            if remediation is None or remediation.status != RemediationStatus.PENDING:
                db.rollback()
                return
            remediation.status = RemediationStatus.RUNNING
            remediation.started_at = lifecycle.now()
            db.commit()

            try:
                finding = db.get(SecurityFinding, uuid.UUID(finding_id))
                if finding is None:
                    _finish(db, remediation, RemediationStatus.FAILED, FindingRemediationStatus.OPEN,
                            "The finding no longer exists.")
                    return
                if not finding.snapshot:
                    _finish(db, remediation, RemediationStatus.NEEDS_HUMAN_REVIEW,
                            FindingRemediationStatus.NEEDS_HUMAN_REVIEW,
                            "No code snapshot is available for this finding.")
                    return

                assessment = db.get(Assessment, finding.assessment_id)
                integration = db.scalar(select(ProjectIntegration).where(
                    ProjectIntegration.project_id == assessment.project_id))
                source_ref = _source_ref(integration)
                if source_ref is None:
                    _finish(db, remediation, RemediationStatus.NEEDS_HUMAN_REVIEW,
                            FindingRemediationStatus.NEEDS_HUMAN_REVIEW,
                            "No source reference is available to rescan against.")
                    return

                baseline_fingerprints = set(db.scalars(
                    select(SecurityFinding.fingerprint).where(SecurityFinding.assessment_id == finding.assessment_id)
                ).all())

                snapshot = Snapshot(file=finding.snapshot["file"], start_line=finding.snapshot["start_line"],
                                    end_line=finding.snapshot["end_line"], code=finding.snapshot["code"])
                finding_dict = {"id": str(finding.id), "rule_id": finding.rule_id, "title": finding.title,
                               "plain_description": finding.plain_description, "fingerprint": finding.fingerprint}

                def should_cancel() -> bool:
                    db.refresh(remediation)
                    return remediation.cancel_requested

                outcome = run_remediation_loop(
                    finding=finding_dict, snapshot=snapshot, llm_a_client=llm_a_client, llm_b_client=llm_b_client,
                    sandbox_runner=sandbox_runner, source_ref=source_ref, baseline_fingerprints=baseline_fingerprints,
                    max_rounds=settings.max_rounds, stagnation_rounds=settings.stagnation_rounds,
                    should_cancel=should_cancel,
                )

                for record in outcome.rounds:
                    db.add(RemediationIteration(
                        remediation_id=remediation.id, iteration_no=record.round_no, round_no=record.round_no,
                        candidate_hash=record.candidate_hash, candidate_code=record.candidate_code,
                        test_results=record.test_results, rescan_diff=record.rescan_diff,
                        failure_output=record.failure_output,
                        fix_source=record.fix_source, fix_note=record.fix_note,
                    ))

                if outcome.status == "fixed":
                    _finish(db, remediation, RemediationStatus.SUCCEEDED, FindingRemediationStatus.FIXED, None)
                elif outcome.status == "cancelled":
                    _finish(db, remediation, RemediationStatus.CANCELLED, FindingRemediationStatus.OPEN,
                            outcome.reason)
                else:
                    _finish(db, remediation, RemediationStatus.NEEDS_HUMAN_REVIEW,
                            FindingRemediationStatus.NEEDS_HUMAN_REVIEW, outcome.reason)
            except Exception:
                db.rollback()
                remediation = db.get(Remediation, uuid.UUID(job_id), with_for_update=True)
                _finish(db, remediation, RemediationStatus.FAILED, FindingRemediationStatus.OPEN,
                        "An internal error interrupted remediation.")
                raise
    finally:
        llm_a_client.close()
        llm_b_client.close()


def _finish(db, remediation: Remediation, status: str, finding_status: str, error: str | None) -> None:
    remediation.status = status
    remediation.finding_status = finding_status
    remediation.error = error
    remediation.finished_at = lifecycle.now()
    db.commit()
