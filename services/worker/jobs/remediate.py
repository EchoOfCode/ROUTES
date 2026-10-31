"""Remediation job: worker-side entry point for the `remediate` queue.

This is the M0 placeholder — it only proves a Remediation row can be queued
and run to completion. The real snapshot/redaction/LLM/verify-sandbox/loop
pipeline lands in later milestones (M2-M6) and will replace the body below.
"""

from __future__ import annotations

import logging
import uuid

from routes_shared.enums import RemediationStatus

from app.models import Remediation
from app.services import lifecycle
from worker.jobs.common import db_session

log = logging.getLogger("routes.worker.remediate")


def run_remediate_job(job_id: str, finding_id: str) -> None:
    with db_session() as db:
        remediation = db.get(Remediation, uuid.UUID(job_id), with_for_update=True)
        if remediation is None or remediation.status != RemediationStatus.PENDING:
            db.rollback()
            return
        remediation.status = RemediationStatus.RUNNING
        remediation.started_at = lifecycle.now()
        db.commit()

        log.info("remediation %s for finding %s: no-op (M0 stub)", job_id, finding_id)

        remediation.status = RemediationStatus.SUCCEEDED
        remediation.finished_at = lifecycle.now()
        db.commit()
