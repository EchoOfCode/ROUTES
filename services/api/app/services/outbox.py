"""Transactional outbox for remediation job dispatch.

A state change that needs a worker (a new run, a recovered run) writes a
``remediation_outbox`` row in the *same* transaction. Publishing to Redis/RQ
happens afterwards, from ``relay``: if Redis is down or the process dies
between commit and publish, the row stays ``pending`` and is published on the
next relay pass (after the request, at API startup, and at the end of every
remediation job). RQ job ids equal remediation ids and the worker claims runs
with a lease, so publishing the same row twice never runs the work twice.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RemediationOutbox
from app.models.base import utcnow
from app.services import queueing

log = logging.getLogger("routes.outbox")
MAX_PUBLISH_ATTEMPTS = 10


def add(db: Session, *, remediation_id: uuid.UUID, job_kind: str, dedupe_key: str, payload: dict) -> None:
    """Stage a job publication in the caller's transaction (idempotent by key)."""
    if db.scalar(select(RemediationOutbox.id).where(RemediationOutbox.dedupe_key == dedupe_key)) is not None:
        return
    db.add(RemediationOutbox(remediation_id=remediation_id, topic="enqueue_job", job_kind=job_kind,
                             job_id=str(remediation_id), payload=payload, dedupe_key=dedupe_key))
    db.flush()


def relay(db: Session, *, limit: int = 50) -> int:
    """Publish pending rows. Each row is locked (SKIP LOCKED) so concurrent
    relays never publish the same row at the same time."""
    published = 0
    rows = db.scalars(
        select(RemediationOutbox)
        .where(RemediationOutbox.status == "pending", RemediationOutbox.available_at <= utcnow())
        .order_by(RemediationOutbox.created_at).limit(limit).with_for_update(skip_locked=True)
    ).all()
    for row in rows:
        row.attempts += 1
        try:
            queueing.enqueue_job(row.job_kind, uuid.UUID(row.job_id), **row.payload)
        except Exception as exc:  # noqa: BLE001 - any broker failure is retried later
            row.last_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            if row.attempts >= MAX_PUBLISH_ATTEMPTS:
                row.status = "failed"
                log.error("outbox row %s failed permanently", row.id)
            else:
                row.available_at = utcnow() + timedelta(seconds=min(300, 5 * 2 ** row.attempts))
            continue
        row.status = "published"
        row.published_at = utcnow()
        row.last_error = None
        published += 1
    db.commit()
    return published


def relay_safely(db: Session) -> int:
    try:
        return relay(db)
    except Exception:  # noqa: BLE001 - never fail the caller because of the relay
        db.rollback()
        log.exception("outbox relay failed")
        return 0
