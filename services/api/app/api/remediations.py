"""Remediation endpoints.

Restricted to SQL injection findings with a persisted code snapshot. XSS's
gate known-bad-fix library (S7) and fixed exploit-payload list (S6b) are
both still SQLi-only no-ops for XSS, so offering "Fix this" there would be
dishonest about what actually gets checked today.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.errors import ApiError, not_found
from app.models import Remediation, SecurityFinding, User
from app.schemas.remediations import RemediationOut
from app.services import queueing
from app.services.projects import owned_assessment
from routes_shared.enums import RemediationStatus

router = APIRouter(prefix="/assessments", tags=["remediations"])

SUPPORTED_RULE_PREFIXES = ("routes.sqli",)
ACTIVE_REMEDIATION_STATUSES = (RemediationStatus.PENDING, RemediationStatus.RUNNING)


def _owned_finding(db: Session, user: User, assessment_id: uuid.UUID, finding_id: uuid.UUID) -> SecurityFinding:
    a = owned_assessment(db, user, assessment_id)
    f = db.scalar(
        select(SecurityFinding).where(SecurityFinding.id == finding_id, SecurityFinding.assessment_id == a.id)
    )
    if f is None:
        raise not_found("Finding")
    return f


def _owned_remediation(db: Session, finding: SecurityFinding, remediation_id: uuid.UUID) -> Remediation:
    remediation = db.scalar(
        select(Remediation).where(Remediation.id == remediation_id, Remediation.finding_id == finding.id)
    )
    if remediation is None:
        raise not_found("Remediation")
    return remediation


@router.post("/{assessment_id}/findings/{finding_id}/remediate", response_model=RemediationOut, status_code=201)
def start_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _owned_finding(db, user, assessment_id, finding_id)
    if not finding.rule_id.startswith(SUPPORTED_RULE_PREFIXES):
        raise ApiError(422, "unsupported_finding",
                       "Automatic remediation is only available for SQL injection findings right now.")
    if not finding.snapshot:
        raise ApiError(422, "no_snapshot", "No code snapshot is available for this finding.")

    existing = db.scalar(
        select(Remediation).where(Remediation.finding_id == finding.id,
                                  Remediation.status.in_(ACTIVE_REMEDIATION_STATUSES))
    )
    if existing is not None:
        return existing

    remediation = Remediation(finding_id=finding.id, status=RemediationStatus.PENDING)
    db.add(remediation)
    db.commit()
    queueing.enqueue_job("remediate", remediation.id, finding_id=str(finding.id))
    return remediation


@router.get("/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}", response_model=RemediationOut)
def get_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, remediation_id: uuid.UUID,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    finding = _owned_finding(db, user, assessment_id, finding_id)
    return _owned_remediation(db, finding, remediation_id)


@router.post("/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}/cancel",
            response_model=RemediationOut)
def cancel_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, remediation_id: uuid.UUID,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    finding = _owned_finding(db, user, assessment_id, finding_id)
    remediation = _owned_remediation(db, finding, remediation_id)
    if remediation.status in ACTIVE_REMEDIATION_STATUSES:
        remediation.cancel_requested = True
        queueing.cancel_job("remediate", remediation.id)  # no-op if already picked up by a worker
        db.commit()
    db.refresh(remediation)
    return remediation
