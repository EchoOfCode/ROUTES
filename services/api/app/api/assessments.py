import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.errors import ApiError
from app.models import (
    Assessment,
    DetectedTechnology,
    DiscoveredEndpoint,
    DiscoveredPage,
    Project,
    SecurityFinding,
    SourceAnalysisResult,
    User,
)
from app.schemas.assessments import (
    AssessmentOut,
    EndpointOut,
    FindingOut,
    PageOut,
    SourceResultOut,
    TechnologyOut,
)
from app.services import assessments as assessment_service
from app.services.projects import owned_assessment, serialize_assessments

router = APIRouter(prefix="/assessments", tags=["assessments"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@router.get("", response_model=list[AssessmentOut])
def list_assessments(
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(Assessment)
        .join(Project, Project.id == Assessment.project_id)
        .where(Project.owner_id == user.id)
        .order_by(Assessment.created_at.desc())
        .limit(limit)
    ).all()
    return serialize_assessments(db, list(rows))


@router.get("/{assessment_id}", response_model=AssessmentOut)
def get_assessment(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return serialize_assessments(db, [owned_assessment(db, user, assessment_id)])[0]


@router.post("/{assessment_id}/cancel", response_model=AssessmentOut)
def cancel(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    assessment = owned_assessment(db, user, assessment_id)
    assessment_service.cancel_assessment(db, assessment)
    db.refresh(assessment)
    return serialize_assessments(db, [assessment])[0]


@router.get("/{assessment_id}/pages", response_model=list[PageOut])
def pages(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = owned_assessment(db, user, assessment_id)
    return db.scalars(
        select(DiscoveredPage).where(DiscoveredPage.assessment_id == a.id).order_by(DiscoveredPage.depth, DiscoveredPage.url)
    ).all()


@router.get("/{assessment_id}/endpoints", response_model=list[EndpointOut])
def endpoints(
    assessment_id: uuid.UUID,
    origin: str | None = Query(default=None, max_length=32),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    a = owned_assessment(db, user, assessment_id)
    stmt = select(DiscoveredEndpoint).where(DiscoveredEndpoint.assessment_id == a.id)
    if origin:
        stmt = stmt.where(DiscoveredEndpoint.origin == origin)
    return db.scalars(stmt.order_by(DiscoveredEndpoint.path, DiscoveredEndpoint.method)).all()


@router.get("/{assessment_id}/technologies", response_model=list[TechnologyOut])
def technologies(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = owned_assessment(db, user, assessment_id)
    return db.scalars(
        select(DetectedTechnology).where(DetectedTechnology.assessment_id == a.id).order_by(
            DetectedTechnology.category, DetectedTechnology.name
        )
    ).all()


@router.get("/{assessment_id}/source", response_model=SourceResultOut | None)
def source(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = owned_assessment(db, user, assessment_id)
    return db.scalar(select(SourceAnalysisResult).where(SourceAnalysisResult.assessment_id == a.id))


@router.get("/{assessment_id}/findings", response_model=list[FindingOut])
def findings(assessment_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = owned_assessment(db, user, assessment_id)
    rows = db.scalars(select(SecurityFinding).where(SecurityFinding.assessment_id == a.id)).all()
    return sorted(rows, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file or "", f.line or 0))


@router.get("/{assessment_id}/findings/{finding_id}", response_model=FindingOut)
def finding(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    a = owned_assessment(db, user, assessment_id)
    f = db.scalar(select(SecurityFinding).where(SecurityFinding.id == finding_id, SecurityFinding.assessment_id == a.id))
    if f is None:
        raise ApiError(404, "not_found", "Finding not found.")
    return f
