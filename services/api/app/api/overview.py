from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from routes_shared.enums import ACTIVE_ASSESSMENT_STATUSES

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models import Assessment, Project, SecurityFinding, User
from app.schemas.assessments import FindingOut, FindingWithContext, Overview
from app.services.projects import serialize_assessments

router = APIRouter(tags=["overview"])


def _latest_assessment_ids(db: Session, user: User) -> list:
    """Findings shown as 'current' come from each project's latest finished assessment."""
    ranked = (
        select(
            Assessment.id,
            func.row_number().over(partition_by=Assessment.project_id, order_by=Assessment.created_at.desc()).label("rn"),
        )
        .join(Project, Project.id == Assessment.project_id)
        .where(Project.owner_id == user.id, Assessment.status.not_in(ACTIVE_ASSESSMENT_STATUSES))
        .subquery()
    )
    return list(db.scalars(select(ranked.c.id).where(ranked.c.rn == 1)).all())


def _with_context(db: Session, findings: list[SecurityFinding]) -> list[FindingWithContext]:
    if not findings:
        return []
    rows = db.execute(
        select(Assessment.id, Project.id, Project.name)
        .join(Project, Project.id == Assessment.project_id)
        .where(Assessment.id.in_({f.assessment_id for f in findings}))
    ).all()
    ctx = {r[0]: (r[1], r[2]) for r in rows}
    return [
        FindingWithContext(
            **FindingOut.model_validate(f).model_dump(),
            project_id=ctx[f.assessment_id][0],
            project_name=ctx[f.assessment_id][1],
        )
        for f in findings
    ]


@router.get("/overview", response_model=Overview)
def overview(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.scalar(select(func.count()).select_from(Project).where(Project.owner_id == user.id)) or 0
    base = select(Assessment).join(Project, Project.id == Assessment.project_id).where(Project.owner_id == user.id)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    active = db.scalar(
        select(func.count()).select_from(base.where(Assessment.status.in_(ACTIVE_ASSESSMENT_STATUSES)).subquery())
    ) or 0
    recent = db.scalars(base.order_by(Assessment.created_at.desc()).limit(6)).all()

    latest_ids = _latest_assessment_ids(db, user)
    severity_counts: dict[str, int] = {}
    recent_findings: list[SecurityFinding] = []
    if latest_ids:
        for sev, n in db.execute(
            select(SecurityFinding.severity, func.count())
            .where(SecurityFinding.assessment_id.in_(latest_ids))
            .group_by(SecurityFinding.severity)
        ).all():
            severity_counts[sev] = n
        recent_findings = list(
            db.scalars(
                select(SecurityFinding)
                .where(SecurityFinding.assessment_id.in_(latest_ids))
                .order_by(SecurityFinding.created_at.desc())
                .limit(8)
            ).all()
        )
    return Overview(
        projects=projects,
        assessments=total,
        active_assessments=active,
        open_findings=sum(severity_counts.values()),
        severity_counts=severity_counts,
        recent_assessments=serialize_assessments(db, list(recent)),
        recent_findings=_with_context(db, recent_findings),
    )


@router.get("/findings", response_model=list[FindingWithContext])
def all_findings(
    severity: str | None = Query(default=None, max_length=16),
    type: str | None = Query(default=None, max_length=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    latest_ids = _latest_assessment_ids(db, user)
    if not latest_ids:
        return []
    stmt = select(SecurityFinding).where(SecurityFinding.assessment_id.in_(latest_ids))
    if severity:
        stmt = stmt.where(SecurityFinding.severity == severity)
    if type:
        stmt = stmt.where(SecurityFinding.type == type)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = sorted(db.scalars(stmt).all(), key=lambda f: (order.get(f.severity, 9), f.file or "", f.line or 0))
    return _with_context(db, rows)
