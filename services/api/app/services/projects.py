"""Ownership-scoped data access. Every project/assessment lookup goes through
these helpers so cross-user access is impossible by construction."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import not_found
from app.models import (
    Assessment,
    DetectedTechnology,
    DiscoveredEndpoint,
    DiscoveredPage,
    Project,
    SecurityFinding,
    User,
)
from app.schemas.assessments import AssessmentCounts, AssessmentOut, JobOut
from app.schemas.projects import AssessmentBrief, IntegrationOut, ProjectOut


def owned_project(db: Session, user: User, project_id: uuid.UUID, *, lock: bool = False) -> Project:
    stmt = select(Project).where(Project.id == project_id, Project.owner_id == user.id)
    if lock:
        stmt = stmt.with_for_update()
    project = db.scalar(stmt)
    if project is None:
        raise not_found("Project")
    return project


def owned_assessment(db: Session, user: User, assessment_id: uuid.UUID) -> Assessment:
    assessment = db.scalar(
        select(Assessment)
        .join(Project, Project.id == Assessment.project_id)
        .where(Assessment.id == assessment_id, Project.owner_id == user.id)
    )
    if assessment is None:
        raise not_found("Assessment")
    return assessment


def _count(db: Session, model, assessment_ids: list[uuid.UUID], *extra) -> dict[uuid.UUID, int]:
    if not assessment_ids:
        return {}
    rows = db.execute(
        select(model.assessment_id, func.count())
        .where(model.assessment_id.in_(assessment_ids), *extra)
        .group_by(model.assessment_id)
    ).all()
    return {r[0]: r[1] for r in rows}


def serialize_assessments(db: Session, assessments: list[Assessment]) -> list[AssessmentOut]:
    ids = [a.id for a in assessments]
    pages = _count(db, DiscoveredPage, ids)
    endpoints = _count(db, DiscoveredEndpoint, ids, DiscoveredEndpoint.origin != "form")
    forms = _count(db, DiscoveredEndpoint, ids, DiscoveredEndpoint.origin == "form")
    techs = _count(db, DetectedTechnology, ids)
    sev: dict[uuid.UUID, dict[str, int]] = {}
    if ids:
        for aid, severity, n in db.execute(
            select(SecurityFinding.assessment_id, SecurityFinding.severity, func.count())
            .where(SecurityFinding.assessment_id.in_(ids))
            .group_by(SecurityFinding.assessment_id, SecurityFinding.severity)
        ).all():
            sev.setdefault(aid, {})[severity] = n
    names = dict(
        db.execute(select(Project.id, Project.name).where(Project.id.in_({a.project_id for a in assessments}))).all()
    ) if assessments else {}
    out = []
    for a in assessments:
        s = sev.get(a.id, {})
        out.append(
            AssessmentOut(
                id=a.id,
                project_id=a.project_id,
                project_name=names.get(a.project_id, ""),
                status=a.status,
                target_url=a.target_url,
                source_kind=a.source_kind,
                source_label=a.source_label,
                manifest_detected=a.manifest_detected,
                manifest_data=a.manifest_data,
                discovery_summary=a.discovery_summary or {},
                error=a.error,
                created_at=a.created_at,
                started_at=a.started_at,
                finished_at=a.finished_at,
                jobs=[JobOut.model_validate(j) for j in a.jobs],
                counts=AssessmentCounts(
                    pages=pages.get(a.id, 0),
                    endpoints=endpoints.get(a.id, 0),
                    forms=forms.get(a.id, 0),
                    technologies=techs.get(a.id, 0),
                    findings=sum(s.values()),
                ),
                severity_counts=s,
            )
        )
    return out


def serialize_projects(db: Session, projects: list[Project]) -> list[ProjectOut]:
    out = []
    for p in projects:
        latest = p.assessments[0] if p.assessments else None
        brief = None
        framework = None
        if latest is not None:
            n = db.scalar(select(func.count()).where(SecurityFinding.assessment_id == latest.id)) or 0
            brief = AssessmentBrief(
                id=latest.id, status=latest.status, created_at=latest.created_at,
                finished_at=latest.finished_at, findings_count=n,
            )
            framework = (latest.discovery_summary or {}).get("stack", {}).get("framework")
            if framework in (None, "Unknown"):
                framework = (latest.discovery_summary or {}).get("source_framework") or framework
        integration = p.integrations[0] if p.integrations else None
        out.append(
            ProjectOut(
                id=p.id,
                name=p.name,
                website_url=p.website_url,
                hostname=p.hostname,
                authorised_at=p.authorised_at,
                authorisation_statement=p.authorisation_statement,
                created_at=p.created_at,
                integration=IntegrationOut.model_validate(integration) if integration else None,
                latest_assessment=brief,
                framework=framework,
            )
        )
    return out
