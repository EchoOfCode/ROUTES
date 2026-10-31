"""Repository functions over the CLI database. The assessment state machine
mirrors the web stack and uses the same rules (``routes_core.status``)."""

from __future__ import annotations

import os
import re
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from routes_core import status as rules
from routes_core.mapping import DiscoveryRecords, SourceRecords
from routes_storage.models import (
    ACTIVE, Assessment, AssessmentStep, Endpoint, Finding, Page, Project, SourceResultRow, Technology, as_utc, utcnow,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STALE_AFTER = timedelta(minutes=3)
_SLUG_RE = re.compile(r"[^a-z0-9-]+")


class StorageError(ValueError):
    """User-facing storage problem (duplicate name, active assessment, unknown project)."""


def slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")[:60]
    return slug or "project"


# ----------------------------------------------------------------- projects
def create_project(db: Session, *, name: str, display_name: str | None = None, website_url: str | None = None,
                   hostname: str | None = None, source_kind: str | None = None, source_location: str | None = None,
                   source_ref: str | None = None, source_private: bool = False, registered: bool = True,
                   authorised: bool = False) -> Project:
    slug = slugify(name)
    if db.scalar(select(Project).where(Project.name == slug)) is not None:
        raise StorageError(f"A project named '{slug}' already exists.")
    p = Project(name=slug, display_name=(display_name or name)[:120], website_url=website_url, hostname=hostname,
                source_kind=source_kind, source_location=source_location, source_ref=source_ref,
                source_private=source_private, registered=registered,
                authorised_at=utcnow() if authorised and website_url else None)
    db.add(p)
    db.commit()
    return p


def unique_name(db: Session, base: str) -> str:
    slug, n = slugify(base), 2
    candidate = slug
    while db.scalar(select(Project.id).where(Project.name == candidate)) is not None:
        candidate = f"{slug}-{n}"
        n += 1
    return candidate


def find_project(db: Session, ref: str) -> Project | None:
    ref = ref.strip()
    if not ref:
        return None
    found = db.scalar(select(Project).where(Project.name == slugify(ref)))
    if found is None and len(ref) >= 6:
        matches = list(db.scalars(select(Project).where(Project.id.startswith(ref)).limit(2)))
        found = matches[0] if len(matches) == 1 else None
    return found


def project_for_target(db: Session, *, hostname: str | None, source_location: str | None) -> Project | None:
    """Reuse the project that already describes this website or source."""
    q = select(Project)
    if hostname:
        q = q.where(Project.hostname == hostname)
    elif source_location:
        q = q.where(Project.source_location == source_location, Project.hostname.is_(None))
    else:
        return None
    return db.scalars(q.order_by(Project.registered.desc(), Project.created_at)).first()


def list_projects(db: Session) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.registered.desc(), Project.updated_at.desc())))


def delete_project(db: Session, project: Project) -> None:
    if active_assessment(db, project.id) is not None:
        raise StorageError("This project has an assessment in progress.")
    db.delete(project)
    db.commit()


# -------------------------------------------------------------- assessments
def active_assessment(db: Session, project_id: str) -> Assessment | None:
    return db.scalar(select(Assessment).where(Assessment.project_id == project_id, Assessment.status.in_(ACTIVE)))


def start_assessment(db: Session, project: Project, *, target_url: str | None, source_kind: str | None,
                     source_label: str | None, steps: list[str]) -> Assessment:
    reconcile(db)
    a = Assessment(project_id=project.id, status="queued", target_url=target_url, source_kind=source_kind,
                   source_label=source_label, summary={}, runner_pid=os.getpid(), heartbeat_at=utcnow(),
                   started_at=utcnow())
    a.steps = [AssessmentStep(kind=k, position=i, status="queued", stages_completed=[], details={})
               for i, k in enumerate(steps)]
    db.add(a)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise StorageError("An assessment for this project is already in progress.") from exc
    project.updated_at = utcnow()
    db.commit()
    return a


def step(assessment: Assessment, kind: str) -> AssessmentStep:
    return next(s for s in assessment.steps if s.kind == kind)


def heartbeat(db: Session, assessment: Assessment, *, status: str | None = None) -> None:
    assessment.heartbeat_at = utcnow()
    if status:
        assessment.status = status
    db.commit()


def reconcile(db: Session) -> int:
    """Fail assessments whose runner process stopped (crash, terminal closed)."""
    cutoff = utcnow() - STALE_AFTER
    stale = 0
    for a in db.scalars(select(Assessment).where(Assessment.status.in_(ACTIVE))):
        hb = as_utc(a.heartbeat_at)
        if hb is None or hb < cutoff:
            a.status, a.error, a.finished_at = "failed", "Interrupted: the ROUTES process running it stopped.", utcnow()
            for s in a.steps:
                if s.status in ("queued", "running"):
                    s.status, s.error, s.finished_at = "failed", "Interrupted.", utcnow()
            stale += 1
    if stale:
        db.commit()
    return stale


def save_discovery(db: Session, assessment: Assessment, records: DiscoveryRecords) -> None:
    db.execute(delete(Page).where(Page.assessment_id == assessment.id))
    db.execute(delete(Technology).where(Technology.assessment_id == assessment.id, Technology.source == "website"))
    db.execute(delete(Endpoint).where(Endpoint.assessment_id == assessment.id, Endpoint.origin != "source_route"))
    for p in records.pages:
        db.add(Page(assessment_id=assessment.id, **p))
    for e in records.endpoints:
        db.add(Endpoint(assessment_id=assessment.id, **e))
    for t in records.technologies:
        db.add(Technology(assessment_id=assessment.id, **t))
    assessment.manifest_detected = records.manifest_detected
    assessment.manifest_data = records.manifest_data
    assessment.summary = {**(assessment.summary or {}), **records.summary}
    db.commit()


def save_source(db: Session, assessment: Assessment, records: SourceRecords) -> None:
    db.execute(delete(SourceResultRow).where(SourceResultRow.assessment_id == assessment.id))
    db.execute(delete(Finding).where(Finding.assessment_id == assessment.id))
    db.execute(delete(Technology).where(Technology.assessment_id == assessment.id, Technology.source == "repository"))
    db.execute(delete(Endpoint).where(Endpoint.assessment_id == assessment.id, Endpoint.origin == "source_route"))
    db.add(SourceResultRow(assessment_id=assessment.id, **records.analysis))
    ordered = sorted(records.findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"] or "", f["line"] or 0))
    for i, f in enumerate(ordered, start=1):
        db.add(Finding(assessment_id=assessment.id, seq=i, **f))
    for t in records.technologies:
        db.add(Technology(assessment_id=assessment.id, **t))
    for e in records.endpoints:
        db.add(Endpoint(assessment_id=assessment.id, **e))
    assessment.summary = {**(assessment.summary or {}), **records.summary}
    db.commit()


def finalize(db: Session, assessment: Assessment) -> Assessment:
    """Set the honest final status, correlate endpoints if confirmed, apply retention."""
    db.refresh(assessment)
    matched = 0
    if assessment.project.match_status == "confirmed":
        matched = rules.correlate(list(assessment.endpoints))
    final, error = rules.compute_final_status(assessment.steps, cancel_requested=assessment.cancel_requested)
    assessment.status, assessment.error, assessment.finished_at = final, error, utcnow()
    assessment.summary = {**(assessment.summary or {}), "correlated_endpoints": matched}
    assessment.runner_pid = None
    db.commit()
    apply_retention(db, assessment.project_id)
    return assessment


def apply_retention(db: Session, project_id: str, limit: int = rules.HISTORY_LIMIT) -> list[str]:
    rows = list(db.scalars(select(Assessment).where(Assessment.project_id == project_id)
                           .order_by(Assessment.created_at.desc())))
    victims = rules.retention_victims(rows, limit)
    ids = [a.id for a in victims]
    for a in victims:
        db.delete(a)
    if victims:
        db.commit()
    return ids


# ------------------------------------------------------------------ queries
def history(db: Session, project: Project | None = None, limit: int = 50) -> list[Assessment]:
    q = select(Assessment).order_by(Assessment.created_at.desc()).limit(limit)
    if project is not None:
        q = q.where(Assessment.project_id == project.id)
    return list(db.scalars(q))


def get_assessment(db: Session, ref: str) -> Assessment | None:
    ref = ref.strip()
    if len(ref) < 6:
        return None
    return db.scalar(select(Assessment).where(Assessment.id.startswith(ref)))


def latest_finished(db: Session, project: Project | None = None) -> Assessment | None:
    q = select(Assessment).where(Assessment.status.not_in(ACTIVE)).order_by(Assessment.created_at.desc())
    if project is not None:
        q = q.where(Assessment.project_id == project.id)
    return db.scalars(q).first()


def findings_for(db: Session, assessment: Assessment, *, severity: str | None = None) -> list[Finding]:
    q = select(Finding).where(Finding.assessment_id == assessment.id).order_by(Finding.seq)
    if severity:
        q = q.where(Finding.severity == severity)
    return list(db.scalars(q))
