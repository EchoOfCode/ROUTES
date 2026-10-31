"""SQLite schema for the ROUTES CLI.

Mirrors the web stack's tables (docs/DATABASE.md) with portable types. Only
metadata and redacted evidence are stored: never HTML, source files,
passwords, tokens or secret values found in code.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

ACTIVE = ("queued", "running", "discovering", "analysing")


def _id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; every stored time is UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


class Base(DeclarativeBase):
    pass


class Timestamps:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Project(Timestamps, Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(80), unique=True)          # slug used on the command line
    display_name: Mapped[str] = mapped_column(String(120))
    registered: Mapped[bool] = mapped_column(Boolean, default=True)     # False for one-off assessments
    website_url: Mapped[str | None] = mapped_column(String(2048))
    hostname: Mapped[str | None] = mapped_column(String(255))
    authorised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_kind: Mapped[str | None] = mapped_column(String(16))          # github | zip | directory
    source_location: Mapped[str | None] = mapped_column(String(2048))    # repo URL or local path (never a token)
    source_ref: Mapped[str | None] = mapped_column(String(255))
    source_private: Mapped[bool] = mapped_column(Boolean, default=False)
    match_status: Mapped[str] = mapped_column(String(16), default="pending")
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="project", cascade="all, delete-orphan",
                                                           passive_deletes=True, order_by="Assessment.created_at.desc()")


class Assessment(Timestamps, Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    target_url: Mapped[str | None] = mapped_column(String(2048))
    source_kind: Mapped[str | None] = mapped_column(String(16))
    source_label: Mapped[str | None] = mapped_column(String(300))
    manifest_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    manifest_data: Mapped[dict | None] = mapped_column(JSON)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    runner_pid: Mapped[int | None] = mapped_column(Integer)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="assessments")
    steps: Mapped[list["AssessmentStep"]] = relationship(cascade="all, delete-orphan", passive_deletes=True,
                                                         order_by="AssessmentStep.position")
    pages: Mapped[list["Page"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    endpoints: Mapped[list["Endpoint"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    technologies: Mapped[list["Technology"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    findings: Mapped[list["Finding"]] = relationship(cascade="all, delete-orphan", passive_deletes=True,
                                                     order_by="Finding.seq")
    source_result: Mapped["SourceResultRow | None"] = relationship(cascade="all, delete-orphan", passive_deletes=True,
                                                                   uselist=False)

    __table_args__ = (
        Index("ix_assessments_project_created", "project_id", "created_at"),
        # At most one active assessment per project.
        Index("uq_assessments_one_active", "project_id", unique=True,
              sqlite_where=text("status IN ('queued','running','discovering','analysing')")),
    )


class AssessmentStep(Timestamps, Base):
    __tablename__ = "assessment_steps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))        # discovery | source
    position: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    stage: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(String(500))
    stages_completed: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("assessment_id", "kind"),)


class Page(Base):
    __tablename__ = "pages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(500))
    content_type: Mapped[str | None] = mapped_column(String(200))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    rendered: Mapped[bool] = mapped_column(Boolean, default=False)
    is_login: Mapped[bool] = mapped_column(Boolean, default=False)
    is_registration: Mapped[bool] = mapped_column(Boolean, default=False)
    links_count: Mapped[int] = mapped_column(Integer, default=0)
    forms_count: Mapped[int] = mapped_column(Integer, default=0)
    scripts_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(500))


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(String(2048))
    path: Mapped[str] = mapped_column(String(2048))
    origin: Mapped[str] = mapped_column(String(32))
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[str] = mapped_column(String(500), default="")
    page_url: Mapped[str | None] = mapped_column(String(2048))


class Technology(Base):
    __tablename__ = "technologies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(200))
    confidence: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16))     # website | repository
    evidence: Mapped[list] = mapped_column(JSON, default=list)


class SourceResultRow(Base):
    __tablename__ = "source_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), unique=True)
    source_kind: Mapped[str] = mapped_column(String(32))
    support_status: Mapped[str] = mapped_column(String(16))
    support_reason: Mapped[str] = mapped_column(Text, default="")
    framework: Mapped[str] = mapped_column(String(200))
    runtime: Mapped[str] = mapped_column(String(200))
    profile: Mapped[dict] = mapped_column(JSON, default=dict)
    routes: Mapped[list] = mapped_column(JSON, default=list)
    db_interactions: Mapped[list] = mapped_column(JSON, default=list)
    input_sources: Mapped[list] = mapped_column(JSON, default=list)
    config_refs: Mapped[list] = mapped_column(JSON, default=list)
    env_var_names: Mapped[list] = mapped_column(JSON, default=list)
    match_evidence: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)          # 1-based number shown to the developer
    type: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(500))
    file: Mapped[str | None] = mapped_column(String(2048))
    line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048))
    method: Mapped[str | None] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(200))
    plain_description: Mapped[str] = mapped_column(Text)
    evidence_summary: Mapped[str] = mapped_column(Text)
    technical_details: Mapped[dict] = mapped_column(JSON, default=dict)
    recommendation: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    __table_args__ = (UniqueConstraint("assessment_id", "fingerprint"), UniqueConstraint("assessment_id", "seq"),
                      Index("ix_findings_assessment_severity", "assessment_id", "severity"))
