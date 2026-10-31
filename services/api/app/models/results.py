import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, TimestampMixin


def _assessment_fk():
    return mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )


class DiscoveredPage(IdMixin, TimestampMixin, Base):
    __tablename__ = "discovered_pages"

    assessment_id: Mapped[uuid.UUID] = _assessment_fk()
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(500))
    content_type: Mapped[str | None] = mapped_column(String(200))
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rendered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_registration: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    links_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    forms_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scripts_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String(500))

    __table_args__ = (UniqueConstraint("assessment_id", "url", name="uq_discovered_pages_assessment_url"),)


class DiscoveredEndpoint(IdMixin, TimestampMixin, Base):
    __tablename__ = "discovered_endpoints"

    assessment_id: Mapped[uuid.UUID] = _assessment_fk()
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    parameters: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    evidence: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    page_url: Mapped[str | None] = mapped_column(String(2048))

    __table_args__ = (Index("ix_discovered_endpoints_assessment_origin", "assessment_id", "origin"),)


class DetectedTechnology(IdMixin, TimestampMixin, Base):
    __tablename__ = "detected_technologies"

    assessment_id: Mapped[uuid.UUID] = _assessment_fk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="website")
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("assessment_id", "name", "source", name="uq_detected_technologies_assessment_name"),
    )


class SourceAnalysisResult(IdMixin, TimestampMixin, Base):
    __tablename__ = "source_analysis_results"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    support_status: Mapped[str] = mapped_column(String(16), nullable=False)
    support_reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    framework: Mapped[str] = mapped_column(String(100), nullable=False, default="Unknown")
    runtime: Mapped[str] = mapped_column(String(100), nullable=False, default="Unknown")
    profile: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    routes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    db_interactions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    input_sources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    config_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    env_var_names: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    match_evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    warnings: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class SecurityFinding(IdMixin, TimestampMixin, Base):
    __tablename__ = "security_findings"

    assessment_id: Mapped[uuid.UUID] = _assessment_fk()
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="potential")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    file: Mapped[str | None] = mapped_column(String(2048))
    line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    endpoint: Mapped[str | None] = mapped_column(String(2048))
    method: Mapped[str | None] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    plain_description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    technical_details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("assessment_id", "fingerprint", name="uq_security_findings_assessment_fingerprint"),
        Index("ix_security_findings_severity", "assessment_id", "severity"),
    )
