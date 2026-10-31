import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin

ACTIVE_STATUS_SQL = "status IN ('queued','running','discovering','analysing')"


class Assessment(IdMixin, TimestampMixin, Base):
    __tablename__ = "assessments"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    source_kind: Mapped[str | None] = mapped_column(String(32))
    source_label: Mapped[str | None] = mapped_column(String(300))
    manifest_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    manifest_data: Mapped[dict | None] = mapped_column(JSONB)
    discovery_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project = relationship("Project", back_populates="assessments")
    jobs = relationship(
        "AssessmentJob", back_populates="assessment", cascade="all, delete-orphan", passive_deletes=True,
        order_by="AssessmentJob.created_at",
    )

    __table_args__ = (
        Index("ix_assessments_project_created", "project_id", "created_at"),
        Index("ix_assessments_status", "status"),
        # At most one active assessment per project: repeated frontend requests
        # can never start the same work twice.
        Index(
            "uq_assessments_one_active_per_project",
            "project_id",
            unique=True,
            postgresql_where=text(ACTIVE_STATUS_SQL),
        ),
    )


class AssessmentJob(IdMixin, TimestampMixin, Base):
    __tablename__ = "assessment_jobs"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    stage: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(String(500))
    stages_completed: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assessment = relationship("Assessment", back_populates="jobs")

    __table_args__ = (UniqueConstraint("assessment_id", "kind", name="uq_assessment_jobs_assessment_kind"),)
