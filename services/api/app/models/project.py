import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin


class Project(IdMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    website_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    authorised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorisation_statement: Mapped[str] = mapped_column(Text, nullable=False)

    owner = relationship("User", back_populates="projects")
    integrations = relationship(
        "ProjectIntegration", back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    assessments = relationship(
        "Assessment",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="desc(Assessment.created_at)",
    )

    __table_args__ = (Index("ix_projects_owner_created", "owner_id", "created_at"),)


class ProjectIntegration(IdMixin, TimestampMixin, Base):
    """A connected source of code. Only one source integration per project.

    Never stores credentials: private-repository tokens are held only in the
    Sandbox Manager's memory for the duration of a single import.
    """

    __tablename__ = "project_integrations"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    repo_owner: Mapped[str | None] = mapped_column(String(100))
    repo_name: Mapped[str | None] = mapped_column(String(100))
    repo_ref: Mapped[str | None] = mapped_column(String(255))
    upload_filename: Mapped[str | None] = mapped_column(String(255))
    upload_size: Mapped[int | None] = mapped_column(BigInteger)
    upload_sha256: Mapped[str | None] = mapped_column(String(64))
    match_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    match_evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    match_decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project = relationship("Project", back_populates="integrations")

    __table_args__ = (UniqueConstraint("project_id", name="uq_project_integrations_project"),)
