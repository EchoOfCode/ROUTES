import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin


class Remediation(IdMixin, TimestampMixin, Base):
    __tablename__ = "remediations"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    finding_status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    iterations = relationship(
        "RemediationIteration", back_populates="remediation", cascade="all, delete-orphan",
        passive_deletes=True, order_by="RemediationIteration.iteration_no",
    )


class RemediationIteration(IdMixin, TimestampMixin, Base):
    __tablename__ = "remediation_iterations"

    remediation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    iteration_no: Mapped[int] = mapped_column(Integer, nullable=False)
    round_no: Mapped[int | None] = mapped_column(Integer)
    batch_id: Mapped[str | None] = mapped_column(String(64))
    candidate_hash: Mapped[str | None] = mapped_column(String(64))
    candidate_code: Mapped[str | None] = mapped_column(Text)
    test_results: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rescan_diff: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    failure_output: Mapped[str | None] = mapped_column(Text)

    remediation = relationship("Remediation", back_populates="iterations")

    __table_args__ = (
        UniqueConstraint("remediation_id", "iteration_no", name="uq_remediation_iterations_remediation_no"),
    )
