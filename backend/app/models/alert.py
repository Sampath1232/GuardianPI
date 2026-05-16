"""
Guardian Pi — Alert Model
Security alerts with severity levels, evidence, and lifecycle tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # critical | high | medium | low | info
    category: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # malware | intrusion | anomaly | policy_violation | system
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open", index=True
    )  # open | acknowledged | resolved | false_positive
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    source: Mapped[str | None] = mapped_column(String(100))  # agent | guardduty | manual
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    mitre_technique: Mapped[str | None] = mapped_column(String(100))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    device = relationship("Device", back_populates="alerts")
    remediation_actions = relationship(
        "RemediationAction", back_populates="alert", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<Alert {self.severity}: {self.title}>"
