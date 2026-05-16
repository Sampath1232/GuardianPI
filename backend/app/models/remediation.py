"""
Guardian Pi — Remediation Action Model
Tracks defensive actions with rollback capability.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id")
    )
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    action_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # quarantine_process | block_ip | disable_service | isolate_endpoint | kill_process
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending"
    )  # pending | running | completed | rolled_back | failed
    parameters: Mapped[dict | None] = mapped_column(JSONB)  # action-specific params
    rollback_data: Mapped[dict | None] = mapped_column(JSONB)  # data needed to undo
    result_message: Mapped[str | None] = mapped_column(Text)
    is_automated: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    device = relationship("Device", back_populates="remediation_actions")
    alert = relationship("Alert", back_populates="remediation_actions")
    initiated_by_user = relationship("User", back_populates="remediation_actions")

    def __repr__(self) -> str:
        return f"<RemediationAction {self.action_type} status={self.status}>"
