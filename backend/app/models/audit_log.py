"""
Guardian Pi — Audit Log Model
Immutable audit entries with HMAC signatures for tamper detection.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), index=True
    )
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # login | device_register | alert_ack | remediation_exec | config_change
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, default="system"
    )  # auth | device | alert | remediation | admin | system
    details: Mapped[dict | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    hmac_signature: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # SHA-256 HMAC for integrity

    # Previous entry hash for chain integrity (append-only log)
    previous_hash: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} at {self.created_at}>"
