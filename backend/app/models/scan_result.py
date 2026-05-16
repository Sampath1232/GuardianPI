"""
Guardian Pi — Scan Result Model
File and process scan results with detailed findings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True
    )
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # file | process | network | rootkit | integrity
    target: Mapped[str | None] = mapped_column(String(1000))  # filepath or process name
    result: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # clean | suspicious | malicious
    risk_score: Mapped[int | None] = mapped_column()  # 0-100
    sha256_hash: Mapped[str | None] = mapped_column(String(64))
    findings: Mapped[dict | None] = mapped_column(JSONB)

    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    device = relationship("Device", back_populates="scan_results")

    def __repr__(self) -> str:
        return f"<ScanResult {self.scan_type}: {self.result}>"
