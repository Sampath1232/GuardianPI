"""
Guardian Pi — Device Model
Registered endpoint devices with platform details and health status.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # windows | linux | macos | android | ios | raspberrypi
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    architecture: Mapped[str] = mapped_column(String(50), nullable=False)  # x86_64 | arm64 | armv7l
    ram_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    cpu_cores: Mapped[int] = mapped_column(Integer, nullable=False)
    cpu_model: Mapped[str | None] = mapped_column(String(255))
    storage_gb: Mapped[int | None] = mapped_column(Integer)
    agent_version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="online", index=True
    )  # online | offline | compromised | quarantined
    is_rooted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_virtual: Mapped[bool] = mapped_column(Boolean, default=False)
    is_compatible: Mapped[bool] = mapped_column(Boolean, default=True)

    # Network identity
    ip_address: Mapped[str | None] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(17))

    # Agent auth
    api_key_hash: Mapped[str | None] = mapped_column(String(255))

    # Timestamps
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Flexible metadata
    metadata_json: Mapped[dict | None] = mapped_column(JSONB)

    # Relationships
    alerts = relationship("Alert", back_populates="device", lazy="dynamic")
    scan_results = relationship("ScanResult", back_populates="device", lazy="dynamic")
    remediation_actions = relationship(
        "RemediationAction", back_populates="device", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<Device {self.hostname} os={self.os_type} status={self.status}>"
