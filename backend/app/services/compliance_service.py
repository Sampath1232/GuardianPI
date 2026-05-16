"""Guardian Pi — Compliance Service: HMAC-signed audit logging and GDPR support."""
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.security import sign_audit_entry
from backend.app.models.audit_log import AuditLog

logger = logging.getLogger("guardian.compliance")


class ComplianceService:
    """Creates tamper-evident audit log entries with HMAC chain."""

    @staticmethod
    async def create_audit_entry(
        db: AsyncSession,
        action: str,
        category: str = "system",
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        """Create an immutable, HMAC-signed audit log entry."""
        entry_data = json.dumps({
            "action": action,
            "category": category,
            "user_id": str(user_id) if user_id else None,
            "device_id": str(device_id) if device_id else None,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True)

        signature = sign_audit_entry(entry_data)

        log = AuditLog(
            user_id=user_id,
            device_id=device_id,
            action=action,
            category=category,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            hmac_signature=signature,
        )
        db.add(log)
        await db.flush()
        logger.info(f"Audit log: {action} [{category}]")
        return log


compliance_service = ComplianceService()
