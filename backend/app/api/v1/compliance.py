"""Guardian Pi — Compliance Router (Audit Logs & GDPR)"""
from __future__ import annotations
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import require_role
from backend.app.core.database import get_db
from backend.app.models.audit_log import AuditLog
from backend.app.models.user import User

router = APIRouter(prefix="/compliance", tags=["Compliance"])

@router.get("/audit-log")
async def get_audit_log(
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    action_filter: str | None = None,
):
    """Get immutable audit log entries (admin only)."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action_filter:
        query = query.where(AuditLog.action == action_filter)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    result = await db.execute(query.offset((page - 1) * page_size).limit(page_size))
    logs = result.scalars().all()
    return {"logs": [{"id": str(l.id), "action": l.action, "category": l.category,
        "details": l.details, "ip_address": l.ip_address, "hmac_signature": l.hmac_signature,
        "created_at": l.created_at.isoformat()} for l in logs], "total": total, "page": page}

@router.get("/gdpr-export/{device_id}")
async def gdpr_export(
    device_id: UUID,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    """Export all data associated with a device (GDPR compliance)."""
    from backend.app.models.device import Device
    from backend.app.models.alert import Alert
    from backend.app.models.scan_result import ScanResult
    device = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if not device:
        return {"error": "Device not found"}
    alerts = (await db.execute(select(Alert).where(Alert.device_id == device_id))).scalars().all()
    scans = (await db.execute(select(ScanResult).where(ScanResult.device_id == device_id))).scalars().all()
    return {
        "device": {"id": str(device.id), "hostname": device.hostname, "os_type": device.os_type,
            "registered_at": device.registered_at.isoformat()},
        "alerts_count": len(alerts),
        "scans_count": len(scans),
        "export_format": "JSON",
        "gdpr_note": "This export contains all personally identifiable data associated with this device.",
    }
