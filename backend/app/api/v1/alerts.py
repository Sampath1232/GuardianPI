"""
Guardian Pi — Alerts Router
Security alert management, filtering, and statistics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import get_current_user, require_role, validate_agent_api_key
from backend.app.core.database import get_db
from backend.app.models.alert import Alert
from backend.app.models.user import User
from backend.app.schemas.alert import (
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertStats,
    AlertUpdateRequest,
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    request: AlertCreate,
    api_key: Annotated[str, Depends(validate_agent_api_key)],
    db: AsyncSession = Depends(get_db),
):
    """Create a new security alert from an agent."""
    alert = Alert(
        device_id=UUID(request.device_id),
        severity=request.severity,
        category=request.category,
        title=request.title,
        description=request.description,
        evidence=request.evidence,
        source=request.source,
        mitre_tactic=request.mitre_tactic,
        mitre_technique=request.mitre_technique,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    device_id: str | None = None,
):
    """List alerts with filtering and pagination."""
    query = select(Alert).order_by(Alert.created_at.desc())

    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if device_id:
        query = query.where(Alert.device_id == UUID(device_id))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        total=total, page=page, page_size=page_size,
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: UUID,
    request: AlertUpdateRequest,
    current_user: Annotated[User, Depends(require_role(["admin", "analyst"]))],
    db: AsyncSession = Depends(get_db),
):
    """Update alert status (acknowledge, resolve, mark false positive)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = request.status
    alert.acknowledged_by = current_user.id
    if request.status == "resolved":
        alert.resolved_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get alert statistics summary."""
    total = (await db.execute(select(func.count(Alert.id)))).scalar() or 0

    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )).scalar() or 0
        severity_counts[sev] = count

    open_count = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )).scalar() or 0
    resolved_count = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "resolved")
    )).scalar() or 0

    return AlertStats(
        total=total, open_count=open_count, resolved_count=resolved_count,
        **severity_counts,
    )
