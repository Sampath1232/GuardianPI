"""Guardian Pi — Remediation Router"""
from __future__ import annotations
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import require_role
from backend.app.core.database import get_db
from backend.app.models.remediation import RemediationAction
from backend.app.models.user import User
from backend.app.schemas.telemetry import RemediationRequest, RemediationResponse, RollbackRequest

router = APIRouter(prefix="/remediation", tags=["Remediation"])

@router.post("", response_model=RemediationResponse, status_code=201)
async def create_remediation(
    request: RemediationRequest,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    """Create a defensive remediation action (admin only)."""
    action = RemediationAction(
        device_id=UUID(request.device_id),
        alert_id=UUID(request.alert_id) if request.alert_id else None,
        initiated_by=current_user.id,
        action_type=request.action_type,
        parameters=request.parameters,
        status="pending",
    )
    db.add(action)
    await db.flush()
    await db.refresh(action)
    return RemediationResponse.model_validate(action)

@router.post("/{action_id}/rollback", response_model=RemediationResponse)
async def rollback_action(
    action_id: UUID,
    request: RollbackRequest,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    """Rollback a previously executed remediation action."""
    result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(404, "Remediation action not found")
    if action.status != "completed":
        raise HTTPException(400, "Can only rollback completed actions")
    action.status = "rolled_back"
    action.result_message = f"Rolled back: {request.reason}"
    await db.flush()
    await db.refresh(action)
    return RemediationResponse.model_validate(action)
