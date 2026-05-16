"""
Guardian Pi — Policies Router
Security policy management and enforcement for device fleet.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import get_current_user, require_role
from backend.app.core.database import Base, get_db
from backend.app.models.user import User

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

router = APIRouter(prefix="/policies", tags=["Policies"])


# ── Policy Model (inline for self-contained module) ──────────────
class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    # Rule definition as JSON: conditions, actions, thresholds
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Which OS types this policy applies to
    target_os: Mapped[list] = mapped_column(JSONB, default=["windows", "linux", "macos", "raspberrypi"])
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# ── Schemas ──────────────────────────────────────────────────────
class PolicyCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    category: str = Field(max_length=100)
    rules: dict
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    is_enabled: bool = True
    target_os: list[str] = ["windows", "linux", "macos", "raspberrypi"]

class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None
    category: str
    rules: dict
    severity: str
    is_enabled: bool
    target_os: list
    created_at: datetime
    model_config = {"from_attributes": True}

class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rules: dict | None = None
    severity: str | None = None
    is_enabled: bool | None = None
    target_os: list[str] | None = None


# ── Endpoints ────────────────────────────────────────────────────
@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    request: PolicyCreate,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    """Create a new security policy (admin only)."""
    policy = Policy(
        name=request.name, description=request.description,
        category=request.category, rules=request.rules,
        severity=request.severity, is_enabled=request.is_enabled,
        target_os=request.target_os, created_by=current_user.id,
    )
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    return PolicyResponse.model_validate(policy)


@router.get("")
async def list_policies(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    enabled_only: bool = False,
):
    """List all security policies."""
    query = select(Policy)
    if enabled_only:
        query = query.where(Policy.is_enabled == True)
    result = await db.execute(query)
    policies = result.scalars().all()
    return {"policies": [PolicyResponse.model_validate(p) for p in policies], "total": len(policies)}


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    return PolicyResponse.model_validate(policy)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID,
    request: PolicyUpdate,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)
    await db.flush()
    await db.refresh(policy)
    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    await db.delete(policy)


@router.get("/agent/{os_type}")
async def get_agent_policies(
    os_type: str,
    db: AsyncSession = Depends(get_db),
):
    """Get active policies for a specific OS type (called by agents)."""
    result = await db.execute(
        select(Policy).where(Policy.is_enabled == True)
    )
    policies = result.scalars().all()
    # Filter to policies targeting this OS
    matching = [p for p in policies if os_type in (p.target_os or [])]
    return {"policies": [{"id": str(p.id), "name": p.name, "rules": p.rules, "severity": p.severity} for p in matching]}
