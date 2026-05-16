"""
Guardian Pi — Investigations Router
Incident investigation workflow with timeline tracking.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import get_current_user, require_role
from backend.app.core.database import Base, get_db
from backend.app.models.user import User

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

router = APIRouter(prefix="/investigations", tags=["Investigations"])


# ── Investigation Model ──────────────────────────────────────────
class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="open")  # open | in_progress | resolved | closed
    priority: Mapped[str] = mapped_column(String(50), default="medium")
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    # Linked alert IDs
    alert_ids: Mapped[list | None] = mapped_column(JSONB)
    device_ids: Mapped[list | None] = mapped_column(JSONB)
    # Investigation timeline entries
    timeline: Mapped[list | None] = mapped_column(JSONB, default=[])
    findings: Mapped[str | None] = mapped_column(Text)
    # MITRE ATT&CK mapping
    mitre_tactics: Mapped[list | None] = mapped_column(JSONB)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ── Schemas ──────────────────────────────────────────────────────
class InvestigationCreate(BaseModel):
    title: str = Field(max_length=500)
    description: str | None = None
    priority: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    alert_ids: list[str] | None = None
    device_ids: list[str] | None = None
    mitre_tactics: list[str] | None = None

class InvestigationResponse(BaseModel):
    id: str
    title: str
    description: str | None
    status: str
    priority: str
    assignee_id: str | None
    alert_ids: list | None
    device_ids: list | None
    timeline: list | None
    findings: str | None
    mitre_tactics: list | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    model_config = {"from_attributes": True}

class TimelineEntry(BaseModel):
    action: str  # note | evidence | remediation | escalation
    content: str
    metadata: dict | None = None


# ── Endpoints ────────────────────────────────────────────────────
@router.post("", response_model=InvestigationResponse, status_code=201)
async def create_investigation(
    request: InvestigationCreate,
    current_user: Annotated[User, Depends(require_role(["admin", "analyst"]))],
    db: AsyncSession = Depends(get_db),
):
    """Create a new investigation case."""
    inv = Investigation(
        title=request.title, description=request.description,
        priority=request.priority, alert_ids=request.alert_ids,
        device_ids=request.device_ids, mitre_tactics=request.mitre_tactics,
        created_by=current_user.id,
        timeline=[{
            "action": "created", "content": f"Investigation created by {current_user.email}",
            "timestamp": datetime.now(timezone.utc).isoformat(), "user": current_user.email,
        }],
    )
    db.add(inv)
    await db.flush()
    await db.refresh(inv)
    return InvestigationResponse.model_validate(inv)


@router.get("")
async def list_investigations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = Query(None, alias="status"),
):
    query = select(Investigation).order_by(Investigation.created_at.desc())
    if status_filter:
        query = query.where(Investigation.status == status_filter)
    result = await db.execute(query)
    investigations = result.scalars().all()
    return {"investigations": [InvestigationResponse.model_validate(i) for i in investigations], "total": len(investigations)}


@router.get("/{inv_id}", response_model=InvestigationResponse)
async def get_investigation(
    inv_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Investigation).where(Investigation.id == inv_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return InvestigationResponse.model_validate(inv)


@router.post("/{inv_id}/timeline", response_model=InvestigationResponse)
async def add_timeline_entry(
    inv_id: uuid.UUID,
    entry: TimelineEntry,
    current_user: Annotated[User, Depends(require_role(["admin", "analyst"]))],
    db: AsyncSession = Depends(get_db),
):
    """Add a timeline entry to an investigation."""
    result = await db.execute(select(Investigation).where(Investigation.id == inv_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")

    timeline = list(inv.timeline or [])
    timeline.append({
        "action": entry.action, "content": entry.content,
        "metadata": entry.metadata, "user": current_user.email,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    inv.timeline = timeline
    inv.status = "in_progress"
    await db.flush()
    await db.refresh(inv)
    return InvestigationResponse.model_validate(inv)


@router.patch("/{inv_id}/assign")
async def assign_investigation(
    inv_id: uuid.UUID,
    assignee_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_role(["admin"]))],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Investigation).where(Investigation.id == inv_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    inv.assignee_id = assignee_id
    await db.flush()
    return {"status": "assigned", "assignee_id": str(assignee_id)}


@router.patch("/{inv_id}/close")
async def close_investigation(
    inv_id: uuid.UUID,
    findings: str,
    current_user: Annotated[User, Depends(require_role(["admin", "analyst"]))],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Investigation).where(Investigation.id == inv_id))
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    inv.status = "closed"
    inv.findings = findings
    inv.closed_at = datetime.now(timezone.utc)
    timeline = list(inv.timeline or [])
    timeline.append({
        "action": "closed", "content": f"Investigation closed: {findings}",
        "user": current_user.email, "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    inv.timeline = timeline
    await db.flush()
    return {"status": "closed"}
