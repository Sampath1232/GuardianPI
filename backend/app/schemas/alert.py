"""Guardian Pi — Alert Schemas"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    device_id: str
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    category: str = Field(max_length=100)
    title: str = Field(max_length=500)
    description: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None
    source: Optional[str] = "agent"
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

class AlertResponse(BaseModel):
    id: str
    device_id: str
    severity: str
    category: str
    title: str
    description: Optional[str]
    evidence: Optional[dict[str, Any]]
    status: str
    source: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}

class AlertUpdateRequest(BaseModel):
    status: str = Field(pattern="^(acknowledged|resolved|false_positive)$")
    resolution_note: Optional[str] = None

class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int
    page: int
    page_size: int

class AlertStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open_count: int
    resolved_count: int
