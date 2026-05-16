"""Guardian Pi — Device Schemas"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class DeviceRegisterRequest(BaseModel):
    hostname: str = Field(max_length=255)
    os_type: str = Field(pattern="^(windows|linux|macos|android|ios|raspberrypi)$")
    os_version: str = Field(max_length=100)
    architecture: str = Field(max_length=50)
    ram_mb: int = Field(gt=0)
    cpu_cores: int = Field(gt=0)
    cpu_model: Optional[str] = None
    storage_gb: Optional[int] = None
    agent_version: str = Field(max_length=50)
    is_rooted: bool = False
    is_virtual: bool = False
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None

class DeviceResponse(BaseModel):
    id: str
    hostname: str
    os_type: str
    os_version: str
    architecture: str
    ram_mb: int
    cpu_cores: int
    agent_version: str
    status: str
    is_rooted: bool
    is_virtual: bool
    is_compatible: bool
    ip_address: Optional[str]
    last_heartbeat: Optional[datetime]
    registered_at: datetime

    model_config = {"from_attributes": True}

class DeviceHeartbeat(BaseModel):
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    uptime_seconds: int
    active_connections: int = 0
    process_count: int = 0

class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]
    total: int
    page: int
    page_size: int

class CompatibilityCheckRequest(BaseModel):
    os_type: str
    os_version: str
    architecture: str
    ram_mb: int
    storage_gb: int

class CompatibilityCheckResponse(BaseModel):
    is_compatible: bool
    issues: list[str]
    recommendations: list[str]
