"""
Guardian Pi — Devices Router
Device registration, inventory, heartbeat, and compatibility checks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import get_current_user, validate_agent_api_key
from backend.app.core.database import get_db
from backend.app.models.device import Device
from backend.app.models.user import User
from backend.app.schemas.device import (
    CompatibilityCheckRequest,
    CompatibilityCheckResponse,
    DeviceHeartbeat,
    DeviceListResponse,
    DeviceRegisterRequest,
    DeviceResponse,
)

router = APIRouter(prefix="/devices", tags=["Devices"])

# ── Compatibility Matrix ─────────────────────────────────────────
MINIMUM_REQUIREMENTS = {
    "windows": {"min_ram_mb": 2048, "min_storage_gb": 5, "architectures": ["x86_64", "arm64"]},
    "linux": {"min_ram_mb": 512, "min_storage_gb": 2, "architectures": ["x86_64", "arm64", "armv7l"]},
    "macos": {"min_ram_mb": 4096, "min_storage_gb": 5, "architectures": ["x86_64", "arm64"]},
    "raspberrypi": {"min_ram_mb": 256, "min_storage_gb": 2, "architectures": ["armv7l", "arm64"]},
    "android": {"min_ram_mb": 2048, "min_storage_gb": 1, "architectures": ["arm64", "armv7l"]},
    "ios": {"min_ram_mb": 2048, "min_storage_gb": 1, "architectures": ["arm64"]},
}


@router.post("/register", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    request: DeviceRegisterRequest,
    api_key: Annotated[str, Depends(validate_agent_api_key)],
    db: AsyncSession = Depends(get_db),
):
    """Register a new device with the platform (requires API key)."""
    # Check compatibility
    compat = _check_compatibility(request.os_type, request.os_version, request.architecture, request.ram_mb, request.storage_gb or 0)

    device = Device(
        hostname=request.hostname,
        os_type=request.os_type,
        os_version=request.os_version,
        architecture=request.architecture,
        ram_mb=request.ram_mb,
        cpu_cores=request.cpu_cores,
        cpu_model=request.cpu_model,
        storage_gb=request.storage_gb,
        agent_version=request.agent_version,
        is_rooted=request.is_rooted,
        is_virtual=request.is_virtual,
        is_compatible=compat.is_compatible,
        ip_address=request.ip_address,
        mac_address=request.mac_address,
        metadata_json=request.metadata_json,
        last_heartbeat=datetime.now(timezone.utc),
    )
    db.add(device)
    await db.flush()
    await db.refresh(device)

    return DeviceResponse.model_validate(device)


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    os_type: str | None = None,
):
    """List all registered devices with filtering and pagination."""
    query = select(Device)

    if status_filter:
        query = query.where(Device.status == status_filter)
    if os_type:
        query = query.where(Device.os_type == os_type)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    devices = result.scalars().all()

    return DeviceListResponse(
        devices=[DeviceResponse.model_validate(d) for d in devices],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get device details by ID."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceResponse.model_validate(device)


@router.post("/{device_id}/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def device_heartbeat(
    device_id: UUID,
    heartbeat: DeviceHeartbeat,
    api_key: Annotated[str, Depends(validate_agent_api_key)],
    db: AsyncSession = Depends(get_db),
):
    """Receive heartbeat from an agent. Updates device status and metrics."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.last_heartbeat = datetime.now(timezone.utc)
    device.status = "online"
    device.metadata_json = {
        **(device.metadata_json or {}),
        "last_metrics": heartbeat.model_dump(),
    }
    await db.flush()


@router.post("/compatibility-check", response_model=CompatibilityCheckResponse)
async def compatibility_check(request: CompatibilityCheckRequest):
    """Check if a device meets minimum requirements for agent installation."""
    return _check_compatibility(
        request.os_type, request.os_version, request.architecture,
        request.ram_mb, request.storage_gb,
    )


def _check_compatibility(os_type: str, os_version: str, architecture: str, ram_mb: int, storage_gb: int) -> CompatibilityCheckResponse:
    issues = []
    recommendations = []

    reqs = MINIMUM_REQUIREMENTS.get(os_type)
    if not reqs:
        issues.append(f"Unsupported OS: {os_type}")
        return CompatibilityCheckResponse(is_compatible=False, issues=issues, recommendations=["Use a supported platform"])

    if architecture not in reqs["architectures"]:
        issues.append(f"Unsupported architecture: {architecture}")
    if ram_mb < reqs["min_ram_mb"]:
        issues.append(f"Insufficient RAM: {ram_mb}MB (minimum {reqs['min_ram_mb']}MB)")
        recommendations.append("Upgrade device RAM")
    if storage_gb < reqs["min_storage_gb"]:
        issues.append(f"Insufficient storage: {storage_gb}GB (minimum {reqs['min_storage_gb']}GB)")

    return CompatibilityCheckResponse(
        is_compatible=len(issues) == 0,
        issues=issues,
        recommendations=recommendations,
    )
