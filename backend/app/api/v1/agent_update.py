"""
Guardian Pi — Agent Update Router
Secure agent update distribution with signature verification.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel

from backend.app.api.deps import require_role, verify_agent_api_key

router = APIRouter(prefix="/agent", tags=["Agent Management"])
logger = logging.getLogger("guardian.agent_update")


class AgentVersion(BaseModel):
    version: str
    platform: str  # windows | linux | macos | arm | android
    download_url: str
    sha256_hash: str
    release_notes: str
    size_bytes: int
    released_at: str


# In-memory version registry (production: use DB)
_versions: dict[str, AgentVersion] = {
    "linux": AgentVersion(
        version="2.0.0", platform="linux",
        download_url="/api/v1/agent/download/linux",
        sha256_hash="placeholder_hash", release_notes="Initial Go agent release",
        size_bytes=0, released_at=datetime.now(timezone.utc).isoformat(),
    ),
}


@router.get("/update/check")
async def check_for_update(
    current_version: str, platform: str,
    api_key: str = Depends(verify_agent_api_key),
):
    """Check if a newer agent version is available."""
    available = _versions.get(platform)
    if not available:
        return {"update_available": False, "message": f"No builds for platform: {platform}"}

    needs_update = available.version != current_version
    return {
        "update_available": needs_update,
        "current_version": current_version,
        "latest_version": available.version,
        "download_url": available.download_url if needs_update else None,
        "sha256_hash": available.sha256_hash if needs_update else None,
        "release_notes": available.release_notes if needs_update else None,
    }


@router.post("/update/publish")
async def publish_agent_update(
    version: str, platform: str, release_notes: str,
    binary: UploadFile = File(...),
    current_user=Depends(require_role(["admin"])),
):
    """Publish a new agent binary (admin only). Computes SHA-256 hash."""
    content = await binary.read()

    sha256_hash = hashlib.sha256(content).hexdigest()
    logger.info(f"Publishing agent v{version} for {platform} ({len(content)} bytes, SHA256: {sha256_hash})")

    _versions[platform] = AgentVersion(
        version=version, platform=platform,
        download_url=f"/api/v1/agent/download/{platform}",
        sha256_hash=sha256_hash, release_notes=release_notes,
        size_bytes=len(content),
        released_at=datetime.now(timezone.utc).isoformat(),
    )

    return {"status": "published", "version": version, "platform": platform, "sha256": sha256_hash}


@router.get("/versions")
async def list_agent_versions():
    """List all available agent versions by platform."""
    return {"versions": {k: v.model_dump() for k, v in _versions.items()}}
