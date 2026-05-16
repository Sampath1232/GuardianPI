"""
Guardian Pi — Telemetry Router
Encrypted telemetry ingestion from agents.
"""

from __future__ import annotations

import base64
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import validate_agent_api_key
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.schemas.telemetry import TelemetryPayload

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry(
    payload: TelemetryPayload,
    api_key: Annotated[str, Depends(validate_agent_api_key)],
    db: AsyncSession = Depends(get_db),
):
    """Ingest encrypted telemetry from an agent."""
    if payload.encrypted_data and payload.nonce and payload.tag:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = base64.b64decode(settings.TELEMETRY_ENCRYPTION_KEY)
            nonce_bytes = base64.b64decode(payload.nonce)
            ct = base64.b64decode(payload.encrypted_data)
            tag_bytes = base64.b64decode(payload.tag)
            data = json.loads(AESGCM(key).decrypt(nonce_bytes, ct + tag_bytes, None))
        except Exception as e:
            raise HTTPException(400, detail=f"Decryption failed: {e}")
    elif payload.data and settings.is_development:
        data = payload.data
    else:
        raise HTTPException(400, detail="Encrypted payload required")

    events = data.get("events", [])
    alerts_created = 0
    for event in events:
        if event.get("severity") in ("critical", "high", "medium"):
            from backend.app.models.alert import Alert
            from uuid import UUID
            db.add(Alert(
                device_id=UUID(payload.device_id), severity=event["severity"],
                category=event.get("event_type", "telemetry"),
                title=event.get("title", "Telemetry Alert"),
                description=event.get("description"), evidence=event.get("details"),
                source="agent_telemetry",
            ))
            alerts_created += 1
    await db.flush()
    return {"status": "accepted", "events_processed": len(events), "alerts_created": alerts_created}
