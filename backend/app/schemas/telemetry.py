"""Guardian Pi — Telemetry & Remediation Schemas"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class TelemetryPayload(BaseModel):
    device_id: str
    timestamp: datetime
    encrypted_data: Optional[str] = None  # Base64 AES-256-GCM encrypted
    data: Optional[dict[str, Any]] = None  # Plaintext fallback (dev only)
    nonce: Optional[str] = None
    tag: Optional[str] = None

class TelemetryEvent(BaseModel):
    event_type: str  # process_alert | file_change | network_anomaly | usb_event
    severity: str
    details: dict[str, Any]
    timestamp: datetime

class RemediationRequest(BaseModel):
    device_id: str
    action_type: str = Field(
        pattern="^(quarantine_process|block_ip|disable_service|isolate_endpoint|kill_process)$"
    )
    parameters: dict[str, Any]
    alert_id: Optional[str] = None

class RemediationResponse(BaseModel):
    id: str
    device_id: str
    action_type: str
    status: str
    parameters: Optional[dict[str, Any]]
    result_message: Optional[str]
    is_automated: bool
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}

class RollbackRequest(BaseModel):
    remediation_id: str
    reason: str
