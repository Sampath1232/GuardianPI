"""
Guardian Pi — Real-time Alert Pipeline
Bridges NATS events → Detection Engine → Alert Creation → WebSocket Broadcast.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import async_session_factory
from backend.app.models.alert import Alert
from backend.app.services.detection_service import detection_engine
from backend.app.services.event_bus import event_bus
from backend.app.api.v1.websocket import broadcast_alert, broadcast_device_update

logger = logging.getLogger("guardian.pipeline")


class AlertPipeline:
    """Processes incoming telemetry, runs detections, creates alerts, broadcasts in real-time."""

    def __init__(self):
        self._running = False

    async def start(self):
        """Start listening for telemetry events and running detection pipeline."""
        self._running = True
        logger.info("Alert pipeline started")

        # Subscribe to NATS telemetry stream
        await event_bus.subscribe("guardian.telemetry.>", self._handle_telemetry)
        # Subscribe to device status changes
        await event_bus.subscribe("guardian.devices.status", self._handle_device_status)

    async def stop(self):
        self._running = False

    async def process_telemetry_batch(self, device_id: str, events: list[dict]):
        """Process a batch of telemetry events through the detection pipeline."""
        alerts_created = []

        for event in events:
            event_type = event.get("event_type", "")
            severity = event.get("severity", "info")
            title = event.get("title", "")
            details = event.get("details", {})

            # Skip info-level system metrics (don't create alerts for normal telemetry)
            if event_type == "system_metrics" and severity == "info":
                # Run anomaly scoring on metrics
                anomaly = detection_engine.calculate_anomaly_score(details)
                if anomaly["anomaly_score"] > 30:
                    alert = await self._create_alert(
                        device_id=device_id,
                        title=f"Anomaly detected: score {anomaly['anomaly_score']}",
                        description="; ".join(anomaly["reasons"]),
                        severity=anomaly["risk_level"],
                        alert_type="anomaly",
                        details={"anomaly": anomaly, **details},
                    )
                    if alert:
                        alerts_created.append(alert)
                continue

            # Run Sigma rule matching on process events
            if event_type in ("process_alert", "detection"):
                process_name = details.get("process_name", details.get("name", ""))
                cmdline = details.get("cmdline", "")
                matches = detection_engine.match_process(process_name, cmdline)

                if matches:
                    for match in matches:
                        alert = await self._create_alert(
                            device_id=device_id,
                            title=f"{match['rule_name']}: {process_name}",
                            description=match["description"],
                            severity=match["severity"],
                            alert_type=match["category"],
                            details={
                                "rule_id": match["rule_id"],
                                "mitre_tactic": match["mitre_tactic"],
                                "mitre_technique": match["mitre_technique"],
                                **details,
                            },
                        )
                        if alert:
                            alerts_created.append(alert)
                    continue

            # Create alert for any non-info severity events
            if severity in ("critical", "high", "medium"):
                alert = await self._create_alert(
                    device_id=device_id,
                    title=title,
                    description=f"{event_type}: {title}",
                    severity=severity,
                    alert_type=event_type,
                    details=details,
                )
                if alert:
                    alerts_created.append(alert)

        return alerts_created

    async def _create_alert(
        self, device_id: str, title: str, description: str,
        severity: str, alert_type: str, details: dict,
    ) -> dict | None:
        """Create an alert in the database and broadcast via WebSocket."""
        try:
            async with async_session_factory() as db:
                alert = Alert(
                    device_id=UUID(device_id) if device_id and device_id != "self" else None,
                    title=title,
                    description=description,
                    severity=severity,
                    alert_type=alert_type,
                    source="agent",
                    details=details,
                )
                db.add(alert)
                await db.commit()
                await db.refresh(alert)

                alert_data = {
                    "id": str(alert.id),
                    "title": alert.title,
                    "severity": alert.severity,
                    "alert_type": alert.alert_type,
                    "device_id": device_id,
                    "details": details,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                }

                # Broadcast to WebSocket clients
                await broadcast_alert(alert_data)

                # Publish to NATS for other consumers
                await event_bus.publish_alert(alert_data)

                logger.warning(f"Alert created: [{severity}] {title}")
                return alert_data

        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None

    async def _handle_telemetry(self, message: dict):
        """NATS callback for incoming telemetry."""
        device_id = message.get("device_id", "")
        data = message.get("data", {})
        events = data.get("events", [])
        if events:
            await self.process_telemetry_batch(device_id, events)

    async def _handle_device_status(self, message: dict):
        """NATS callback for device status changes."""
        await broadcast_device_update(message.get("data", message))


# Singleton
alert_pipeline = AlertPipeline()
