"""
Guardian Pi — NATS Event Bus Service
Real-time event distribution using NATS JetStream.
Bridges agent telemetry → WebSocket broadcast → alerting pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Callable, Awaitable

logger = logging.getLogger("guardian.nats")


class NATSEventBus:
    """Async NATS JetStream event bus for real-time event distribution."""

    # Stream/subject definitions
    STREAM_ALERTS = "GUARDIAN_ALERTS"
    STREAM_TELEMETRY = "GUARDIAN_TELEMETRY"
    STREAM_DEVICES = "GUARDIAN_DEVICES"
    SUBJECT_ALERT_NEW = "guardian.alerts.new"
    SUBJECT_ALERT_ACK = "guardian.alerts.ack"
    SUBJECT_TELEMETRY = "guardian.telemetry.>"
    SUBJECT_DEVICE_STATUS = "guardian.devices.status"
    SUBJECT_DEVICE_HEARTBEAT = "guardian.devices.heartbeat"

    def __init__(self, nats_url: str = "nats://localhost:4222"):
        self._url = nats_url
        self._nc = None
        self._js = None
        self._subscribers: dict[str, list[Callable]] = {}

    async def connect(self):
        """Connect to NATS and create JetStream streams."""
        try:
            import nats
            self._nc = await nats.connect(self._url)
            self._js = self._nc.jetstream()

            # Create streams if they don't exist
            for stream_name, subjects in [
                (self.STREAM_ALERTS, ["guardian.alerts.>"]),
                (self.STREAM_TELEMETRY, ["guardian.telemetry.>"]),
                (self.STREAM_DEVICES, ["guardian.devices.>"]),
            ]:
                try:
                    await self._js.add_stream(
                        name=stream_name,
                        subjects=subjects,
                        retention="limits",
                        max_age=86400 * 7,  # 7 days
                        max_bytes=1024 * 1024 * 512,  # 512 MB
                    )
                except Exception:
                    pass  # Stream already exists

            logger.info(f"NATS connected: {self._url}")
        except ImportError:
            logger.warning("nats-py not installed — event bus disabled")
        except Exception as e:
            logger.warning(f"NATS connection failed: {e} — operating without event bus")

    async def disconnect(self):
        if self._nc and not self._nc.is_closed:
            await self._nc.close()
            logger.info("NATS disconnected")

    async def publish_alert(self, alert_data: dict):
        """Publish a new alert event."""
        await self._publish(self.SUBJECT_ALERT_NEW, {
            "type": "new_alert",
            "data": alert_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def publish_telemetry(self, device_id: str, telemetry_data: dict):
        """Publish telemetry data for a specific device."""
        await self._publish(f"guardian.telemetry.{device_id}", {
            "type": "telemetry",
            "device_id": device_id,
            "data": telemetry_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def publish_device_status(self, device_id: str, status: str):
        """Publish device status change."""
        await self._publish(self.SUBJECT_DEVICE_STATUS, {
            "type": "device_status",
            "device_id": device_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def subscribe(self, subject: str, callback: Callable[[dict], Awaitable[None]]):
        """Subscribe to a NATS subject with a callback."""
        if not self._js:
            logger.warning("NATS not connected — skipping subscription")
            return

        async def _handler(msg):
            try:
                data = json.loads(msg.data.decode())
                await callback(data)
                await msg.ack()
            except Exception as e:
                logger.error(f"NATS handler error: {e}")

        await self._js.subscribe(subject, cb=_handler, durable="guardian-api")
        logger.info(f"Subscribed to {subject}")

    async def _publish(self, subject: str, data: dict):
        """Internal publish with JSON serialization."""
        if not self._js:
            return
        try:
            payload = json.dumps(data).encode()
            await self._js.publish(subject, payload)
            logger.debug(f"Published to {subject}")
        except Exception as e:
            logger.error(f"NATS publish error on {subject}: {e}")


# Singleton
event_bus = NATSEventBus()
