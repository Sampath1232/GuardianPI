"""Guardian Pi — Telemetry Sender: batched, encrypted telemetry transmission."""
from __future__ import annotations
import logging
from datetime import datetime, timezone

logger = logging.getLogger("guardian.telemetry")


class TelemetrySender:
    """Queues and sends encrypted telemetry events to the Guardian Pi server."""

    def __init__(self, server_url: str, api_key: str, encryption_key: str | None = None):
        self.server_url = server_url
        self.api_key = api_key
        self._queue: list[dict] = []
        self._max_queue = 100

        if encryption_key:
            from agent.security.crypto import TelemetryCrypto
            self.crypto = TelemetryCrypto(encryption_key)
        else:
            self.crypto = None

    def queue_event(self, event_type: str, severity: str, details: dict):
        """Add an event to the telemetry queue."""
        event = {
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "title": details.get("title", f"{event_type} event"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._queue.append(event)
        if len(self._queue) >= self._max_queue:
            logger.warning("Telemetry queue full, oldest events will be dropped")
            self._queue = self._queue[-self._max_queue:]

    async def flush(self):
        """Send all queued events to the server."""
        if not self._queue:
            return

        events = list(self._queue)
        self._queue.clear()

        payload = {"events": events}

        try:
            import httpx
            headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

            if self.crypto:
                encrypted = self.crypto.encrypt(payload)
                body = {
                    "device_id": "self",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **encrypted,
                }
            else:
                body = {
                    "device_id": "self",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": payload,
                }

            async with httpx.AsyncClient(timeout=30, verify=True) as client:
                response = await client.post(
                    f"{self.server_url}/api/v1/telemetry/ingest",
                    json=body, headers=headers,
                )
                if response.status_code == 202:
                    logger.info(f"Telemetry sent: {len(events)} events")
                else:
                    logger.error(f"Telemetry failed: {response.status_code}")
                    self._queue.extend(events)  # Re-queue on failure
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            self._queue.extend(events)
