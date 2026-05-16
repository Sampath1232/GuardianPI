"""
Guardian Pi — WebSocket Gateway
Real-time alert broadcasting and device status updates.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from backend.app.api.deps import decode_ws_token

router = APIRouter(tags=["WebSocket"])
logger = logging.getLogger("guardian.ws")


class ConnectionManager:
    """Manages active WebSocket connections with room support."""

    def __init__(self):
        self._connections: Dict[str, Set[WebSocket]] = {
            "alerts": set(),
            "devices": set(),
            "telemetry": set(),
        }
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, channel: str = "alerts"):
        await ws.accept()
        async with self._lock:
            if channel not in self._connections:
                self._connections[channel] = set()
            self._connections[channel].add(ws)
        logger.info(f"WS connected to channel '{channel}' ({len(self._connections[channel])} total)")

    async def disconnect(self, ws: WebSocket, channel: str = "alerts"):
        async with self._lock:
            self._connections.get(channel, set()).discard(ws)
        logger.info(f"WS disconnected from '{channel}'")

    async def broadcast(self, channel: str, message: dict):
        """Broadcast a message to all connections in a channel."""
        async with self._lock:
            targets = list(self._connections.get(channel, set()))

        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        # Clean up dead connections
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.get(channel, set()).discard(ws)

    @property
    def active_count(self) -> int:
        return sum(len(conns) for conns in self._connections.values())


# Singleton manager
ws_manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def alerts_websocket(ws: WebSocket):
    """Real-time security alert feed."""
    await ws_manager.connect(ws, "alerts")
    try:
        while True:
            data = await ws.receive_text()
            # Client can send ack messages
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws, "alerts")


@router.websocket("/ws/devices")
async def devices_websocket(ws: WebSocket):
    """Real-time device status updates."""
    await ws_manager.connect(ws, "devices")
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws, "devices")


@router.websocket("/ws/telemetry")
async def telemetry_websocket(ws: WebSocket):
    """Real-time telemetry stream."""
    await ws_manager.connect(ws, "telemetry")
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws, "telemetry")


# Helper function for other routers to broadcast events
async def broadcast_alert(alert_data: dict):
    """Broadcast a new alert to all connected WebSocket clients."""
    await ws_manager.broadcast("alerts", {
        "type": "new_alert",
        "data": alert_data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


async def broadcast_device_update(device_data: dict):
    """Broadcast a device status change."""
    await ws_manager.broadcast("devices", {
        "type": "device_update",
        "data": device_data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
