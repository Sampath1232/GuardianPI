"""
Guardian Pi — Prometheus Metrics Endpoint
Exposes platform metrics for monitoring and observability.
"""
from __future__ import annotations

import time
from fastapi import APIRouter, Response
from backend.app.api.v1.websocket import ws_manager

router = APIRouter(prefix="/metrics", tags=["Metrics"])

_start_time = time.time()


@router.get("", response_class=Response)
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    from backend.app.core.database import async_session_factory
    from backend.app.models.device import Device
    from backend.app.models.alert import Alert
    from sqlalchemy import func, select

    uptime = time.time() - _start_time

    # Gather metrics from database
    async with async_session_factory() as db:
        total_devices = (await db.execute(select(func.count(Device.id)))).scalar() or 0
        online_devices = (await db.execute(select(func.count(Device.id)).where(Device.status == "online"))).scalar() or 0
        total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        open_alerts = (await db.execute(select(func.count(Alert.id)).where(Alert.status == "open"))).scalar() or 0
        critical_alerts = (await db.execute(select(func.count(Alert.id)).where(Alert.severity == "critical", Alert.status == "open"))).scalar() or 0

    ws_connections = ws_manager.active_count

    # Build Prometheus text format
    lines = [
        "# HELP guardian_uptime_seconds Time since server start",
        "# TYPE guardian_uptime_seconds gauge",
        f"guardian_uptime_seconds {uptime:.1f}",
        "",
        "# HELP guardian_devices_total Total registered devices",
        "# TYPE guardian_devices_total gauge",
        f"guardian_devices_total {total_devices}",
        "",
        "# HELP guardian_devices_online Currently online devices",
        "# TYPE guardian_devices_online gauge",
        f"guardian_devices_online {online_devices}",
        "",
        "# HELP guardian_alerts_total Total alerts ever created",
        "# TYPE guardian_alerts_total gauge",
        f"guardian_alerts_total {total_alerts}",
        "",
        "# HELP guardian_alerts_open Currently open alerts",
        "# TYPE guardian_alerts_open gauge",
        f"guardian_alerts_open {open_alerts}",
        "",
        "# HELP guardian_alerts_critical Open critical alerts",
        "# TYPE guardian_alerts_critical gauge",
        f"guardian_alerts_critical {critical_alerts}",
        "",
        "# HELP guardian_ws_connections Active WebSocket connections",
        "# TYPE guardian_ws_connections gauge",
        f"guardian_ws_connections {ws_connections}",
        "",
    ]

    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
