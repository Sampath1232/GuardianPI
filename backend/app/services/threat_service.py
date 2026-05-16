"""Guardian Pi — Threat Service: alert analysis, scoring, and correlation."""
from __future__ import annotations
import logging
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.alert import Alert
from backend.app.models.device import Device

logger = logging.getLogger("guardian.threat")


class ThreatService:
    """Analyzes and correlates security alerts to determine threat level."""

    SEVERITY_SCORES = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}

    @staticmethod
    async def calculate_device_risk_score(db: AsyncSession, device_id) -> dict:
        """Calculate a composite risk score for a device based on its alerts."""
        result = await db.execute(
            select(Alert).where(Alert.device_id == device_id, Alert.status == "open")
        )
        open_alerts = result.scalars().all()

        if not open_alerts:
            return {"risk_score": 0, "risk_level": "low", "open_alerts": 0}

        total_score = sum(
            ThreatService.SEVERITY_SCORES.get(a.severity, 0) for a in open_alerts
        )
        # Normalize to 0-100 scale
        risk_score = min(100, total_score)
        risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "open_alerts": len(open_alerts),
            "critical_count": sum(1 for a in open_alerts if a.severity == "critical"),
            "high_count": sum(1 for a in open_alerts if a.severity == "high"),
        }

    @staticmethod
    async def get_security_posture(db: AsyncSession) -> dict:
        """Calculate overall security posture across all devices."""
        total_devices = (await db.execute(select(func.count(Device.id)))).scalar() or 0
        online = (await db.execute(select(func.count(Device.id)).where(Device.status == "online"))).scalar() or 0
        compromised = (await db.execute(select(func.count(Device.id)).where(Device.status == "compromised"))).scalar() or 0
        open_critical = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == "critical", Alert.status == "open")
        )).scalar() or 0

        if total_devices == 0:
            posture_score = 100
        else:
            posture_score = max(0, 100 - (compromised * 30) - (open_critical * 10))

        return {
            "posture_score": posture_score,
            "total_devices": total_devices,
            "online_devices": online,
            "compromised_devices": compromised,
            "open_critical_alerts": open_critical,
            "status": "healthy" if posture_score >= 80 else "degraded" if posture_score >= 50 else "critical",
        }


threat_service = ThreatService()
