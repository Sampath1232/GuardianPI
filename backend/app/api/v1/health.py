"""Guardian Pi — Health Check Router"""
from __future__ import annotations
from fastapi import APIRouter
from backend.app.core.config import settings

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("/live")
async def liveness():
    """Liveness probe — is the process running?"""
    return {"status": "alive", "version": settings.APP_VERSION}

@router.get("/ready")
async def readiness():
    """Readiness probe — are dependencies available?"""
    checks = {"database": False, "redis": False}
    try:
        from backend.app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["database"] = True
    except Exception:
        pass
    try:
        from backend.app.core.redis import redis_manager
        await redis_manager.client.ping()
        checks["redis"] = True
    except Exception:
        pass
    all_ready = all(checks.values())
    return {"status": "ready" if all_ready else "degraded", "checks": checks}
