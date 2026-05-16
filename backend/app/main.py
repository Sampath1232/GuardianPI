"""
Guardian Pi — FastAPI Application Entry Point
Production-grade security platform backend.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import close_db, init_db
from backend.app.core.redis import redis_manager
from backend.app.middleware.security_headers import SecurityHeadersMiddleware
from backend.app.middleware.request_logger import RequestLoggerMiddleware

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("guardian")


# ── Lifespan ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup/shutdown lifecycle."""
    logger.info("Guardian Pi v2 starting up...")
    await init_db()
    await redis_manager.connect()
    logger.info("Database and Redis connected")

    # Connect NATS event bus and start alert pipeline
    try:
        from backend.app.services.event_bus import event_bus
        from backend.app.services.alert_pipeline import alert_pipeline
        await event_bus.connect()
        await alert_pipeline.start()
        logger.info("Event bus and alert pipeline started")
    except Exception as e:
        logger.warning(f"Event bus unavailable (non-fatal): {e}")

    yield

    logger.info("Guardian Pi shutting down...")
    try:
        from backend.app.services.event_bus import event_bus
        from backend.app.services.alert_pipeline import alert_pipeline
        await alert_pipeline.stop()
        await event_bus.disconnect()
    except Exception:
        pass
    await redis_manager.disconnect()
    await close_db()


# ── App Factory ──────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Production-grade defensive security platform",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan,
    )

    # Middleware (order matters — last added = first executed)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggerMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API v1 routers
    from backend.app.api.v1 import (
        auth, devices, alerts, telemetry, remediation,
        compliance, health, websocket, policies,
        investigations, metrics, agent_update,
    )

    prefix = settings.API_V1_PREFIX
    app.include_router(auth.router, prefix=prefix)
    app.include_router(devices.router, prefix=prefix)
    app.include_router(alerts.router, prefix=prefix)
    app.include_router(telemetry.router, prefix=prefix)
    app.include_router(remediation.router, prefix=prefix)
    app.include_router(compliance.router, prefix=prefix)
    app.include_router(health.router, prefix=prefix)
    app.include_router(policies.router, prefix=prefix)
    app.include_router(investigations.router, prefix=prefix)
    app.include_router(metrics.router, prefix=prefix)
    app.include_router(agent_update.router, prefix=prefix)
    # WebSocket routes (no prefix — mounted at /ws/*)
    app.include_router(websocket.router)

    @app.get("/")
    async def root():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs" if settings.is_development else "disabled in production",
        }

    return app


app = create_app()
