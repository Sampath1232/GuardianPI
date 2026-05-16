"""Guardian Pi — Request Logger Middleware"""
import json
import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("guardian.access")

class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration = round((time.monotonic() - start) * 1000, 2)
        logger.info(json.dumps({
            "method": request.method, "path": request.url.path,
            "status": response.status_code, "duration_ms": duration,
            "client": request.client.host if request.client else "unknown",
        }))
        return response
