"""
Guardian Pi — Redis Configuration
Connection pool for caching, rate limiting, and pub/sub alerts.
"""

from __future__ import annotations

from typing import Optional

import redis.asyncio as aioredis

from backend.app.core.config import settings


class RedisManager:
    """Manages Redis connection lifecycle."""

    def __init__(self) -> None:
        self._pool: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        """Initialize the Redis connection pool."""
        self._pool = aioredis.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self._pool:
            await self._pool.close()

    @property
    def client(self) -> aioredis.Redis:
        """Get the Redis client. Raises if not connected."""
        if self._pool is None:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._pool

    # ── Rate Limiting ────────────────────────────────────────────

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int = settings.RATE_LIMIT_PER_MINUTE,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """
        Sliding window rate limiter.
        Returns (allowed: bool, remaining: int).
        """
        pipe = self._pool.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()

        current = results[0]
        remaining = max(0, max_requests - current)
        return current <= max_requests, remaining

    # ── Caching ──────────────────────────────────────────────────

    async def cache_set(self, key: str, value: str, ttl: int = 300) -> None:
        """Set a cache entry with TTL."""
        await self._pool.setex(key, ttl, value)

    async def cache_get(self, key: str) -> Optional[str]:
        """Get a cache entry."""
        return await self._pool.get(key)

    async def cache_delete(self, key: str) -> None:
        """Delete a cache entry."""
        await self._pool.delete(key)

    # ── Pub/Sub (Alert Broadcasting) ─────────────────────────────

    async def publish_alert(self, channel: str, message: str) -> None:
        """Publish an alert to a Redis channel."""
        await self._pool.publish(channel, message)


redis_manager = RedisManager()
