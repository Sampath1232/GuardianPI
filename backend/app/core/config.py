"""
Guardian Pi — Application Configuration
Environment-based settings with Pydantic validation.
"""

from __future__ import annotations

import secrets
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Central configuration loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "Guardian Pi"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_HOSTS: list[str] = ["*"]

    # ── Security ─────────────────────────────────────────────────
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 10080  # 7 days
    API_KEY_HEADER: str = "X-API-Key"
    AGENT_API_KEYS: list[str] = []  # Pre-shared keys for agent auth
    BCRYPT_ROUNDS: int = 12

    # ── Database ─────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://guardian:guardian_secret@localhost:5432/guardianpi"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_ECHO: bool = False

    # ── Redis ────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = 20

    # ── CORS ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True

    # ── Rate Limiting ────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10

    # ── Telemetry ────────────────────────────────────────────────
    TELEMETRY_ENCRYPTION_KEY: Optional[str] = None  # AES-256 key (base64)
    TELEMETRY_BATCH_SIZE: int = 100
    TELEMETRY_FLUSH_INTERVAL_SECONDS: int = 30

    # ── AWS Integration ──────────────────────────────────────────
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_GUARDDUTY_DETECTOR_ID: Optional[str] = None
    AWS_COGNITO_USER_POOL_ID: Optional[str] = None
    AWS_COGNITO_CLIENT_ID: Optional[str] = None

    # ── File Paths ───────────────────────────────────────────────
    LOG_DIR: str = "logs"
    QUARANTINE_DIR: str = "quarantine"
    UPLOAD_DIR: str = "uploads"

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        return v.lower()

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == Environment.DEVELOPMENT

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()
