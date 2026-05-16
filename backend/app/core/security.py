"""
Guardian Pi — Security Utilities
JWT tokens, password hashing, API key validation, HMAC signing.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

import bcrypt
from jose import JWTError, jwt

from backend.app.core.config import settings


# ── Password Hashing ────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with configurable rounds."""
    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


# ── JWT Tokens ───────────────────────────────────────────────────────


def create_access_token(
    subject: str | UUID,
    role: str = "viewer",
    extra_claims: Optional[dict[str, Any]] = None,
) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(subject),
        "role": role,
        "type": "access",
        "iat": now,
        "exp": expire,
        "jti": secrets.token_urlsafe(16),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str | UUID) -> str:
    """Create a signed JWT refresh token with longer expiry."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(subject),
        "type": "refresh",
        "iat": now,
        "exp": expire,
        "jti": secrets.token_urlsafe(16),
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises JWTError on failure."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError:
        raise


# ── API Key Validation ───────────────────────────────────────────────


def validate_api_key(api_key: str) -> bool:
    """Validate an agent API key using constant-time comparison."""
    return any(
        secrets.compare_digest(api_key, valid_key)
        for valid_key in settings.AGENT_API_KEYS
    )


def generate_api_key() -> str:
    """Generate a secure API key for agent registration."""
    return f"gpi_{secrets.token_urlsafe(48)}"


# ── HMAC Signing (Audit Log Integrity) ───────────────────────────────


def sign_audit_entry(entry_data: str) -> str:
    """Create HMAC-SHA256 signature for an audit log entry."""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        entry_data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_audit_signature(entry_data: str, signature: str) -> bool:
    """Verify HMAC signature of an audit log entry (constant-time)."""
    expected = sign_audit_entry(entry_data)
    return hmac.compare_digest(expected, signature)
