"""
Guardian Pi — Security Module Tests
Tests for JWT, password hashing, API keys, and HMAC signing.
"""
import pytest
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
    generate_api_key,
    sign_audit_entry,
    verify_audit_signature,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "SecureP@ssw0rd!2024"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct_password")
        assert not verify_password("wrong_password", hashed)

    def test_different_hashes(self):
        h1 = hash_password("same_password")
        h2 = hash_password("same_password")
        assert h1 != h2  # Different salts


class TestJWT:
    def test_create_and_decode_access(self):
        token = create_access_token("user-123", role="admin")
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_create_and_decode_refresh(self):
        token = create_refresh_token("user-456")
        payload = decode_token(token)
        assert payload["sub"] == "user-456"
        assert payload["type"] == "refresh"

    def test_token_has_jti(self):
        token = create_access_token("user-789")
        payload = decode_token(token)
        assert "jti" in payload


class TestAPIKey:
    def test_generate_api_key_format(self):
        key = generate_api_key()
        assert key.startswith("gpi_")
        assert len(key) > 20


class TestHMAC:
    def test_sign_and_verify(self):
        data = '{"action": "login", "user": "admin"}'
        sig = sign_audit_entry(data)
        assert verify_audit_signature(data, sig)

    def test_tampered_data_fails(self):
        data = '{"action": "login", "user": "admin"}'
        sig = sign_audit_entry(data)
        assert not verify_audit_signature('{"action": "login", "user": "hacker"}', sig)
