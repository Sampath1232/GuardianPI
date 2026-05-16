"""
Guardian Pi — Auth Endpoint Tests
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Test login with wrong credentials returns 401."""
    response = await client.post("/api/v1/auth/login", json={
        "email": "invalid@test.com",
        "password": "wrongpassword",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_access_without_token(client: AsyncClient):
    """Test protected endpoints require authentication."""
    response = await client.get("/api/v1/devices")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_access_with_valid_token(client: AsyncClient, admin_token: str):
    """Test protected endpoint accepts valid JWT."""
    response = await client.get(
        "/api/v1/devices",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Should succeed (200) or return empty list
    assert response.status_code == 200
