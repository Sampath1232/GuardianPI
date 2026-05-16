"""
Guardian Pi — Health Endpoint Tests
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint returns app info."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Guardian Pi"
    assert data["status"] == "operational"


@pytest.mark.asyncio
async def test_health_live(client: AsyncClient):
    """Test liveness probe."""
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_health_ready(client: AsyncClient):
    """Test readiness probe."""
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
