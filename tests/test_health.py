"""
Tests for JOCKY API Health & Root Endpoints
"""
import pytest
from httpx import ASGITransport, AsyncClient
from api.main import app


@pytest.mark.asyncio
async def test_root_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert "JOCKY" in data["service"]
        assert "Phase 0" in data["phase"]


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "JOCKY" in data["service"]
        assert data["environment"] == "development"
        assert "Phase 0" in data["phase"]
