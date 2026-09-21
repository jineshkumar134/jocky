"""
Tests for JOCKY API Case & Investigation Endpoints (Phase 14)
"""
import pytest
from httpx import ASGITransport, AsyncClient
from server.main import app


@pytest.mark.asyncio
async def test_list_cases():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases")
        assert response.status_code == 200
        cases = response.json()
        assert len(cases) >= 1
        c = cases[0]
        assert c["case_id"] == "JOCKY-FINAL-2026"
        assert c["host_count"] == 3
        assert c["status"] == "OPEN"


@pytest.mark.asyncio
async def test_get_case_details():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026")
        assert response.status_code == 200
        data = response.json()
        assert data["case_id"] == "JOCKY-FINAL-2026"
        assert "case_management" in data
        assert "platform_info" in data
        assert "security_status" in data


@pytest.mark.asyncio
async def test_get_case_hosts():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/hosts")
        assert response.status_code == 200
        hosts = response.json()
        assert len(hosts) == 3
        hostnames = [h["hostname"] for h in hosts]
        assert "LAB-PC-01" in hostnames
        assert "LAB-PC-02" in hostnames
        assert "LAB-PC-03" in hostnames


@pytest.mark.asyncio
async def test_get_case_evidence():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/evidence")
        assert response.status_code == 200
        ev = response.json()
        assert "evidence" in ev
        assert "relationships" in ev
        assert "correlations" in ev
        assert len(ev["evidence"]) >= 5


@pytest.mark.asyncio
async def test_get_case_graph():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/graph")
        assert response.status_code == 200
        g = response.json()
        assert "nodes" in g
        assert "edges" in g
        assert len(g["nodes"]) >= 5
        assert len(g["edges"]) >= 5


@pytest.mark.asyncio
async def test_get_case_timeline():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/timeline")
        assert response.status_code == 200
        t = response.json()
        assert "events" in t
        assert len(t["events"]) >= 5


@pytest.mark.asyncio
async def test_get_case_risk():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/risk")
        assert response.status_code == 200
        r = response.json()
        assert "score" in r
        assert "severity" in r
        assert "findings" in r
        assert r["score"] > 0


@pytest.mark.asyncio
async def test_get_case_blockchain():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/blockchain")
        assert response.status_code == 200
        b = response.json()
        assert "blockchain" in b
        assert "vasp" in b


@pytest.mark.asyncio
async def test_get_case_anchoring():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/anchoring")
        assert response.status_code == 200
        anc = response.json()
        assert "anchor" in anc
        assert "verification" in anc
        assert anc["verification"]["is_valid"] is True


@pytest.mark.asyncio
async def test_get_case_security():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/security")
        assert response.status_code == 200
        sec = response.json()
        assert "platform_info" in sec
        assert "security_status" in sec


@pytest.mark.asyncio
async def test_get_case_research():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/cases/JOCKY-FINAL-2026/research")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 5
        scenario_ids = [item["scenario"]["scenario_id"] for item in data]
        assert "synthetic_polymorphism" in scenario_ids
        assert "synthetic_driver_risk" in scenario_ids
