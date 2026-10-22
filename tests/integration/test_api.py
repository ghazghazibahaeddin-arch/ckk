"""Integration tests verifying the FastAPI HTTP endpoints and contracts."""

import pytest
from httpx import AsyncClient

from cck.contracts.action import AgentAction


@pytest.mark.asyncio
async def test_health_check_endpoint(test_client: AsyncClient) -> None:
    """GET /health must return healthy status."""
    response = await test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "cck-control-plane"


@pytest.mark.asyncio
async def test_api_info_endpoint(test_client: AsyncClient) -> None:
    """GET /api/v1/info must return platform status."""
    response = await test_client.get("/api/v1/info")
    assert response.status_code == 200
    data = response.json()
    assert data["storage_backend"] == "SQLiteStorageBackend"
    assert data["active_policies_count"] >= 3


@pytest.mark.asyncio
async def test_evaluate_safe_action_endpoint(
    test_client: AsyncClient, safe_action: AgentAction
) -> None:
    """POST /api/v1/actions/evaluate with safe action returns ALLOW."""
    payload = safe_action.model_dump(mode="json")
    response = await test_client.post("/api/v1/actions/evaluate", json=payload)
    assert response.status_code == 200
    verdict = response.json()
    assert verdict["decision"] == "ALLOW"
    assert verdict["action_id"] == safe_action.action_id
    assert verdict["risk_level"] == "LOW"


@pytest.mark.asyncio
async def test_evaluate_dangerous_action_endpoint(
    test_client: AsyncClient, dangerous_action: AgentAction
) -> None:
    """POST /api/v1/actions/evaluate with destructive command returns BLOCK."""
    payload = dangerous_action.model_dump(mode="json")
    response = await test_client.post("/api/v1/actions/evaluate", json=payload)
    assert response.status_code == 200
    verdict = response.json()
    assert verdict["decision"] == "BLOCK"
    assert verdict["risk_level"] == "CRITICAL"
    assert len(verdict["matched_policies"]) > 0


@pytest.mark.asyncio
async def test_list_policies_and_audits_endpoint(
    test_client: AsyncClient, safe_action: AgentAction
) -> None:
    """Verify policies list and audit ledger trail via HTTP."""
    # List policies
    pol_response = await test_client.get("/api/v1/policies")
    assert pol_response.status_code == 200
    policies = pol_response.json()
    assert len(policies) >= 3

    # Post an action to trigger audit recording
    payload = safe_action.model_dump(mode="json")
    await test_client.post("/api/v1/actions/evaluate", json=payload)

    # List audits
    audit_response = await test_client.get("/api/v1/audits")
    assert audit_response.status_code == 200
    audits = audit_response.json()
    assert len(audits) >= 1
    assert audits[0]["action_id"] == safe_action.action_id


@pytest.mark.asyncio
async def test_scenarios_and_connectors_api(test_client: AsyncClient) -> None:
    """Verify scenarios listing, connectors metadata, and audit verification endpoints."""
    # List scenarios
    scen_resp = await test_client.get("/api/v1/scenarios")
    assert scen_resp.status_code == 200
    scenarios = scen_resp.json()
    assert len(scenarios) >= 1

    # List connectors
    conn_resp = await test_client.get("/api/v1/connectors")
    assert conn_resp.status_code == 200
    connectors = conn_resp.json()
    assert len(connectors) >= 1
    assert any(c["connector_id"] == "in_memory_sandbox" for c in connectors)

    # Verify audit chain
    verify_resp = await test_client.get("/api/v1/audits/verify-chain")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert "verified" in verify_data
    assert verify_data["algorithm"] == "SHA-256"

