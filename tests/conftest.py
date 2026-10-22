"""Shared pytest fixtures and test configurations for CCK test suite."""

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from cck.api.app import create_app
from cck.contracts.action import AgentAction, AgentIdentity
from cck.core.types import ActionSeverity
from cck.runtime.engine import CCKControlPlane
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Provide a isolated temporary SQLite database path."""
    return tmp_path / "test_cck.db"


@pytest.fixture
def sample_agent() -> AgentIdentity:
    """Fixture returning a standard test agent identity."""
    return AgentIdentity(
        agent_id="agt-sec-dev-01",
        name="SecurityAuditorAgent",
        version="2.1.0",
        tenant_id="test-corp",
        trust_tier="standard",
    )


@pytest.fixture
def safe_action(sample_agent: AgentIdentity) -> AgentAction:
    """Fixture returning a safe read-only agent action."""
    return AgentAction(
        action_id="act-safe-001",
        agent=sample_agent,
        session_id="sess-test-101",
        capability="filesystem.read",
        target="/var/log/application.log",
        parameters={"path": "/var/log/application.log", "lines": 100},
        severity=ActionSeverity.INFORMATIONAL,
    )


@pytest.fixture
def dangerous_action(sample_agent: AgentIdentity) -> AgentAction:
    """Fixture returning a catastrophic destructive shell action."""
    return AgentAction(
        action_id="act-danger-002",
        agent=sample_agent,
        session_id="sess-test-102",
        capability="bash.execute",
        target="system.root",
        parameters={"command": "rm -rf / --no-preserve-root"},
        severity=ActionSeverity.DESTRUCTIVE,
    )


@pytest.fixture
def approval_action(sample_agent: AgentIdentity) -> AgentAction:
    """Fixture returning an action requiring human operator sign-off."""
    return AgentAction(
        action_id="act-approval-003",
        agent=sample_agent,
        session_id="sess-test-103",
        capability="bash.execute",
        target="system.services",
        parameters={"command": "systemctl stop production-gateway.service"},
        severity=ActionSeverity.MUTATION,
    )


@pytest.fixture
async def control_plane(temp_db_path: Path) -> AsyncGenerator[CCKControlPlane, None]:
    """Provide an initialized CCKControlPlane with isolated storage."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    cp = CCKControlPlane(storage=storage)
    await cp.initialize()
    yield cp
    await cp.shutdown()


@pytest.fixture
async def test_client(control_plane: CCKControlPlane) -> AsyncGenerator[AsyncClient, None]:
    """Provide an asynchronous HTTP client configured with test control plane."""
    app = create_app(control_plane=control_plane)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
