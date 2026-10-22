"""Unit tests verifying SQLite storage operations and boundary contracts."""

from pathlib import Path

import pytest

from cck.contracts.action import AgentAction
from cck.contracts.policy import PolicyRule
from cck.core.types import RiskLevel, VerdictDecision
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_sqlite_initialization_and_tables(temp_db_path: Path) -> None:
    """Verify tables and indexes are created without error."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    assert temp_db_path.exists()
    await storage.close()


@pytest.mark.asyncio
async def test_sqlite_action_crud(temp_db_path: Path, safe_action: AgentAction) -> None:
    """Test saving and retrieving an agent action from SQLite."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    # Save
    await storage.save_action(safe_action)

    # Fetch
    retrieved = await storage.get_action(safe_action.action_id)
    assert retrieved is not None
    assert retrieved.action_id == safe_action.action_id
    assert retrieved.agent.agent_id == safe_action.agent.agent_id
    assert retrieved.capability == safe_action.capability

    # Non-existent action returns None
    missing = await storage.get_action("non-existent-id")
    assert missing is None

    await storage.close()


@pytest.mark.asyncio
async def test_sqlite_policy_management(temp_db_path: Path) -> None:
    """Test saving, retrieving, and listing policy rules."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    policy = PolicyRule(
        rule_id="POL-SQLITE-01",
        name="Block Drop Database",
        description="Prevents DROP commands",
        capability_pattern="database.query",
        target_pattern="*",
        action_effect=VerdictDecision.BLOCK,
        risk_level=RiskLevel.CRITICAL,
        is_active=True,
        conditions={"forbidden_words": ["DROP DATABASE"]},
    )

    await storage.save_policy(policy)

    # Get by ID
    loaded = await storage.get_policy("POL-SQLITE-01")
    assert loaded is not None
    assert loaded.name == "Block Drop Database"
    assert loaded.action_effect == VerdictDecision.BLOCK

    # List
    all_policies = await storage.list_policies(active_only=True)
    assert len(all_policies) >= 1
    assert any(p.rule_id == "POL-SQLITE-01" for p in all_policies)

    await storage.close()
