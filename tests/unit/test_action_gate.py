"""Unit tests for Action Gate."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.core.types import ActionSeverity, VerdictDecision
from cck.reliability.action_gate import ActionGate
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.fixture
def agent() -> AgentIdentity:
    return AgentIdentity(agent_id="agt-gate-test", name="GateTester")


@pytest.mark.asyncio
async def test_action_gate_allow_valid_fresh_preconditions(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Action with fresh facts and authentic evidence is ALLOWED."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    # 1. Authentic evidence
    evidence = await evidence_reg.record_evidence(
        entity_id="order:100",
        field_name="status",
        raw_payload={"status": "paid"},
        source="stripe",
    )

    # 2. Valid fresh fact
    await fact_reg.record_fact(
        entity_id="order:100",
        field_name="status",
        value="paid",
        source="stripe",
        evidence_id=evidence.evidence_id,
        ttl_seconds=300.0,
    )

    action = AgentAction(
        action_id="act-fulfill-01",
        agent=agent,
        session_id="sess-01",
        capability="shipping.dispatch",
        target="warehouse",
        severity=ActionSeverity.STANDARD,
    )

    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-01",
        required_facts=[("order:100", "status")],
        claimed_evidence_ids=[evidence.evidence_id],
    )

    verdict = await gate.evaluate_action(action=action, spec=spec)
    assert verdict.decision == VerdictDecision.ALLOW
    assert verdict.risk_score < 0.3

    await storage.close()


@pytest.mark.asyncio
async def test_action_gate_block_on_fabricated_evidence(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Action claiming untracked / fabricated evidence is BLOCKED."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    action = AgentAction(
        action_id="act-fake-evi",
        agent=agent,
        session_id="sess-02",
        capability="billing.charge",
        target="gateway",
    )

    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-02",
        required_facts=[],
        claimed_evidence_ids=["evi_hallucinated_untracked_citation"],
    )

    verdict = await gate.evaluate_action(action=action, spec=spec)
    assert verdict.decision == VerdictDecision.BLOCK
    assert "unknown/fabricated evidence" in verdict.reason

    await storage.close()


@pytest.mark.asyncio
async def test_action_gate_revalidate_on_stale_fact(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Action requiring a STALE fact (TTL expired) receives REVALIDATE verdict."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    t0 = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    evi = await evidence_reg.record_evidence("inv:item9", "qty", 10, "rfid", observed_at=t0)
    await fact_reg.record_fact(
        entity_id="inv:item9",
        field_name="qty",
        value=10,
        source="rfid",
        evidence_id=evi.evidence_id,
        ttl_seconds=30.0,
        observed_at=t0,
    )

    action = AgentAction(
        action_id="act-pick-item",
        agent=agent,
        session_id="sess-03",
        capability="robotics.pick",
        target="bin-9",
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-03",
        required_facts=[("inv:item9", "qty")],
        claimed_evidence_ids=[evi.evidence_id],
    )

    # Evaluate at t0 + 100s (exceeds TTL 30s)
    t_later = t0 + timedelta(seconds=100)
    verdict = await gate.evaluate_action(action=action, spec=spec, current_time=t_later)

    assert verdict.decision == VerdictDecision.REVALIDATE
    assert "is STALE" in verdict.reason

    await storage.close()
