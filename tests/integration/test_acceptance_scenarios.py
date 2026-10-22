"""Integration Acceptance Tests for CCK Layer 1 (Core Reliability Engine).

Covers the mandatory deterministic order status invalidation scenario,
plus all 8 edge cases specified in the requirements.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.journal import JournalEntry
from cck.core.exceptions import EvidenceNotFoundError, VersionConflictError
from cck.core.types import ActionSeverity, DependencyType, JournalEventType, VerdictDecision
from cck.reliability.action_gate import ActionGate
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.reliability.freshness_engine import FreshnessEngine
from cck.reliability.replay_engine import ReplayEngine
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.fixture
def agent() -> AgentIdentity:
    return AgentIdentity(
        agent_id="agt-fulfillment-ai",
        name="AutomatedFulfillmentWorker",
        version="1.0.0",
        trust_tier="standard",
    )


@pytest.mark.asyncio
async def test_mandatory_acceptance_order_invalidation_scenario(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """MANDATORY DETERMINISTIC ACCEPTANCE SCENARIO:

    1. Read order status as 'paid'.
    2. Record system evidence and link action dependency.
    3. Before execution, order status is updated to 'refunded' via a trusted webhook.
    4. An autonomous action attempts to fulfill the order relying on the old 'paid' status.
    5. CCK ActionGate must detect that the dependency is no longer valid and BLOCK the action!
    """
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    freshness = FreshnessEngine(fact_registry=fact_reg, dependency_graph=dep_graph)
    gate = ActionGate(
        evidence_registry=evidence_reg,
        fact_registry=fact_reg,
        dependency_graph=dep_graph,
    )

    order_id = "order:1099"
    fact_node_id = DependencyGraph.format_fact_node_id(order_id, "status")
    action_id = "act:ship_parcel_99"

    # Step 1: Read order status as 'paid' & record evidence
    evidence_paid = await evidence_reg.record_evidence(
        entity_id=order_id,
        field_name="status",
        raw_payload={"order_id": "1099", "status": "paid", "amount": 120.0},
        source="stripe_webhook",
    )

    # Step 2: Record fact & register dependency in the graph
    await freshness.process_incoming_observation(
        entity_id=order_id,
        entity_type="order",
        field_name="status",
        new_value="paid",
        source="stripe_webhook",
        version=1,
        evidence_id=evidence_paid.evidence_id,
    )

    dep_graph.add_node(fact_node_id, DependencyType.FACT)
    dep_graph.add_node(action_id, DependencyType.ACTION)
    dep_graph.add_dependency(dependent_node_id=action_id, prerequisite_node_id=fact_node_id)

    action = AgentAction(
        action_id=action_id,
        agent=agent,
        session_id="sess-ship-1",
        capability="logistics.ship",
        target="courier.fedex",
        parameters={"order_id": order_id, "warehouse": "east_hub"},
        severity=ActionSeverity.MUTATION,
    )

    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-ship-1",
        required_facts=[(order_id, "status")],
        claimed_evidence_ids=[evidence_paid.evidence_id],
    )

    # Pre-check: while 'paid', action gate passes
    initial_verdict = await gate.evaluate_action(action=action, spec=spec)
    assert initial_verdict.decision == VerdictDecision.ALLOW

    # Step 3: Reliable update arrives from payment gateway updating status to 'refunded'
    await evidence_reg.record_evidence(
        entity_id=order_id,
        field_name="status",
        raw_payload={"order_id": "1099", "status": "refunded", "reason": "fraud_alert"},
        source="stripe_webhook",
    )

    # Mark the previous fact state as INVALIDATED due to status change
    await fact_reg.invalidate_fact(order_id, "status", reason="Status changed to refunded")

    # Step 4 & 5: Autonomous agent attempts to execute shipping based on old state
    subsequent_verdict = await gate.evaluate_action(action=action, spec=spec)

    # The gate must detect that the required fact is INVALIDATED and BLOCK the action!
    assert subsequent_verdict.decision == VerdictDecision.BLOCK
    assert "has been INVALIDATED" in subsequent_verdict.reason
    assert subsequent_verdict.risk_score >= 0.9

    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_1_fact_with_no_evidence(temp_db_path: Path) -> None:
    """Edge Case 1: Attempting to link a fact to non-existent evidence."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    fact_reg = FactRegistry(storage=storage)

    with pytest.raises(EvidenceNotFoundError):
        await fact_reg.record_fact(
            entity_id="order:1",
            field_name="status",
            value="paid",
            source="unknown",
            evidence_id="evi_missing_evidence_999",
        )
    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_2_unknown_fabricated_evidence(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Edge Case 2: Action claiming unknown / fabricated evidence ID is blocked."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    action = AgentAction(
        action_id="act-fake",
        agent=agent,
        session_id="sess-fake",
        capability="api.write",
        target="endpoint",
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-fake",
        required_facts=[],
        claimed_evidence_ids=["evi_nonexistent_hallucinated_proof"],
    )

    verdict = await gate.evaluate_action(action=action, spec=spec)
    assert verdict.decision == VerdictDecision.BLOCK
    assert "fabricated evidence" in verdict.reason

    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_3_unrelated_field_change(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Edge Case 3: Changing customer_note does NOT invalidate dependency on order.status."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    freshness = FreshnessEngine(fact_registry=fact_reg, dependency_graph=dep_graph)
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    order_id = "order:300"
    evi = await evidence_reg.record_evidence(order_id, "status", {"status": "paid"}, "source")
    await fact_reg.record_fact(order_id, "status", "paid", "source", evidence_id=evi.evidence_id, ttl_seconds=600)

    # Now update unrelated field 'customer_note'
    _, invalidated = await freshness.process_incoming_observation(
        entity_id=order_id,
        entity_type="order",
        field_name="customer_note",
        new_value="Please leave at doorstep",
        source="customer",
        version=1,
    )
    assert len(invalidated) == 0

    # Action depending on status remains completely ALLOWED
    action = AgentAction(action_id="act-300", agent=agent, session_id="s3", capability="ship.order", target="wh")
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="d3",
        required_facts=[(order_id, "status")],
        claimed_evidence_ids=[evi.evidence_id],
    )
    verdict = await gate.evaluate_action(action=action, spec=spec)
    assert verdict.decision == VerdictDecision.ALLOW

    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_4_fact_freshness_expiration(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Edge Case 4: Expired TTL causes fact to degrade to STALE, resulting in REVALIDATE."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=DependencyGraph())

    t0 = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
    evi = await evidence_reg.record_evidence("sensor:1", "temperature", 22.0, "thermometer", observed_at=t0)
    await fact_reg.record_fact("sensor:1", "temperature", 22.0, "thermometer", evidence_id=evi.evidence_id, ttl_seconds=10.0, observed_at=t0)

    action = AgentAction(action_id="act-cool", agent=agent, session_id="s4", capability="hvac.cool", target="room1")
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="d4",
        required_facts=[("sensor:1", "temperature")],
        claimed_evidence_ids=[evi.evidence_id],
    )

    # 15 seconds later -> TTL expired -> REVALIDATE
    t_later = t0 + timedelta(seconds=15)
    verdict = await gate.evaluate_action(action=action, spec=spec, current_time=t_later)
    assert verdict.decision == VerdictDecision.REVALIDATE
    assert "is STALE" in verdict.reason

    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_5_duplicate_and_out_of_order_event(temp_db_path: Path) -> None:
    """Edge Case 5: Duplicate events are accepted idempotently, out-of-order events are rejected."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    freshness = FreshnessEngine(fact_registry=FactRegistry(storage=storage), dependency_graph=DependencyGraph())

    # Version 2
    f2, inv2 = await freshness.process_incoming_observation("acc:1", "account", "tier", "gold", "crm", version=2)
    assert f2.version == 2

    # Duplicate version 2 with same value
    f_dup, inv_dup = await freshness.process_incoming_observation("acc:1", "account", "tier", "gold", "crm", version=2)
    assert len(inv_dup) == 0

    # Delayed version 1 -> rejected
    with pytest.raises(VersionConflictError):
        await freshness.process_incoming_observation("acc:1", "account", "tier", "silver", "crm", version=1)

    await storage.close()


@pytest.mark.asyncio
async def test_edge_case_6_replay_attempt_executes_zero_external_actions() -> None:
    """Edge Case 6: Replay strictly ensures ZERO external actions are executed."""
    replay_engine = ReplayEngine()
    now = datetime(2026, 10, 18, 11, 0, 0, tzinfo=timezone.utc)

    # Synthetic session with action executed
    journal_entries = [
        JournalEntry(
            entry_id="j-act-1",
            timestamp=now,
            correlation_id="sess-rep-test",
            event_type=JournalEventType.ACTION_EXECUTED,
            policy_version="1.0.0",
            payload={"action_id": "act-real-write", "command": "rm -rf /test"},
        )
    ]

    report = await replay_engine.replay_session(journal_entries=journal_entries)
    # Crucial assertion: ZERO external executions
    assert report.external_actions_executed == 0


@pytest.mark.asyncio
async def test_edge_case_7_policy_version_mismatch() -> None:
    """Edge Case 7: Replay with diverging policy version is detected and flagged."""
    replay_engine = ReplayEngine()
    now = datetime(2026, 10, 18, 11, 0, 0, tzinfo=timezone.utc)

    journal_entries = [
        JournalEntry(
            entry_id="j-pol-v1",
            timestamp=now,
            correlation_id="sess-pol-test",
            event_type=JournalEventType.FACT_OBSERVED,
            policy_version="1.0.0",
            payload={"entity_id": "e", "field_name": "f", "value": 1, "source": "s"},
        )
    ]

    report = await replay_engine.replay_session(journal_entries=journal_entries, expected_policy_version="2.0.0")
    assert report.is_fully_reproducible is False
    assert report.divergent_steps == 1
    assert "Policy version mismatch" in report.divergence_details[0]


@pytest.mark.asyncio
async def test_edge_case_8_decision_missing_essential_dependency(temp_db_path: Path, agent: AgentIdentity) -> None:
    """Edge Case 8: Action referencing an unregistered / unknown required fact is blocked."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    gate = ActionGate(
        evidence_registry=EvidenceRegistry(storage=storage),
        fact_registry=FactRegistry(storage=storage),
        dependency_graph=DependencyGraph(),
    )

    action = AgentAction(action_id="act-missing-dep", agent=agent, session_id="s8", capability="p.exec", target="t")
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="d8",
        required_facts=[("non_existent_entity", "missing_field")],
        claimed_evidence_ids=[],
    )

    verdict = await gate.evaluate_action(action=action, spec=spec)
    assert verdict.decision == VerdictDecision.BLOCK
    assert "is unknown or has no recorded observations" in verdict.reason

    await storage.close()
