"""Integration tests verifying the CCK Connectors & Execution Adapters pipeline (Layer 2).

Verifies the integration of:
1. ReadAdapter with EntityRegistry, FactRegistry, and EvidenceRegistry.
2. WriteAdapter zero-bypass execution through ActionGate, TargetValidator, and IdempotencyAdapter.
3. Write blocked when dependent fact becomes stale or invalidated by upstream events.
4. TargetValidator preventing writes when external resource state drifts concurrently.
5. Idempotent re-execution returning cached response without re-invoking external connector.
6. Network disconnection before dispatch, during dispatch, and prohibition of unsafe auto-retry.
7. Secrets sanitization in EventJournal and execution receipts.
"""

from pathlib import Path

import pytest

from cck.connectors.adapters.read_adapter import ReadAdapter
from cck.connectors.adapters.write_adapter import WriteAdapter
from cck.connectors.health import ConnectorHealthMonitor
from cck.connectors.idempotency import IdempotencyAdapter
from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.core.exceptions import (
    ActionGateError,
    IdempotencyConflictError,
    TargetValidationError,
    UnknownExecutionOutcomeError,
)
from cck.core.types import (
    ActionSeverity,
    DependencyType,
    FactState,
    JournalEventType,
)
from cck.reliability.action_gate import ActionGate
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.entity_registry import EntityRegistry
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.reliability.freshness_engine import FreshnessEngine
from cck.reliability.journal import EventJournal
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.fixture
def agent() -> AgentIdentity:
    return AgentIdentity(
        agent_id="agt-integration-worker",
        name="ConnectorIntegrationAgent",
        version="1.0.0",
        trust_tier="standard",
    )


@pytest.mark.asyncio
async def test_read_adapter_end_to_end_ingestion(temp_db_path: Path) -> None:
    """ReadAdapter ingests external reading into EntityRegistry, FactRegistry, and EvidenceRegistry."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    entity_reg = EntityRegistry(storage=storage)

    read_adapter = ReadAdapter(
        entity_registry=entity_reg,
        fact_registry=fact_reg,
        evidence_registry=evidence_reg,
    )

    connector = InMemorySandboxConnector(connector_id="crm-sandbox")
    connector.seed_target(
        "customer:c-100",
        {"name": "Acme Corp", "tier": "enterprise", "mrr": 5000},
        version=1,
    )

    # Ingest read
    entity, facts, evidence = await read_adapter.ingest_read(
        connector=connector,
        target="customer:c-100",
        entity_id="customer:c-100",
        entity_type="customer",
        entity_name="Acme Corp",
    )

    assert entity.entity_id == "customer:c-100"
    assert entity.attributes["tier"] == "enterprise"
    assert evidence is not None
    assert evidence.evidence_id.startswith("evi_")
    assert evidence.source == "crm-sandbox"

    # Verify facts were created in registry with system evidence
    assert len(facts) == 3
    tier_fact = await fact_reg.get_fact("customer:c-100", "tier")
    assert tier_fact is not None
    assert tier_fact.value == "enterprise"
    assert tier_fact.evidence_id == evidence.evidence_id
    assert tier_fact.state == FactState.VALID


@pytest.mark.asyncio
async def test_read_adapter_missing_target_marks_unknown(temp_db_path: Path) -> None:
    """ReadAdapter ingesting non-existent target marks facts as UNKNOWN."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    entity_reg = EntityRegistry(storage=storage)

    read_adapter = ReadAdapter(
        entity_registry=entity_reg,
        fact_registry=fact_reg,
        evidence_registry=evidence_reg,
    )

    connector = InMemorySandboxConnector()
    entity, facts, evidence = await read_adapter.ingest_read(
        connector=connector,
        target="missing:res-999",
        entity_id="missing:res-999",
        entity_type="record",
    )

    assert evidence is None
    assert len(facts) == 1
    assert facts[0].state == FactState.UNKNOWN


@pytest.mark.asyncio
async def test_write_adapter_pipeline_success_and_journaling(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """WriteAdapter executes successfully through ActionGate, updates connector, and records in journal."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    journal = EventJournal(storage=storage)
    health = ConnectorHealthMonitor()
    idempotency = IdempotencyAdapter()

    gate = ActionGate(
        evidence_registry=evidence_reg,
        fact_registry=fact_reg,
        dependency_graph=dep_graph,
    )

    write_adapter = WriteAdapter(
        action_gate=gate,
        idempotency_adapter=idempotency,
        event_journal=journal,
        health_monitor=health,
    )

    connector = InMemorySandboxConnector(connector_id="billing-sandbox")
    connector.seed_target("invoice:inv-1", {"status": "unpaid", "amount": 250}, version=1)

    action = AgentAction(
        action_id="act-pay-inv-1",
        agent=agent,
        session_id="sess-pay-1",
        capability="billing.pay",
        target="invoice:inv-1",
        parameters={"status": "paid", "payment_method": "credit_card"},
        severity=ActionSeverity.MUTATION,
        idempotency_key="pay-key-1001",
    )

    res = await write_adapter.execute_write(
        connector=connector,
        action=action,
        expected_version=1,
    )

    assert res.success is True
    assert res.new_version == 2
    assert res.response_data["status"] == "paid"

    # Verify journal entry was recorded
    entries = await journal.list_events(action.session_id)
    assert len(entries) >= 1
    assert entries[-1].event_type == JournalEventType.ACTION_EXECUTED
    assert entries[-1].payload["action_id"] == "act-pay-inv-1"

    # Verify health monitor recorded success
    h = health.get_health("billing-sandbox")
    assert h.healthy is True
    assert h.error_rate == 0.0


@pytest.mark.asyncio
async def test_write_adapter_blocks_on_stale_or_invalidated_fact(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """WriteAdapter strictly rejects execution when a prerequisite fact is invalidated."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    freshness = FreshnessEngine(fact_registry=fact_reg, dependency_graph=dep_graph)
    journal = EventJournal(storage=storage)

    gate = ActionGate(
        evidence_registry=evidence_reg,
        fact_registry=fact_reg,
        dependency_graph=dep_graph,
    )

    write_adapter = WriteAdapter(action_gate=gate, event_journal=journal)

    # 1. Register evidence and fact for order status = 'authorized'
    evidence = await evidence_reg.record_evidence(
        entity_id="order:88",
        field_name="status",
        raw_payload={"status": "authorized"},
        source="stripe_webhook",
    )
    fact, _ = await freshness.process_incoming_observation(
        entity_id="order:88",
        entity_type="order",
        field_name="status",
        new_value="authorized",
        source="stripe_webhook",
        version=1,
        evidence_id=evidence.evidence_id,
    )

    # 2. Register dependency
    fact_node_id = DependencyGraph.format_fact_node_id("order:88", "status")
    action_id = "act-capture-88"
    dep_graph.add_node(fact_node_id, DependencyType.FACT)
    dep_graph.add_node(action_id, DependencyType.ACTION)
    dep_graph.add_dependency(action_id, fact_node_id)

    # 3. Upstream event invalidates fact (order cancelled)
    evidence_cancel = await evidence_reg.record_evidence(
        entity_id="order:88",
        field_name="status",
        raw_payload={"status": "cancelled"},
        source="admin_dashboard",
    )
    await freshness.process_incoming_observation(
        entity_id="order:88",
        entity_type="order",
        field_name="status",
        new_value="cancelled",
        source="admin_dashboard",
        version=2,
        evidence_id=evidence_cancel.evidence_id,
    )
    await fact_reg.invalidate_fact("order:88", "status", reason="Order cancelled")

    connector = InMemorySandboxConnector()
    connector.seed_target("order:88", {"status": "authorized"}, version=1)

    action = AgentAction(
        action_id=action_id,
        agent=agent,
        session_id="sess-88",
        capability="order.capture",
        target="order:88",
        parameters={"capture": True},
        severity=ActionSeverity.MUTATION,
    )

    spec = ActionDependencySpec(
        action_id=action_id,
        decision_id="dec-order-88",
        required_facts=[(fact.entity_id, fact.field_name)],
        claimed_evidence_ids=[evidence.evidence_id],
    )

    # WriteAdapter must block execution via ActionGateError
    with pytest.raises(ActionGateError) as exc_info:
        await write_adapter.execute_write(
            connector=connector,
            action=action,
            spec=spec,
        )
    assert "blocked by CCK ActionGate: BLOCK" in str(exc_info.value)

    # External store was NOT mutated!
    order_state = await connector.read("order:88")
    assert order_state.data["status"] == "authorized"


@pytest.mark.asyncio
async def test_write_adapter_target_version_drift_detection(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """TargetValidator detects live external state version change and halts write."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_reg, fact_reg, dep_graph)

    write_adapter = WriteAdapter(action_gate=gate)

    connector = InMemorySandboxConnector()
    # Live store is at version 3
    connector.seed_target("doc:readme", {"content": "v3 text"}, version=3)

    action = AgentAction(
        action_id="act-write-doc",
        agent=agent,
        session_id="sess-doc",
        capability="docs.update",
        target="doc:readme",
        parameters={"content": "v2 text overwrite"},
        severity=ActionSeverity.STANDARD,
    )

    # Agent expected version 2, but live version is 3
    with pytest.raises(TargetValidationError) as exc_info:
        await write_adapter.execute_write(
            connector=connector,
            action=action,
            expected_version=2,
        )
    assert "Expected version 2, but live version is 3" in str(exc_info.value)
    assert "Concurrent modification detected" in str(exc_info.value)


@pytest.mark.asyncio
async def test_write_adapter_idempotency_returns_cached_result(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """Duplicate write request with the same idempotency key returns cached result without re-executing."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_reg, fact_reg, dep_graph)
    idempotency = IdempotencyAdapter()

    write_adapter = WriteAdapter(action_gate=gate, idempotency_adapter=idempotency)

    connector = InMemorySandboxConnector()
    connector.seed_target("counter:1", {"val": 10}, version=1)

    action = AgentAction(
        action_id="act-increment-1",
        agent=agent,
        session_id="sess-inc",
        capability="counter.inc",
        target="counter:1",
        parameters={"val": 11},
        severity=ActionSeverity.MUTATION,
        idempotency_key="key-inc-counter-001",
    )

    # First execution
    res1 = await write_adapter.execute_write(
        connector=connector,
        action=action,
        idempotency_key="key-inc-counter-001",
    )
    assert res1.success is True
    assert res1.new_version == 2
    assert res1.response_data["val"] == 11

    # Second execution with same idempotency key
    res2 = await write_adapter.execute_write(
        connector=connector,
        action=action,
        idempotency_key="key-inc-counter-001",
    )
    assert res2.success is True
    assert res2.response_data["val"] == 11

    # Counter in store was NOT incremented again
    read_state = await connector.read("counter:1")
    assert read_state.version == 2


@pytest.mark.asyncio
async def test_write_adapter_handles_disconnection_and_marks_unknown_outcome(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """Network connection drop during execution marks UNKNOWN_OUTCOME and prohibits unsafe auto-retry."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_reg, fact_reg, dep_graph)
    idempotency = IdempotencyAdapter()

    write_adapter = WriteAdapter(action_gate=gate, idempotency_adapter=idempotency)

    connector = InMemorySandboxConnector()
    connector.seed_target("transfer:tx-5", {"status": "pending"}, version=1)
    connector.simulate_disconnect_during = True  # Disconnects after mutating, before response

    idem_key = "key-transfer-tx-5"
    action = AgentAction(
        action_id="act-tx-5",
        agent=agent,
        session_id="sess-tx-5",
        capability="banking.transfer",
        target="transfer:tx-5",
        parameters={"status": "executed", "amount": 1000},
        severity=ActionSeverity.MUTATION,
        idempotency_key=idem_key,
    )

    with pytest.raises(UnknownExecutionOutcomeError) as exc_info:
        await write_adapter.execute_write(
            connector=connector,
            action=action,
            idempotency_key=idem_key,
        )
    assert "Outcome is UNKNOWN" in str(exc_info.value)
    assert "Unsafe auto-retry prohibited" in str(exc_info.value)

    # Verify idempotency record reflects UNKNOWN_OUTCOME
    record = await idempotency.get_record(idem_key)
    assert record is not None
    assert record.status.value == "UNKNOWN_OUTCOME"

    # Attempting to re-execute with same key without manual resolution fails
    with pytest.raises(IdempotencyConflictError):
        await write_adapter.execute_write(
            connector=connector,
            action=action,
            idempotency_key=idem_key,
        )


@pytest.mark.asyncio
async def test_write_adapter_secret_scrubbing_in_journal(
    temp_db_path: Path, agent: AgentIdentity
) -> None:
    """WriteAdapter sanitizes secrets in parameters before writing to EventJournal."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    journal = EventJournal(storage=storage)
    gate = ActionGate(evidence_reg, fact_reg, dep_graph)

    write_adapter = WriteAdapter(action_gate=gate, event_journal=journal)

    connector = InMemorySandboxConnector()
    connector.seed_target("config:keys", {"ready": True}, version=1)

    secret_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    action = AgentAction(
        action_id="act-secret-test",
        agent=agent,
        session_id="sess-secret",
        capability="config.set",
        target="config:keys",
        parameters={
            "api_key": secret_token,
            "auth_header": f"Bearer {secret_token}",
            "regular_setting": "dark_mode",
        },
        severity=ActionSeverity.STANDARD,
    )

    await write_adapter.execute_write(connector=connector, action=action)

    # Check journal payload
    entries = await journal.list_events(action.session_id)
    assert len(entries) >= 1
    last_entry = entries[-1]
    params = last_entry.payload["parameters"]

    assert params["api_key"] == "[REDACTED_SECRET]"
    assert params["auth_header"] == "Bearer [REDACTED_SECRET]"
    assert params["regular_setting"] == "dark_mode"
    assert secret_token not in str(last_entry.payload)
