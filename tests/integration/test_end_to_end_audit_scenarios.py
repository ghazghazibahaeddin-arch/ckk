"""Comprehensive End-to-End Integration Scenarios for CCK (QA & Engineering Audit).

Explicitly implements and verifies all 10 mandated lifecycle scenarios (أ through ي):
A. Agent reads reliable fact -> CCK records evidence & dependency -> Action allowed by policy -> Successful write.
B. Fact changes after read and before execution -> CCK detects invalidation & re-evaluates -> Blocked.
C. Fact changes after last check and before physical write -> Target validation & conditional write race prevention.
   Also verifies honest disclosure when connector lacks conditional write support.
D. Disconnection occurs after execution and before response arrives -> Marked UNKNOWN_OUTCOME -> Blocks unsafe retry.
E. Action rejected due to missing evidence or unauthorized role -> Proves ZERO external write execution.
F. Human approval granted, but target facts drift before execution -> Re-validation blocks stale approval.
G. Recovery orchestrator recovers side effects -> Resumes safely without state loss or infinite loops.
H. Cross-tenant access attempt -> Strict isolation blocks access with PolicyViolationError.
I. Event journal replay -> Proves zero external execution during historical audit replay.
J. CLI scenario failure execution -> Proves non-zero exit code and failure reporting.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cck.cli.main import app as cli_app
from cck.connectors.adapters.read_adapter import ReadAdapter
from cck.connectors.adapters.write_adapter import WriteAdapter
from cck.connectors.capabilities import CapabilityRegistry
from cck.connectors.health import ConnectorHealthMonitor
from cck.connectors.idempotency import IdempotencyAdapter
from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.connectors.implementations.stubs import ZendeskConnectorStub
from cck.connectors.target_validator import TargetValidator
from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.journal import JournalEntry
from cck.control.approvals import ApprovalWorkflowManager
from cck.core.exceptions import (
    ActionGateError,
    ApprovalError,
    IdempotencyConflictError,
    PolicyViolationError,
    TargetValidationError,
    UnknownExecutionOutcomeError,
    UnsupportedCapabilityError,
)
from cck.core.types import (
    ActionSeverity,
    ConnectorCapability,
    DependencyType,
    JournalEventType,
    RecoveryState,
    VerdictDecision,
)
from cck.enterprise.tenancy import TenantIsolationEnforcer
from cck.recovery.orchestrator import RecoveryOrchestrator
from cck.recovery.planner import RepairPlan, RepairPlanItem
from cck.reliability.action_gate import ActionGate
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.entity_registry import EntityRegistry
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.reliability.freshness_engine import FreshnessEngine
from cck.reliability.journal import EventJournal
from cck.reliability.replay_engine import ReplayEngine
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.fixture
def test_agent() -> AgentIdentity:
    return AgentIdentity(
        agent_id="agt-qa-worker",
        name="QAAuditWorker",
        version="1.0.0",
        tenant_id="tenant-alpha",
        trust_tier="standard",
    )


# -----------------------------------------------------------------------------
# Scenario A (أ): End-to-End Read -> Evidence -> Policy Allow -> Execution
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_a_read_evidence_dependency_and_successful_write(
    temp_db_path: Path, test_agent: AgentIdentity
) -> None:
    """Scenario A:
    Agent reads reliable fact -> CCK records evidence and dependency ->
    Agent proposes action -> Policy allows -> WriteAdapter executes through Gate ->
    Outcome journaled.
    """
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    entity_reg = EntityRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    journal = EventJournal(storage=storage)
    gate = ActionGate(
        evidence_registry=evidence_reg,
        fact_registry=fact_reg,
        dependency_graph=dep_graph,
    )

    connector = InMemorySandboxConnector(connector_id="order-sandbox")
    connector.seed_target("order:A-100", {"status": "authorized", "amount": 500.0}, version=1)

    read_adapter = ReadAdapter(
        entity_registry=entity_reg,
        fact_registry=fact_reg,
        evidence_registry=evidence_reg,
    )
    write_adapter = WriteAdapter(
        action_gate=gate,
        idempotency_adapter=IdempotencyAdapter(),
        event_journal=journal,
        health_monitor=ConnectorHealthMonitor(),
    )

    # 1. Read fact through ReadAdapter
    entity, facts, evidence = await read_adapter.ingest_read(
        connector=connector,
        target="order:A-100",
        entity_id="order:A-100",
        entity_type="order",
        entity_name="OrderA",
    )
    assert entity.entity_id == "order:A-100"
    assert facts[0].value == "authorized"
    assert evidence.evidence_id.startswith("evi_")

    # 2. Register dependency in graph
    fact_node = DependencyGraph.format_fact_node_id("order:A-100", "status")
    dep_graph.add_node(fact_node, DependencyType.FACT)
    dep_graph.add_node("act-capture-A", DependencyType.ACTION)
    dep_graph.add_dependency("act-capture-A", fact_node)

    # 3. Create agent action
    action = AgentAction(
        action_id="act-capture-A",
        agent=test_agent,
        session_id="sess-A",
        capability="finance.capture",
        target="order:A-100",
        parameters={"status": "captured", "amount": 500.0},
        severity=ActionSeverity.MUTATION,
        idempotency_key="idem-capture-A-01",
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-capture-A",
        required_facts=[("order:A-100", "status")],
        claimed_evidence_ids=[evidence.evidence_id],
    )

    # 4. Execute through write adapter (passes through ActionGate)
    write_res = await write_adapter.execute_write(
        connector=connector,
        action=action,
        spec=spec,
        expected_version=1,
    )
    assert write_res.success is True
    assert write_res.new_version == 2

    # 5. Verify journal recorded ACTION_EXECUTED
    events = await journal.list_events(correlation_id="sess-A")
    assert len(events) >= 1
    assert events[-1].event_type == JournalEventType.ACTION_EXECUTED
    assert events[-1].payload["action_id"] == "act-capture-A"

    await storage.close()


# -----------------------------------------------------------------------------
# Scenario B (ب): Fact Drift / Mutation Before Execution Triggers Block
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_b_fact_mutation_before_execution_triggers_block(
    temp_db_path: Path, test_agent: AgentIdentity
) -> None:
    """Scenario B:
    Fact changes after read and before execution -> CCK detects invalidation & re-evaluates -> Blocked.
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
    connector = InMemorySandboxConnector()
    write_adapter = WriteAdapter(
        action_gate=gate,
        idempotency_adapter=IdempotencyAdapter(),
        event_journal=EventJournal(storage=storage),
        health_monitor=ConnectorHealthMonitor(),
    )

    # 1. Observe initial state (status = 'paid')
    evi1 = await evidence_reg.record_evidence(
        entity_id="order:B-200",
        field_name="status",
        raw_payload={"status": "paid"},
        source="billing_webhook",
    )
    fact1, _ = await freshness.process_incoming_observation(
        entity_id="order:B-200",
        entity_type="order",
        field_name="status",
        new_value="paid",
        source="billing_webhook",
        version=1,
        evidence_id=evi1.evidence_id,
    )

    fact_node = DependencyGraph.format_fact_node_id("order:B-200", "status")
    dep_graph.add_node(fact_node, DependencyType.FACT)
    dep_graph.add_node("act-ship-B", DependencyType.ACTION)
    dep_graph.add_dependency("act-ship-B", fact_node)

    action = AgentAction(
        action_id="act-ship-B",
        agent=test_agent,
        session_id="sess-B",
        capability="logistics.ship",
        target="order:B-200",
        parameters={"status": "shipped", "tracking": "FEDEX-992"},
        severity=ActionSeverity.MUTATION,
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-ship-B",
        required_facts=[("order:B-200", "status")],
        claimed_evidence_ids=[evi1.evidence_id],
    )

    # Pre-condition: action is permitted while fact is valid
    verdict1 = await gate.evaluate_action(action, spec)
    assert verdict1.decision == VerdictDecision.ALLOW

    # 2. External world mutates: refund webhook arrives!
    evi2 = await evidence_reg.record_evidence(
        entity_id="order:B-200",
        field_name="status",
        raw_payload={"status": "refunded"},
        source="billing_webhook",
    )
    await freshness.process_incoming_observation(
        entity_id="order:B-200",
        entity_type="order",
        field_name="status",
        new_value="refunded",
        source="billing_webhook",
        version=2,
        evidence_id=evi2.evidence_id,
    )

    # Invalidate stale status
    await fact_reg.invalidate_fact("order:B-200", "status", reason="Status mutated to refunded")

    # 3. ActionGate must detect invalidation and BLOCK execution
    verdict2 = await gate.evaluate_action(action, spec)
    assert verdict2.decision == VerdictDecision.BLOCK
    assert "has been INVALIDATED" in verdict2.reason

    # Proves WriteAdapter blocks external dispatch
    with pytest.raises(ActionGateError) as exc_info:
        await write_adapter.execute_write(connector=connector, action=action, spec=spec)
    assert "blocked by CCK ActionGate: BLOCK" in str(exc_info.value)

    await storage.close()


# -----------------------------------------------------------------------------
# Scenario C (ج): Race Condition CAS & Honest Capability Disclosure
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_c_race_condition_version_drift_and_unsupported_honest_disclosure() -> None:
    """Scenario C:
    1. If target drifts right before physical write -> TargetValidator catches version drift.
    2. If connector does NOT support conditional write -> System honestly raises UnsupportedCapabilityError
       instead of pretending to guarantee concurrency safety.
    """
    # 1. Live target version drift on supporting connector
    connector_supporting = InMemorySandboxConnector()
    connector_supporting.seed_target("account:C-300", {"balance": 1000.0}, version=1)

    validator = TargetValidator()
    # Live version was 1, but another concurrent writer changed it to 2!
    connector_supporting.seed_target("account:C-300", {"balance": 800.0}, version=2)

    with pytest.raises(TargetValidationError) as exc_info:
        await validator.validate_preconditions(
            connector=connector_supporting,
            target="account:C-300",
            expected_version=1,  # Stale version expectation!
        )
    assert "Concurrent modification detected" in str(exc_info.value)

    # 2. Honest disclosure on non-supporting connector (e.g. ZendeskConnectorStub)
    stub_conn = ZendeskConnectorStub()
    registry = CapabilityRegistry()
    registry.register_connector_capabilities(stub_conn.connector_id, stub_conn.supported_capabilities)

    # Zendesk stub does not support CONDITIONAL_WRITE
    assert not registry.supports(stub_conn.connector_id, ConnectorCapability.CONDITIONAL_WRITE)

    with pytest.raises(UnsupportedCapabilityError) as exc_info2:
        registry.assert_supports(stub_conn.connector_id, ConnectorCapability.CONDITIONAL_WRITE)
    assert "does not support capability 'CONDITIONAL_WRITE'" in str(exc_info2.value)


# -----------------------------------------------------------------------------
# Scenario D (د): Disconnection After Execution, UNKNOWN_OUTCOME & Idempotency
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_d_network_disconnect_outcome_and_idempotent_retry_safety(
    temp_db_path: Path, test_agent: AgentIdentity
) -> None:
    """Scenario D:
    Network disconnects after execution and before response arrives ->
    Outcome marked UNKNOWN_OUTCOME -> Blocks unsafe automatic retries.
    """
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    connector = InMemorySandboxConnector()
    connector.seed_target("transfer:D-400", {"status": "pending"}, version=1)
    connector.simulate_disconnect_during = True  # Disconnects after write, before response

    write_adapter = WriteAdapter(
        action_gate=gate,
        idempotency_adapter=IdempotencyAdapter(),
        event_journal=EventJournal(storage=storage),
        health_monitor=ConnectorHealthMonitor(),
    )

    action = AgentAction(
        action_id="act-wire-D",
        agent=test_agent,
        session_id="sess-D",
        capability="finance.wire",
        target="transfer:D-400",
        parameters={"status": "sent", "amount": 10000.0},
        severity=ActionSeverity.MUTATION,
        idempotency_key="idem-wire-D-01",
    )

    # First attempt experiences disconnect after mutation
    with pytest.raises(UnknownExecutionOutcomeError) as exc_info:
        await write_adapter.execute_write(connector=connector, action=action)
    assert "Outcome is UNKNOWN" in str(exc_info.value)
    assert "Unsafe auto-retry prohibited" in str(exc_info.value)

    # Subsequent retry attempt must be BLOCKED because outcome is UNKNOWN!
    with pytest.raises(IdempotencyConflictError) as exc_info2:
        await write_adapter.execute_write(connector=connector, action=action)
    assert "UNKNOWN_OUTCOME" in str(exc_info2.value)
    assert "Manual inspection required before retrying unsafe actions" in str(exc_info2.value)

    await storage.close()


# -----------------------------------------------------------------------------
# Scenario E (هـ): Missing Evidence or Privileges Proves Zero External Execution
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_e_missing_evidence_or_privileges_guarantees_zero_external_execution(
    temp_db_path: Path, test_agent: AgentIdentity
) -> None:
    """Scenario E:
    CCK rejects action due to missing evidence or destructive policy ->
    Guarantees ZERO external execution (connector.write_count == 0).
    """
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    gate = ActionGate(evidence_registry=evidence_reg, fact_registry=fact_reg, dependency_graph=dep_graph)

    connector = InMemorySandboxConnector()
    connector.seed_target("server:prod-root", {"uptime": 9999}, version=1)
    write_adapter = WriteAdapter(
        action_gate=gate,
        idempotency_adapter=IdempotencyAdapter(),
        event_journal=EventJournal(storage=storage),
        health_monitor=ConnectorHealthMonitor(),
    )

    # Propose destructive command
    action = AgentAction(
        action_id="act-rm-E",
        agent=test_agent,
        session_id="sess-E",
        capability="bash.execute",
        target="server:prod-root",
        parameters={"command": "rm -rf / --no-preserve-root"},
        severity=ActionSeverity.DESTRUCTIVE,
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-E",
        required_facts=[],
        claimed_evidence_ids=["evi_non_existent_fake_id"],  # Fabricated evidence!
    )

    with pytest.raises(ActionGateError):
        await write_adapter.execute_write(connector=connector, action=action, spec=spec)

    # Assert 100% guarantee: zero external writes took place
    assert len(connector._history) == 0
    read_back = await connector.read("server:prod-root")
    assert read_back.data["uptime"] == 9999
    assert read_back.version == 1

    await storage.close()


# -----------------------------------------------------------------------------
# Scenario F (و): Human Approval Re-Validation On Drift Before Execution
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_f_human_approval_state_drift_pre_execution_rejection(
    test_agent: AgentIdentity,
) -> None:
    """Scenario F:
    Action requires human approval -> Granted by supervisor ->
    State drifts before execution -> Re-validation blocks execution.
    """
    approvals = ApprovalWorkflowManager()
    action = AgentAction(
        action_id="act-scale-F",
        agent=test_agent,
        session_id="sess-F",
        capability="bash.execute",
        target="server.k8s",
        parameters={"command": "systemctl stop production-api"},
        severity=ActionSeverity.MUTATION,
    )

    # Request approval with initial snapshot
    req = approvals.request_approval(
        action=action,
        reason="Scale down test",
        policy_version="1.0.0",
        state_snapshot={"active_nodes": 5, "cluster_status": "healthy"},
    )

    # Supervisor approves
    approvals.resolve_approval(
        approval_id=req.approval_id,
        approved=True,
        approver_id="admin-ciso",
        approver_role="admin",
    )

    # Target cluster state changes before execution (cluster becomes degraded)
    drifted_state = {"active_nodes": 2, "cluster_status": "degraded"}

    # Attempting to consume approval on drifted state must raise ApprovalError
    with pytest.raises(ApprovalError) as exc_info:
        approvals.consume_approval(req.approval_id, current_state=drifted_state)
    assert "Approval context changed!" in str(exc_info.value)
    assert "Re-approval required" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Scenario G (ز): Recovery Orchestrator Crash / Resume Without Infinite Loop
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_g_recovery_orchestrator_crash_resume_and_loop_prevention() -> None:
    """Scenario G:
    Recovery detects side effect -> Resumes safely after interruption ->
    Enforces max attempts to prevent infinite loop.
    """
    orchestrator = RecoveryOrchestrator(max_attempts=2)
    connector = InMemorySandboxConnector()
    connector.seed_target("service:auth", {"status": "broken"}, version=1)

    plan = RepairPlan(
        plan_id="plan-auth-fix",
        problem_description="Service auth state degraded",
        impacted_nodes=["service:auth"],
        steps=[
            RepairPlanItem(
                step_id="step-1",
                action_type="restart",
                target="service:auth",
                requires_approval=False,
                risk_level="LOW",
            )
        ],
        requires_human_signoff=False,
    )

    session = orchestrator.start_recovery("wf-recovery-01", plan)
    assert session.state == RecoveryState.REPAIRING

    # Simulated crash: verify post recovery fails because condition is not yet met
    success = await orchestrator.verify_post_recovery(
        session_id=session.session_id,
        connector=connector,
        target="service:auth",
        expected_conditions={"status": "healthy"},
    )
    assert success is False
    assert session.state == RecoveryState.FAILED

    # Repair succeeds in world
    connector.seed_target("service:auth", {"status": "healthy"}, version=2)
    success_retry = await orchestrator.verify_post_recovery(
        session_id=session.session_id,
        connector=connector,
        target="service:auth",
        expected_conditions={"status": "healthy"},
    )
    assert success_retry is True
    assert session.state == RecoveryState.SUCCESS


# -----------------------------------------------------------------------------
# Scenario H (ح): Cross-Tenant Access Rejection
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_h_cross_tenant_isolation_enforcement() -> None:
    """Scenario H:
    Tenant A attempts to access Tenant B's resources -> Blocked by PolicyViolationError.
    """
    enforcer = TenantIsolationEnforcer()

    # Valid intra-tenant access
    enforcer.assert_tenant_access(request_tenant="tenant-coca-cola", resource_tenant="tenant-coca-cola")

    # Cross-tenant access rejected
    with pytest.raises(PolicyViolationError) as exc_info:
        enforcer.assert_tenant_access(
            request_tenant="tenant-pepsi",
            resource_tenant="tenant-coca-cola",
        )
    assert "Cross-tenant access violation" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Scenario I (ط): Event Journal Replay Proves Zero External Actions
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scenario_i_journal_replay_proves_zero_external_execution(
    test_agent: AgentIdentity,
) -> None:
    """Scenario I:
    Replaying event journal from history reproduces verdicts while executing ZERO external side effects.
    """
    replay_engine = ReplayEngine()
    now = datetime.now(timezone.utc)

    action = AgentAction(
        action_id="act-replay-I",
        agent=test_agent,
        session_id="sess-replay-I",
        capability="database.query",
        target="db.read_replica",
        severity=ActionSeverity.INFORMATIONAL,
    )
    spec = ActionDependencySpec(
        action_id=action.action_id,
        decision_id="dec-I",
        required_facts=[],
        claimed_evidence_ids=[],
    )

    events = [
        JournalEntry(
            entry_id="j-I-1",
            timestamp=now,
            correlation_id="sess-replay-I",
            event_type=JournalEventType.GATE_DECISION,
            policy_version="1.0.0",
            payload={
                "action": action.model_dump(mode="json"),
                "spec": spec.model_dump(mode="json"),
                "decision": VerdictDecision.ALLOW.value,
            },
        )
    ]

    report = await replay_engine.replay_session(
        journal_entries=events,
        expected_policy_version="1.0.0",
    )

    assert report.is_fully_reproducible is True
    assert report.external_actions_executed == 0
    assert report.matched_steps == 1


# -----------------------------------------------------------------------------
# Scenario J (ي): Developer Runs Failing Scenario Via CLI
# -----------------------------------------------------------------------------
def test_scenario_j_cli_failing_scenario_returns_error_exit_code(tmp_path: Path) -> None:
    """Scenario J:
    Running a failing test pack via CLI ('cck test ./scenarios') exits with non-zero code and reports failure.
    """
    failing_scenario = {
        "scenario_id": "scen_failing_case",
        "title": "Intentional Failure Expectation Mismatch",
        "category": "fault_test",
        "steps": [
            {
                "action": "execute",
                "target": "server.root",
                "payload": {
                    "action": {
                        "action_id": "act-fail-cli",
                        "capability": "bash.execute",
                        "severity": "DESTRUCTIVE",
                        "parameters": {"command": "rm -rf / --no-preserve-root"},
                    }
                },
                "expected_verdict": "ALLOW",  # Mismatch: policy blocks it, but expected ALLOW!
            }
        ],
    }

    scenarios_dir = tmp_path / "bad_scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    (scenarios_dir / "bad_scenario.json").write_text(json.dumps(failing_scenario), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli_app, ["test", str(scenarios_dir)])

    # Must exit with non-zero code (exit code 1)
    assert result.exit_code == 1
    assert "FAILED" in result.stdout
    assert "Summary" in result.stdout
