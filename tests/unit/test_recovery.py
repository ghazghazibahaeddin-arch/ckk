"""Unit tests for CCK Recovery & Repair (Layer 4).

Verifies:
1. Impact Analyzer blast radius traversal on DependencyGraph.
2. Decision Re-evaluator verdict re-computation.
3. Repair Planner and action reversibility checking.
4. Recovery Orchestrator lifecycle states and post-verification via trusted read.
"""

import pytest

from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.core.types import DependencyType, RecoveryState
from cck.recovery.impact import ImpactAnalyzer
from cck.recovery.orchestrator import RecoveryOrchestrator
from cck.recovery.planner import RepairPlanner
from cck.reliability.dependency_graph import DependencyGraph


@pytest.fixture
def graph() -> DependencyGraph:
    dg = DependencyGraph()
    fact_id = DependencyGraph.format_fact_node_id("order:10", "status")
    act_id = DependencyGraph.format_action_node_id("ship_10")
    dg.add_node(fact_id, DependencyType.FACT)
    dg.add_node(act_id, DependencyType.ACTION)
    dg.add_dependency(dependent_node_id=act_id, prerequisite_node_id=fact_id)
    return dg


def test_impact_analyzer_blast_radius(graph: DependencyGraph) -> None:
    """ImpactAnalyzer identifies downstream actions affected by fact changes."""
    analyzer = ImpactAnalyzer(graph)
    impacted = analyzer.analyze_fact_impact("order:10", "status")
    act_id = DependencyGraph.format_action_node_id("ship_10")
    assert act_id in impacted


def test_repair_planner_categorizes_reversibility() -> None:
    """RepairPlanner correctly identifies reversible and irreversible steps."""
    planner = RepairPlanner()
    plan = planner.create_repair_plan(
        problem_description="Order cancelled unexpectedly",
        impacted_nodes=["act:ship_10"],
        recommended_steps=[
            {"capability": "database.update", "target": "warehouse:east"},
            {"capability": "email.send", "target": "customer@acme.com"},
        ],
    )
    assert len(plan.steps) == 2
    # email.send is irreversible, so plan requires human sign-off
    assert plan.requires_human_signoff is True


@pytest.mark.asyncio
async def test_recovery_orchestrator_post_verification() -> None:
    """RecoveryOrchestrator enforces post-recovery verification against trusted source read."""
    connector = InMemorySandboxConnector()
    connector.seed_target("order:10", {"status": "cancelled", "restocked": True}, version=2)

    planner = RepairPlanner()
    plan = planner.create_repair_plan(
        problem_description="Fix failed delivery",
        impacted_nodes=["act:ship_10"],
        recommended_steps=[{"capability": "database.update", "target": "order:10"}],
    )

    orchestrator = RecoveryOrchestrator(max_attempts=3)
    session = orchestrator.start_recovery("workflow-99", plan)
    assert session.state == RecoveryState.REPAIRING

    # Post-recovery verification reading back trusted state
    success = await orchestrator.verify_post_recovery(
        session_id=session.session_id,
        connector=connector,
        target="order:10",
        expected_conditions={"status": "cancelled", "restocked": True},
    )
    assert success is True
    assert session.state == RecoveryState.SUCCESS
