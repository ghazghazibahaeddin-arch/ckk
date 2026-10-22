"""Unit tests for Dependency Graph."""

import pytest

from cck.core.exceptions import CircularDependencyError
from cck.core.types import DependencyType
from cck.reliability.dependency_graph import DependencyGraph


def test_dependency_linking_and_blast_radius() -> None:
    """Test linking nodes and computing transitive downstream invalidation blast radius."""
    graph = DependencyGraph()

    # Model: Evidence -> Fact -> Decision -> Action
    evi_id = "evi:tx_1"
    fact_id = "fact:order:1:status"
    decision_id = "dec:authorize_refund"
    action_id = "act:dispatch_refund"

    graph.add_node(evi_id, DependencyType.EVIDENCE)
    graph.add_node(fact_id, DependencyType.FACT)
    graph.add_node(decision_id, DependencyType.DECISION)
    graph.add_node(action_id, DependencyType.ACTION)

    # Action depends on Decision
    graph.add_dependency(dependent_node_id=action_id, prerequisite_node_id=decision_id)
    # Decision depends on Fact
    graph.add_dependency(dependent_node_id=decision_id, prerequisite_node_id=fact_id)
    # Fact depends on Evidence
    graph.add_dependency(dependent_node_id=fact_id, prerequisite_node_id=evi_id)

    # Verify upstream prerequisites
    assert graph.get_prerequisites(action_id) == {decision_id}
    assert graph.get_prerequisites(decision_id) == {fact_id}

    # Verify downstream blast radius when Fact changes
    affected = graph.get_affected_downstream(fact_id)
    assert decision_id in affected
    assert action_id in affected
    assert len(affected) == 2


def test_circular_dependency_detection() -> None:
    """Circular dependencies must be detected and rejected."""
    graph = DependencyGraph()

    node_a = "node:A"
    node_b = "node:B"
    node_c = "node:C"

    # A depends on B
    graph.add_dependency(dependent_node_id=node_a, prerequisite_node_id=node_b)
    # B depends on C
    graph.add_dependency(dependent_node_id=node_b, prerequisite_node_id=node_c)

    # C depends on A -> would create cycle A -> B -> C -> A
    with pytest.raises(CircularDependencyError):
        graph.add_dependency(dependent_node_id=node_c, prerequisite_node_id=node_a)

    # Self-dependency must also be rejected
    with pytest.raises(CircularDependencyError):
        graph.add_dependency(dependent_node_id="node:X", prerequisite_node_id="node:X")
