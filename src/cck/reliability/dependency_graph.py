"""Dependency Graph for CCK.

Tracks directed dependency chains connecting Actions -> Decisions -> Facts -> Evidence.
Detects illegal circular dependencies and computes blast-radius invalidation trees.
"""

from collections import defaultdict, deque
from typing import Any

from cck.contracts.dependency import DependencyEdge, DependencyNode
from cck.core.exceptions import CircularDependencyError
from cck.core.types import DependencyType


class DependencyGraph:
    """In-memory and persistent dependency graph for decision traceability."""

    def __init__(self) -> None:
        self._nodes: dict[str, DependencyNode] = {}
        # Forward edges: prerequisite -> set of dependents (who depends on this node?)
        self._dependents: dict[str, set[str]] = defaultdict(set)
        # Reverse edges: dependent -> set of prerequisites (what does this node depend on?)
        self._prerequisites: dict[str, set[str]] = defaultdict(set)

    def add_node(
        self,
        node_id: str,
        node_type: DependencyType,
        entity_id: str | None = None,
        field_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DependencyNode:
        """Register a vertex in the dependency graph."""
        node = DependencyNode(
            node_id=node_id,
            node_type=node_type,
            entity_id=entity_id,
            field_name=field_name,
            metadata=metadata or {},
        )
        self._nodes[node_id] = node
        return node

    def get_node(self, node_id: str) -> DependencyNode | None:
        """Retrieve node by ID."""
        return self._nodes.get(node_id)

    def add_dependency(
        self,
        dependent_node_id: str,
        prerequisite_node_id: str,
        relation_label: str = "depends_on",
    ) -> DependencyEdge:
        """Link `dependent_node_id` to depend on `prerequisite_node_id`.

        Enforces cycle detection: if linking creates a circular dependency,
        reverts changes and raises CircularDependencyError.
        """
        if dependent_node_id == prerequisite_node_id:
            raise CircularDependencyError(
                f"Self-referential circular dependency detected: '{dependent_node_id}' cannot depend on itself."
            )

        # Tentatively add edge
        self._prerequisites[dependent_node_id].add(prerequisite_node_id)
        self._dependents[prerequisite_node_id].add(dependent_node_id)

        # Ensure both nodes exist in nodes registry
        if dependent_node_id not in self._nodes:
            self.add_node(dependent_node_id, DependencyType.ACTION)
        if prerequisite_node_id not in self._nodes:
            self.add_node(prerequisite_node_id, DependencyType.FACT)

        # Check for cycles using DFS from dependent_node_id
        if self._has_cycle_from(prerequisite_node_id, dependent_node_id):
            # Roll back edge
            self._prerequisites[dependent_node_id].remove(prerequisite_node_id)
            self._dependents[prerequisite_node_id].remove(dependent_node_id)
            raise CircularDependencyError(
                f"Circular dependency detected between '{dependent_node_id}' and '{prerequisite_node_id}'."
            )

        return DependencyEdge(
            dependent_node_id=dependent_node_id,
            prerequisite_node_id=prerequisite_node_id,
            relation_label=relation_label,
        )

    def _has_cycle_from(self, start: str, target: str) -> bool:
        """Check if target is reachable from start following prerequisites."""
        visited: set[str] = set()
        queue: deque[str] = deque([start])

        while queue:
            current = queue.popleft()
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            for prereq in self._prerequisites.get(current, set()):
                if prereq not in visited:
                    queue.append(prereq)

        return False

    def get_prerequisites(self, node_id: str) -> set[str]:
        """Return direct prerequisites required by a node."""
        return set(self._prerequisites.get(node_id, set()))

    def get_direct_dependents(self, node_id: str) -> set[str]:
        """Return direct downstream nodes that depend on this node."""
        return set(self._dependents.get(node_id, set()))

    def get_affected_downstream(self, changed_node_id: str) -> set[str]:
        """Compute transitive blast-radius of all nodes invalidated when `changed_node_id` changes.

        Traverses downstream dependents via BFS.
        """
        affected: set[str] = set()
        queue: deque[str] = deque([changed_node_id])

        while queue:
            current = queue.popleft()
            for dep in self._dependents.get(current, set()):
                if dep not in affected:
                    affected.add(dep)
                    queue.append(dep)

        return affected

    @staticmethod
    def format_fact_node_id(entity_id: str, field_name: str) -> str:
        """Standardized graph node ID for a fact."""
        return f"fact:{entity_id}:{field_name}"

    @staticmethod
    def format_action_node_id(action_id: str) -> str:
        """Standardized graph node ID for an action."""
        return f"act:{action_id}"

    @staticmethod
    def format_evidence_node_id(evidence_id: str) -> str:
        """Standardized graph node ID for evidence."""
        return f"evi:{evidence_id}"
