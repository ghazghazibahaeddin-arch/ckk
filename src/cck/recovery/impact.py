"""Impact Analyzer for CCK Recovery & Repair (Layer 4).

Traverses the Dependency Graph to determine all downstream decisions, actions,
and dependent workflows affected by a fact change or evidence invalidation.
"""

from cck.reliability.dependency_graph import DependencyGraph


class ImpactAnalyzer:
    """Analyzes blast radius and downstream dependencies when facts or evidence change."""

    def __init__(self, dependency_graph: DependencyGraph) -> None:
        self.dependency_graph = dependency_graph

    def analyze_fact_impact(self, entity_id: str, field_name: str) -> set[str]:
        """Identify all downstream action/decision node IDs affected by a fact change.

        Returns:
            set[str]: Set of impacted node IDs (actions, derived facts, downstream workflows).
        """
        fact_node_id = DependencyGraph.format_fact_node_id(entity_id, field_name)
        return self.dependency_graph.get_affected_downstream(fact_node_id)

    def analyze_evidence_impact(self, evidence_id: str) -> set[str]:
        """Identify impacted nodes associated with an invalidated evidence ID."""
        # Find all nodes linked or dependent on evidence
        impacted: set[str] = set()
        for node_id in self.dependency_graph.get_all_nodes():
            node = self.dependency_graph.get_node(node_id)
            if node and node.metadata.get("evidence_id") == evidence_id:
                impacted.add(node_id)
                impacted.update(self.dependency_graph.get_affected_downstream(node_id))
        return impacted
