"""Unit tests for Freshness & Invalidation Engine."""

from pathlib import Path

import pytest

from cck.core.exceptions import VersionConflictError
from cck.core.types import DependencyType
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.reliability.freshness_engine import FreshnessEngine
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_fine_grained_field_fingerprinting(temp_db_path: Path) -> None:
    """Changing an unrelated field (e.g. customer note) must NOT invalidate dependencies on order.status."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    evidence_reg = EvidenceRegistry(storage=storage)
    fact_reg = FactRegistry(storage=storage, evidence_registry=evidence_reg)
    dep_graph = DependencyGraph()
    freshness = FreshnessEngine(fact_registry=fact_reg, dependency_graph=dep_graph)

    # Setup graph: action depends on order.status
    fact_status_node = DependencyGraph.format_fact_node_id("order:10", "status")
    fact_notes_node = DependencyGraph.format_fact_node_id("order:10", "notes")
    action_node = "act:ship_goods"

    dep_graph.add_node(fact_status_node, DependencyType.FACT)
    dep_graph.add_node(fact_notes_node, DependencyType.FACT)
    dep_graph.add_node(action_node, DependencyType.ACTION)

    # act:ship_goods depends on status ONLY, NOT notes
    dep_graph.add_dependency(dependent_node_id=action_node, prerequisite_node_id=fact_status_node)

    # 1. Initial observation: status = 'paid', version 1
    await freshness.process_incoming_observation(
        entity_id="order:10",
        entity_type="order",
        field_name="status",
        new_value="paid",
        source="billing",
        version=1,
    )

    # 2. Update UNRELATED field 'notes'
    _, invalidated = await freshness.process_incoming_observation(
        entity_id="order:10",
        entity_type="order",
        field_name="notes",
        new_value="Please pack with extra bubble wrap",
        source="customer_support",
        version=1,
    )

    # Crucial check: act:ship_goods was NOT invalidated!
    assert action_node not in invalidated
    assert len(invalidated) == 0

    # 3. Now update RELATED field 'status' from 'paid' to 'cancelled'
    _, invalidated_status = await freshness.process_incoming_observation(
        entity_id="order:10",
        entity_type="order",
        field_name="status",
        new_value="cancelled",
        source="billing",
        version=2,
    )

    # Crucial check: act:ship_goods IS invalidated!
    assert action_node in invalidated_status

    await storage.close()


@pytest.mark.asyncio
async def test_duplicate_and_delayed_events_handling(temp_db_path: Path) -> None:
    """Duplicate events cause no invalidation; delayed events with older version are rejected."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    fact_reg = FactRegistry(storage=storage)
    dep_graph = DependencyGraph()
    freshness = FreshnessEngine(fact_registry=fact_reg, dependency_graph=dep_graph)

    # Version 2
    await freshness.process_incoming_observation(
        entity_id="inv:item1",
        entity_type="inventory",
        field_name="stock",
        new_value=50,
        source="erp",
        version=2,
    )

    # Duplicate version 2 with same value -> 0 invalidations, idempotent
    _, invalidated_dup = await freshness.process_incoming_observation(
        entity_id="inv:item1",
        entity_type="inventory",
        field_name="stock",
        new_value=50,
        source="erp",
        version=2,
    )
    assert len(invalidated_dup) == 0

    # Delayed version 1 -> raises VersionConflictError
    with pytest.raises(VersionConflictError):
        await freshness.process_incoming_observation(
            entity_id="inv:item1",
            entity_type="inventory",
            field_name="stock",
            new_value=100,
            source="erp",
            version=1,
        )

    await storage.close()
