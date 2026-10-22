"""Unit tests for Entity Identity Registry."""

from pathlib import Path

import pytest

from cck.contracts.entity import Entity
from cck.core.exceptions import EntityConflictError, EntityNotFoundError
from cck.reliability.entity_registry import EntityRegistry
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_entity_creation_and_lookup(temp_db_path: Path) -> None:
    """Test standard entity registration and retrieval by ID."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EntityRegistry(storage=storage)

    entity = Entity(
        entity_id="order:8821",
        entity_type="order",
        name="Customer Checkout Order",
        attributes={"amount": 150.0, "currency": "USD"},
    )
    await registry.register_entity(entity)

    loaded = await registry.get_entity("order:8821")
    assert loaded.entity_id == "order:8821"
    assert loaded.entity_type == "order"
    assert loaded.attributes["amount"] == 150.0

    await storage.close()


@pytest.mark.asyncio
async def test_prevent_name_collision_conflation(temp_db_path: Path) -> None:
    """Prevent confounding two distinct entities that share the same human name."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EntityRegistry(storage=storage)

    # Two distinct servers sharing the identical name "web-gateway"
    server_east = Entity(
        entity_id="srv:us-east-01",
        entity_type="server",
        name="web-gateway",
        attributes={"region": "us-east-1", "ip": "10.0.1.5"},
    )
    server_west = Entity(
        entity_id="srv:us-west-02",
        entity_type="server",
        name="web-gateway",
        attributes={"region": "us-west-2", "ip": "10.0.2.8"},
    )

    await registry.register_entity(server_east)
    await registry.register_entity(server_west)

    # Verification: Lookup by ID must return distinct objects
    east_loaded = await registry.get_entity("srv:us-east-01")
    west_loaded = await registry.get_entity("srv:us-west-02")

    assert east_loaded.entity_id != west_loaded.entity_id
    assert east_loaded.attributes["region"] == "us-east-1"
    assert west_loaded.attributes["region"] == "us-west-2"

    # Search by name returns both as distinct entities
    matches = await registry.find_entities(name="web-gateway")
    assert len(matches) == 2
    assert {m.entity_id for m in matches} == {"srv:us-east-01", "srv:us-west-02"}

    assert await registry.are_distinct_entities("srv:us-east-01", "srv:us-west-02") is True

    await storage.close()


@pytest.mark.asyncio
async def test_entity_id_type_conflict_prevention(temp_db_path: Path) -> None:
    """Reject registering an entity if the same ID is re-used with a conflicting type."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EntityRegistry(storage=storage)

    order_entity = Entity(
        entity_id="ent:9999",
        entity_type="order",
        name="Order 9999",
    )
    await registry.register_entity(order_entity)

    # Attempt to overwrite same ID as a 'customer'
    conflicting_entity = Entity(
        entity_id="ent:9999",
        entity_type="customer",
        name="Conflicting Customer",
    )
    with pytest.raises(EntityConflictError):
        await registry.register_entity(conflicting_entity)

    await storage.close()


@pytest.mark.asyncio
async def test_entity_not_found_raises(temp_db_path: Path) -> None:
    """Requesting non-existent entity raises EntityNotFoundError."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EntityRegistry(storage=storage)

    with pytest.raises(EntityNotFoundError):
        await registry.get_entity("non:existent")

    await storage.close()


def test_invalid_entity_id_format() -> None:
    """Invalid entity ID formats (e.g. whitespace, illegal characters) are rejected."""
    with pytest.raises(ValueError):
        Entity(
            entity_id="order with spaces",
            entity_type="order",
            name="Bad Entity",
        )
