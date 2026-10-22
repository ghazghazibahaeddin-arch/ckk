"""Entity Identity Registry for CCK.

Manages discrete entity identities, preventing collision or conflation between
different entities sharing similar names, and enforcing strict identifier rules.
"""

from cck.contracts.entity import Entity
from cck.core.exceptions import EntityConflictError, EntityNotFoundError
from cck.storage.base import StorageBackend


class EntityRegistry:
    """Registry maintaining authoritative entity identities and preventing name-collision bugs."""

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    async def register_entity(self, entity: Entity) -> Entity:
        """Register a new entity or update an existing one if the identity matches.

        Guarantees that an entity cannot be registered if it introduces a conflicting
        identity structure with an existing record.
        """
        existing = await self.storage.get_entity(entity.entity_id)
        if existing is not None and existing.entity_type != entity.entity_type:
            raise EntityConflictError(
                f"Entity '{entity.entity_id}' already exists with different type "
                f"'{existing.entity_type}', cannot change to '{entity.entity_type}'."
            )

        await self.storage.save_entity(entity)
        return entity

    async def get_entity(self, entity_id: str) -> Entity:
        """Retrieve an entity by unique ID or raise EntityNotFoundError."""
        entity = await self.storage.get_entity(entity_id)
        if entity is None:
            raise EntityNotFoundError(f"Entity with ID '{entity_id}' was not found in registry.")
        return entity

    async def find_entities(
        self,
        entity_type: str | None = None,
        name: str | None = None,
    ) -> list[Entity]:
        """Search entities by type and/or exact name.

        Demonstrates anti-conflation: multiple entities may share the same human name,
        but are returned as distinct objects with distinct entity_id values.
        """
        entities = await self.storage.list_entities(entity_type=entity_type)
        if name is not None:
            return [e for e in entities if e.name == name]
        return entities

    async def are_distinct_entities(self, entity_id_a: str, entity_id_b: str) -> bool:
        """Verify that two IDs represent strictly distinct entities, even if names match."""
        if entity_id_a == entity_id_b:
            return False
        ent_a = await self.get_entity(entity_id_a)
        ent_b = await self.get_entity(entity_id_b)
        return ent_a.entity_id != ent_b.entity_id
