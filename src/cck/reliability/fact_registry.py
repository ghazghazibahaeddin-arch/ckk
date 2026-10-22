"""Fact Registry for CCK.

Maintains authoritative state facts tied to entities and fields, tracking
versions, sources, and freshness, and enforcing that absence of an update
is NOT assumed to be proof of continuing validity.
"""

from datetime import datetime, timezone
from typing import Any

from cck.contracts.entity import Entity
from cck.contracts.fact import Fact, compute_value_fingerprint
from cck.core.exceptions import EvidenceNotFoundError, VersionConflictError
from cck.core.types import FactState
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.storage.base import StorageBackend


class FactRegistry:
    """Registry maintaining active and historical facts for entities."""

    def __init__(
        self,
        storage: StorageBackend,
        evidence_registry: EvidenceRegistry | None = None,
    ) -> None:
        self.storage = storage
        self.evidence_registry = evidence_registry or EvidenceRegistry(storage=storage)

    async def record_fact(
        self,
        entity_id: str,
        field_name: str,
        value: Any,
        source: str,
        version: int = 1,
        evidence_id: str | None = None,
        ttl_seconds: float | None = None,
        observed_at: datetime | None = None,
    ) -> Fact:
        """Record or update a fact for an entity and field.

        Rules:
        1. If evidence_id is provided, it MUST exist in EvidenceRegistry.
        2. Version monotonicity: an event with version < existing.version is rejected (out-of-order / delayed).
        3. Idempotency: an event with identical version and identical value is accepted idempotently.
        """
        obs_time = observed_at or datetime.now(timezone.utc)
        fingerprint = compute_value_fingerprint(value)

        # 1. Evidence existence validation
        if evidence_id is not None:
            is_valid = await self.evidence_registry.is_valid_evidence_id(evidence_id)
            if not is_valid:
                raise EvidenceNotFoundError(
                    f"Cannot link fact {entity_id}.{field_name} to non-existent evidence '{evidence_id}'."
                )

        # 2. Check existing fact for version conflicts
        existing = await self.storage.get_fact(entity_id, field_name)
        if existing is not None and version < existing.version:
            raise VersionConflictError(
                f"Version regression for fact {entity_id}.{field_name}: "
                f"Incoming version {version} is older than current version {existing.version}."
            )

        # 3. Ensure entity exists in storage to maintain entity-fact linkage
        existing_ent = await self.storage.get_entity(entity_id)
        if existing_ent is None:
            clean_type = entity_id.split(":")[0].lower() if ":" in entity_id else "entity"
            await self.storage.save_entity(
                Entity(
                    entity_id=entity_id,
                    entity_type=clean_type,
                    name=entity_id,
                )
            )

        fact = Fact(
            entity_id=entity_id,
            field_name=field_name,
            value=value,
            source=source,
            observed_at=obs_time,
            version=version,
            state=FactState.VALID,
            evidence_id=evidence_id,
            ttl_seconds=ttl_seconds,
            field_fingerprint=fingerprint,
        )

        await self.storage.save_fact(fact)
        return fact

    async def get_fact(
        self,
        entity_id: str,
        field_name: str,
        current_time: datetime | None = None,
    ) -> Fact | None:
        """Retrieve a fact, automatically evaluating its freshness.

        Crucial Rule:
        Absence of an update does NOT mean the fact is still valid.
        If current_time - observed_at > ttl_seconds, the fact degrades to STALE.
        """
        fact = await self.storage.get_fact(entity_id, field_name)
        if fact is None:
            return None

        # Freshness evaluation
        if fact.state == FactState.VALID and fact.ttl_seconds is not None:
            now = current_time or datetime.now(timezone.utc)
            age = (now - fact.observed_at).total_seconds()
            if age > fact.ttl_seconds:
                # Degrade state to STALE
                fact = fact.model_copy(update={"state": FactState.STALE})
                await self.storage.save_fact(fact)

        return fact

    async def invalidate_fact(
        self,
        entity_id: str,
        field_name: str,
        reason: str = "",
    ) -> Fact:
        """Explicitly invalidate a fact when reliable evidence or events refute it."""
        fact = await self.get_fact(entity_id, field_name)
        if fact is None:
            # Create an invalidated placeholder
            fact = Fact(
                entity_id=entity_id,
                field_name=field_name,
                value=None,
                source="invalidation_engine",
                version=1,
                state=FactState.INVALIDATED,
            )
        else:
            fact = fact.model_copy(update={"state": FactState.INVALIDATED})

        await self.storage.save_fact(fact)
        return fact

    async def list_facts(self, entity_id: str) -> list[Fact]:
        """List all facts known for an entity with evaluated freshness."""
        facts = await self.storage.list_facts_for_entity(entity_id)
        now = datetime.now(timezone.utc)
        results: list[Fact] = []
        for f in facts:
            if (
                f.state == FactState.VALID
                and f.ttl_seconds is not None
                and (now - f.observed_at).total_seconds() > f.ttl_seconds
            ):
                f = f.model_copy(update={"state": FactState.STALE})
            results.append(f)
        return results
