"""Read Adapter for CCK Connectors.

Transforms external system readings into normalized CCK Entities, Facts, and system-minted Evidence.
Explicitly distinguishes between trusted, missing, and unverifiable data.
"""

from typing import Any

from cck.connectors.interface import Connector, ReadResult
from cck.contracts.entity import Entity
from cck.contracts.evidence import Evidence
from cck.contracts.fact import Fact
from cck.core.types import FactState
from cck.reliability.entity_registry import EntityRegistry
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry


class ReadAdapter:
    """Ingests reads from external connectors into the CCK Core Reliability Engine."""

    def __init__(
        self,
        entity_registry: EntityRegistry,
        fact_registry: FactRegistry,
        evidence_registry: EvidenceRegistry,
    ) -> None:
        self.entity_registry = entity_registry
        self.fact_registry = fact_registry
        self.evidence_registry = evidence_registry

    async def ingest_read(
        self,
        connector: Connector,
        target: str,
        entity_id: str,
        entity_type: str,
        params: dict[str, Any] | None = None,
        entity_name: str | None = None,
    ) -> tuple[Entity, list[Fact], Evidence | None]:
        """Execute a connector read and normalize into Entity, Facts, and Evidence.

        Rules:
        1. If entity does not exist in external system: records fact state as UNKNOWN.
        2. If entity exists: creates system-minted Evidence with SHA-256 payload hash.
        3. Persists entity in EntityRegistry and facts in FactRegistry.
        """
        read_res: ReadResult = await connector.read(target=target, params=params)

        # 1. Handle missing/non-existent entity
        if not read_res.exists:
            # Register placeholder entity if missing
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                name=entity_name or entity_id,
            )
            await self.entity_registry.register_entity(entity)

            # Record UNKNOWN facts
            unknown_fact = Fact(
                entity_id=entity_id,
                field_name="_exists",
                value=False,
                source=connector.connector_id,
                state=FactState.UNKNOWN,
            )
            return entity, [unknown_fact], None

        # 2. Authentic read: record system-minted Evidence
        evidence = await self.evidence_registry.record_evidence(
            entity_id=entity_id,
            field_name="_aggregate",
            raw_payload=read_res.raw_response or read_res.data,
            source=connector.connector_id,
            observed_at=read_res.observed_at,
            metadata={"target": target, "connector": connector.name},
        )

        # 3. Register or update entity
        entity = Entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=entity_name or entity_id,
            attributes=read_res.data,
        )
        await self.entity_registry.register_entity(entity)

        # 4. Ingest normalized facts
        facts: list[Fact] = []
        version = read_res.version or 1

        for field_name, value in read_res.data.items():
            fact = await self.fact_registry.record_fact(
                entity_id=entity_id,
                field_name=field_name,
                value=value,
                source=connector.connector_id,
                version=version,
                evidence_id=evidence.evidence_id,
                observed_at=read_res.observed_at,
            )
            facts.append(fact)

        return entity, facts, evidence
