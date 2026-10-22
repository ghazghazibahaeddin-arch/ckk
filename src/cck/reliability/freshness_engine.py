"""Freshness and Invalidation Engine for CCK.

Enforces field-level freshness policies, applies fine-grained fingerprint checks
to prevent over-invalidation when unrelated fields change, and handles delayed
or duplicate events deterministically.
"""

from datetime import datetime, timezone
from typing import Any

from cck.contracts.fact import Fact, compute_value_fingerprint
from cck.core.exceptions import VersionConflictError
from cck.core.types import FactState
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.fact_registry import FactRegistry


class FreshnessEngine:
    """Engine enforcing freshness policies and performing precise downstream invalidations."""

    def __init__(
        self,
        fact_registry: FactRegistry,
        dependency_graph: DependencyGraph,
        default_ttls: dict[str, float] | None = None,
    ) -> None:
        self.fact_registry = fact_registry
        self.dependency_graph = dependency_graph
        # Map of "entity_type.field_name" or "field_name" -> TTL in seconds
        self._policy_ttls: dict[str, float] = default_ttls or {
            "order.status": 300.0,       # 5 minutes
            "customer.balance": 60.0,    # 1 minute
            "inventory.stock": 120.0,    # 2 minutes
            "default": 3600.0,           # 1 hour
        }

    def get_configured_ttl(self, entity_type: str, field_name: str) -> float:
        """Resolve policy TTL for a given field."""
        key = f"{entity_type}.{field_name}"
        if key in self._policy_ttls:
            return self._policy_ttls[key]
        if field_name in self._policy_ttls:
            return self._policy_ttls[field_name]
        return self._policy_ttls.get("default", 3600.0)

    def set_ttl_policy(self, field_or_type_key: str, ttl_seconds: float) -> None:
        """Configure freshness TTL policy."""
        self._policy_ttls[field_or_type_key] = max(0.0, ttl_seconds)

    async def process_incoming_observation(
        self,
        entity_id: str,
        entity_type: str,
        field_name: str,
        new_value: Any,
        source: str,
        version: int,
        evidence_id: str | None = None,
        observed_at: datetime | None = None,
    ) -> tuple[Fact, set[str]]:
        """Process an incoming observation from a trusted source.

        Returns:
            tuple[Fact, set[str]]: The updated Fact, and the set of downstream
            node IDs that were invalidated (empty if value was unchanged or duplicate).

        Rules:
        1. Out-of-order events (version < existing.version) are rejected via VersionConflictError.
        2. Duplicate events (version == existing.version and fingerprint matches) cause no invalidation.
        3. Unrelated fields: changing `notes` does NOT invalidate dependencies on `status`.
        4. Invalidation occurs ONLY if the field's fingerprint actually changed.
        """
        obs_time = observed_at or datetime.now(timezone.utc)
        new_fingerprint = compute_value_fingerprint(new_value)
        ttl = self.get_configured_ttl(entity_type, field_name)

        existing = await self.fact_registry.get_fact(entity_id, field_name)
        invalidated_nodes: set[str] = set()

        if existing is not None:
            # 1. Version ordering check
            if version < existing.version:
                raise VersionConflictError(
                    f"Delayed out-of-order observation for {entity_id}.{field_name}: "
                    f"Received version {version} is older than current version {existing.version}."
                )

            # 2. Duplicate event check (idempotent no-op)
            if version == existing.version and existing.field_fingerprint == new_fingerprint:
                return existing, set()

            # 3. Fine-grained fingerprint change check
            if existing.field_fingerprint != new_fingerprint:
                # Value genuinely changed! Invalidate downstream dependents
                fact_node_id = DependencyGraph.format_fact_node_id(entity_id, field_name)
                invalidated_nodes = self.dependency_graph.get_affected_downstream(fact_node_id)

        # Record new fact
        fact = await self.fact_registry.record_fact(
            entity_id=entity_id,
            field_name=field_name,
            value=new_value,
            source=source,
            version=version,
            evidence_id=evidence_id,
            ttl_seconds=ttl,
            observed_at=obs_time,
        )

        return fact, invalidated_nodes

    async def check_freshness(self, fact: Fact, current_time: datetime | None = None) -> FactState:
        """Evaluate whether a fact remains fresh.

        Rule: Absence of an update does NOT mean the fact is still valid.
        """
        if fact.state != FactState.VALID:
            return fact.state

        if fact.ttl_seconds is None:
            return FactState.VALID

        now = current_time or datetime.now(timezone.utc)
        age = (now - fact.observed_at).total_seconds()
        if age > fact.ttl_seconds:
            return FactState.STALE

        return FactState.VALID
