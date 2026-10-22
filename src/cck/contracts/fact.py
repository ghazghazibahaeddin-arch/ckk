"""Fact Registry contracts for CCK."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import FactState


def compute_value_fingerprint(value: Any) -> str:
    """Compute a deterministic SHA-256 fingerprint for a fact's value."""
    try:
        serialized = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    except Exception:
        serialized = str(value).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class Fact(BaseModel):
    """Represents a validated fact attached to an entity and a specific field."""

    entity_id: str = Field(..., description="Target entity ID this fact pertains to")
    field_name: str = Field(..., description="Specific field/attribute name (e.g. 'status', 'balance')")
    value: Any = Field(..., description="Observed value of the field")
    source: str = Field(..., description="Trusted source or system that observed this fact")
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the observation",
    )
    version: int = Field(default=1, ge=1, description="Monotonically increasing version counter")
    state: FactState = Field(
        default=FactState.VALID,
        description="Current validity state (VALID, STALE, INVALIDATED, UNKNOWN)",
    )
    evidence_id: str | None = Field(
        default=None,
        description="ID of the supporting evidence record in Evidence Registry",
    )
    ttl_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Maximum freshness time in seconds before the fact degrades to STALE",
    )
    field_fingerprint: str = Field(
        default="",
        description="Deterministic hash of the value to support fine-grained change detection",
    )

    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if not self.field_fingerprint:
            object.__setattr__(self, "field_fingerprint", compute_value_fingerprint(self.value))

    def is_fresh(self, current_time: datetime | None = None) -> bool:
        """Evaluate if the fact is within its allowed freshness TTL.

        Rule: Absence of an update does NOT imply the fact remains valid.
        """
        if self.state != FactState.VALID:
            return False

        if self.ttl_seconds is None:
            return True

        now = current_time or datetime.now(timezone.utc)
        age = (now - self.observed_at).total_seconds()
        return age <= self.ttl_seconds
