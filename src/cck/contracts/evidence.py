"""Evidence Registry contracts for CCK."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def compute_payload_hash(payload: Any) -> str:
    """Compute SHA-256 digest of canonical raw evidence payload."""
    try:
        serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    except Exception:
        serialized = str(payload).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class Evidence(BaseModel):
    """Immutable evidence record generated strictly by the CCK system."""

    evidence_id: str = Field(
        default_factory=lambda: f"evi_{uuid4().hex}",
        description="System-issued unique evidence identifier (starts with 'evi_')",
    )
    entity_id: str = Field(..., description="Target entity identifier")
    field_name: str = Field(..., description="Target field identifier")
    raw_payload: Any = Field(..., description="Exact raw reading or response payload received from source")
    source: str = Field(..., description="Trusted origin (e.g. 'stripe_api', 'postgres_replica', 'sysfs')")
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC observation timestamp",
    )
    payload_hash: str = Field(
        default="",
        description="SHA-256 digest of the canonicalized raw payload",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Provenance metadata (e.g. request ID, sensor calibration, signature)",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id_format(cls, v: str) -> str:
        if not v.startswith("evi_") or len(v) < 10:
            raise ValueError(
                f"Invalid evidence_id '{v}'. Evidence IDs must be system-issued and prefixed with 'evi_'."
            )
        return v

    def model_post_init(self, __context: Any) -> None:
        if not self.payload_hash:
            object.__setattr__(self, "payload_hash", compute_payload_hash(self.raw_payload))

    def verify_integrity(self) -> bool:
        """Verify that the raw payload matches the stored cryptographic hash."""
        return self.payload_hash == compute_payload_hash(self.raw_payload)
