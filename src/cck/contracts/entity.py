"""Entity Identity contracts for CCK."""

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allow alphanumeric, underscores, hyphens, and colons in entity IDs
ENTITY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:]+$")


class Entity(BaseModel):
    """Represents a discrete domain entity with an immutable identifier and type.

    Guarantees that two entities with identical or similar names are never
    conflated if their entity_id or entity_type differ.
    """

    entity_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        description="Immutable, globally unique identifier (e.g. 'order:9021', 'cust_abc')",
    )
    entity_type: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Domain category of the entity (e.g. 'order', 'account', 'server')",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Human-readable label or display name",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Domain-specific properties and metadata",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC last updated timestamp",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean or not ENTITY_ID_PATTERN.match(clean):
            raise ValueError(
                f"Invalid entity_id '{v}'. Must match pattern [a-zA-Z0-9_-:] and not contain whitespace."
            )
        return clean

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean or not re.match(r"^[a-z0-9_\-]+$", clean):
            raise ValueError(
                f"Invalid entity_type '{v}'. Must be lowercase alphanumeric with hyphens or underscores."
            )
        return clean
