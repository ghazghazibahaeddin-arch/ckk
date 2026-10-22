"""Dependency Graph contracts for CCK."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import DependencyType


class DependencyNode(BaseModel):
    """A discrete vertex in the reliability dependency graph."""

    node_id: str = Field(..., description="Unique graph node ID (e.g. 'fact:order:101:status', 'act:8821')")
    node_type: DependencyType = Field(..., description="Domain type of the vertex")
    entity_id: str | None = Field(default=None, description="Associated entity ID if applicable")
    field_name: str | None = Field(default=None, description="Associated field name if applicable")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Contextual node metadata")

    model_config = ConfigDict(extra="forbid")


class DependencyEdge(BaseModel):
    """A directed dependency relationship: `dependent_node_id` depends on `prerequisite_node_id`."""

    dependent_node_id: str = Field(..., description="The downstream node requiring the prerequisite")
    prerequisite_node_id: str = Field(..., description="The upstream dependency that must remain valid")
    relation_label: str = Field(default="depends_on", description="Semantic relationship description")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp of the edge",
    )

    model_config = ConfigDict(extra="forbid")


class ActionDependencySpec(BaseModel):
    """Specification of facts and evidence required for an action to be authorized."""

    action_id: str = Field(..., description="ID of the action being gated")
    decision_id: str = Field(..., description="Correlating decision ID")
    required_facts: list[tuple[str, str]] = Field(
        default_factory=list,
        description="List of (entity_id, field_name) tuples required to be VALID and fresh",
    )
    claimed_evidence_ids: list[str] = Field(
        default_factory=list,
        description="System evidence IDs that substantiate the action's preconditions",
    )
    policy_version: str = Field(
        default="1.0.0",
        description="Version of the safety policy governing this dependency check",
    )

    model_config = ConfigDict(extra="forbid")
