"""Contracts representing agent identity and external actions."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import ActionSeverity


class AgentIdentity(BaseModel):
    """Information identifying the external AI agent initiating the action."""

    agent_id: str = Field(..., description="Unique immutable identifier for the agent")
    name: str = Field(..., description="Human-readable name of the agent")
    version: str = Field(default="1.0.0", description="Agent release or model version")
    tenant_id: str = Field(default="default", description="Multi-tenant namespace")
    trust_tier: str = Field(
        default="standard",
        description="Trust level assigned to this agent (sandboxed, standard, privileged)",
    )

    model_config = ConfigDict(frozen=True)


class AgentAction(BaseModel):
    """Canonical representation of an external action proposed by an agent."""

    action_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Globally unique identifier for this action execution attempt",
    )
    agent: AgentIdentity = Field(
        ...,
        description="Identity of the agent attempting to execute the action",
    )
    session_id: str = Field(
        ...,
        description="Trace or session identifier linking related agent operations",
    )
    capability: str = Field(
        ...,
        description="Target capability category, e.g. 'bash.execute', 'filesystem.write', 'http.post'",
    )
    target: str = Field(
        ...,
        description="Specific resource target, e.g. '/var/log/app.log', 'https://api.external.com', 'users_table'",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value parameters or arguments intended for the execution",
    )
    severity: ActionSeverity = Field(
        default=ActionSeverity.STANDARD,
        description="Inherent severity rating of the requested action",
    )
    idempotency_key: str | None = Field(
        default=None,
        description="Optional idempotency key to prevent accidental duplicate executions",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible context metadata (reasoning trace, user prompt, parent plan ID)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the action was formulated by the agent",
    )

    model_config = ConfigDict(extra="forbid")
