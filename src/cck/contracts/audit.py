"""Contracts for tamper-evident audit records and execution receipts."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import ActionStatus


class AuditRecord(BaseModel):
    """Immutable audit trail entry recording action evaluation and execution."""

    audit_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this audit ledger entry",
    )
    action_id: str = Field(..., description="Foreign key referencing AgentAction.action_id")
    agent_id: str = Field(..., description="Identifier of the executing agent")
    action_hash: str = Field(
        ...,
        description="SHA-256 digest of canonicalized AgentAction data",
    )
    previous_hash: str | None = Field(
        default=None,
        description="SHA-256 digest of preceding audit entry, forming an immutable hash chain",
    )
    verdict: ExecutionVerdict = Field(
        ...,
        description="Complete execution verdict produced by the policy gate",
    )
    execution_status: ActionStatus = Field(
        ...,
        description="Current state of the action lifecycle",
    )
    execution_result: dict[str, Any] | None = Field(
        default=None,
        description="Execution output or error payload if action was executed",
    )
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of audit registration",
    )

    model_config = ConfigDict(extra="forbid")
