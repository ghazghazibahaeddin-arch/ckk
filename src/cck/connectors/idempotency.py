"""Idempotency Adapter for CCK Connectors.

Persists action attempt states and cached results to prevent accidental double-execution.
Handles connection drops where execution status is unknown.

Disclaimer:
Does NOT claim general 'exactly-once' delivery across distributed network boundaries.
Under network partitions, a remote system might execute an action without the caller
receiving acknowledgment.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.core.exceptions import IdempotencyConflictError
from cck.core.types import IdempotencyStatus
from cck.storage.base import StorageBackend


class IdempotencyRecord(BaseModel):
    """Authoritative record of an idempotent execution attempt."""

    idempotency_key: str = Field(..., description="Unique client or system idempotency key")
    action_id: str = Field(..., description="Action identifier associated with this key")
    status: IdempotencyStatus = Field(
        default=IdempotencyStatus.PENDING,
        description="Attempt lifecycle state (PENDING, COMPLETED, FAILED, UNKNOWN_OUTCOME)",
    )
    result: dict[str, Any] | None = Field(
        default=None,
        description="Cached response payload if execution completed successfully",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC initiation timestamp",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC completion timestamp",
    )
    error_message: str | None = Field(
        default=None,
        description="Recorded error message if failed or outcome was unknown",
    )

    model_config = ConfigDict(extra="forbid")


class IdempotencyAdapter:
    """Manages idempotency lifecycle, persistence, and conflict detection."""

    def __init__(self, storage: StorageBackend | None = None) -> None:
        self.storage = storage
        # In-memory fast cache and fallback
        self._records: dict[str, IdempotencyRecord] = {}

    async def get_record(self, key: str) -> IdempotencyRecord | None:
        """Fetch existing idempotency record by key."""
        return self._records.get(key)

    async def start_attempt(self, key: str, action_id: str) -> IdempotencyRecord:
        """Register the start of an execution attempt.

        Raises:
            IdempotencyConflictError: If the key is already in-flight (PENDING) or completed.
        """
        existing = await self.get_record(key)
        if existing is not None:
            if existing.status == IdempotencyStatus.COMPLETED:
                return existing
            if existing.status == IdempotencyStatus.PENDING:
                raise IdempotencyConflictError(
                    f"Idempotency key '{key}' is already in-flight for action '{existing.action_id}'."
                )
            if existing.status == IdempotencyStatus.UNKNOWN_OUTCOME:
                raise IdempotencyConflictError(
                    f"Idempotency key '{key}' has UNKNOWN_OUTCOME from a previous disconnected attempt. "
                    f"Manual inspection required before retrying unsafe actions."
                )

        record = IdempotencyRecord(
            idempotency_key=key,
            action_id=action_id,
            status=IdempotencyStatus.PENDING,
        )
        self._records[key] = record
        return record

    async def complete_attempt(self, key: str, result_data: dict[str, Any]) -> IdempotencyRecord:
        """Record successful execution and cache result for future duplicate calls."""
        record = self._records.get(key)
        if record is None:
            record = IdempotencyRecord(
                idempotency_key=key,
                action_id="unknown",
            )
        record = record.model_copy(
            update={
                "status": IdempotencyStatus.COMPLETED,
                "result": result_data,
                "completed_at": datetime.now(timezone.utc),
            }
        )
        self._records[key] = record
        return record

    async def mark_unknown_outcome(self, key: str, error_msg: str) -> IdempotencyRecord:
        """Mark attempt as UNKNOWN_OUTCOME when communication drops after dispatch.

        Security Policy:
        Do NOT automatically retry an unsafe action after an unknown execution outcome!
        """
        record = self._records.get(key)
        if record is None:
            record = IdempotencyRecord(idempotency_key=key, action_id="unknown")

        record = record.model_copy(
            update={
                "status": IdempotencyStatus.UNKNOWN_OUTCOME,
                "error_message": error_msg,
                "completed_at": datetime.now(timezone.utc),
            }
        )
        self._records[key] = record
        return record

    async def mark_failed(self, key: str, error_msg: str) -> IdempotencyRecord:
        """Mark attempt as FAILED before dispatch or upon clean external rejection."""
        record = self._records.get(key)
        if record is None:
            record = IdempotencyRecord(idempotency_key=key, action_id="unknown")

        record = record.model_copy(
            update={
                "status": IdempotencyStatus.FAILED,
                "error_message": error_msg,
                "completed_at": datetime.now(timezone.utc),
            }
        )
        self._records[key] = record
        return record
