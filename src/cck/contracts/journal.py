"""Event Journal contracts for CCK."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import JournalEventType


def compute_journal_hash(
    entry_id: str,
    timestamp_iso: str,
    correlation_id: str,
    event_type: str,
    policy_version: str,
    payload: dict[str, Any],
    previous_hash: str | None,
) -> str:
    """Compute SHA-256 digest of journal entry fields.

    Security Boundary Note:
    This tamper-detection digest guarantees detection of sequential alterations,
    insertions, and reordering within an audit chain. It does NOT guarantee
    protection against total out-of-band database wiping by privileged operating
    system accounts.
    """
    canonical_dict = {
        "entry_id": entry_id,
        "timestamp": timestamp_iso,
        "correlation_id": correlation_id,
        "event_type": event_type,
        "policy_version": policy_version,
        "payload": payload,
        "previous_hash": previous_hash or "",
    }
    encoded = json.dumps(canonical_dict, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class JournalEntry(BaseModel):
    """An immutable, cryptographically-chained event journal entry."""

    entry_id: str = Field(
        default_factory=lambda: f"jrn_{uuid4().hex}",
        description="Unique sequential journal entry identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC registration timestamp",
    )
    correlation_id: str = Field(..., description="Distributed trace or session correlation ID")
    event_type: JournalEventType = Field(..., description="Classification of the recorded event")
    policy_version: str = Field(default="1.0.0", description="Active policy version at time of recording")
    payload: dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    previous_hash: str | None = Field(
        default=None,
        description="SHA-256 digest of preceding journal entry (None for genesis entry)",
    )
    entry_hash: str = Field(
        default="",
        description="Cryptographic SHA-256 hash linking this entry to the preceding chain",
    )

    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if not self.entry_hash:
            h = compute_journal_hash(
                entry_id=self.entry_id,
                timestamp_iso=self.timestamp.isoformat(),
                correlation_id=self.correlation_id,
                event_type=self.event_type.value,
                policy_version=self.policy_version,
                payload=self.payload,
                previous_hash=self.previous_hash,
            )
            object.__setattr__(self, "entry_hash", h)
