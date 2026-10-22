"""Event Journal for CCK.

Appends tamper-evident audit and state transition events with cryptographic
SHA-256 hash chaining for forensic verification and replayability.

Security Boundary & Limitations Disclosure:
------------------------------------------
The hash chain mechanism mathematically guarantees detection of:
1. Retroactive modification of past entries (hash mismatch).
2. Deletion or omission of entries in the middle of a sequence (broken link).
3. Reordering of entries.

However, it CANNOT guarantee:
1. Prevention against total filesystem/database erasure by an OS-level administrator.
2. Protection against physical disk corruption without off-site replication.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cck.contracts.journal import JournalEntry, compute_journal_hash
from cck.core.types import JournalEventType
from cck.storage.base import StorageBackend


class EventJournal:
    """Service managing append-only, chained event journal logs."""

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    async def record_event(
        self,
        correlation_id: str,
        event_type: JournalEventType,
        payload: dict[str, Any],
        policy_version: str = "1.0.0",
        timestamp: datetime | None = None,
    ) -> JournalEntry:
        """Append a new event entry into the chained journal."""
        entry_id = f"jrn_{uuid4().hex}"
        event_time = timestamp or datetime.now(timezone.utc)
        time_iso = event_time.isoformat()

        # Fetch last entry hash for chaining
        previous_hash = await self.storage.get_last_journal_hash()

        # Compute tamper-detection entry hash
        entry_hash = compute_journal_hash(
            entry_id=entry_id,
            timestamp_iso=time_iso,
            correlation_id=correlation_id,
            event_type=event_type.value,
            policy_version=policy_version,
            payload=payload,
            previous_hash=previous_hash,
        )

        entry = JournalEntry(
            entry_id=entry_id,
            timestamp=event_time,
            correlation_id=correlation_id,
            event_type=event_type,
            policy_version=policy_version,
            payload=payload,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

        await self.storage.append_journal(entry)
        return entry

    async def list_events(
        self,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[JournalEntry]:
        """Retrieve chronological journal entries."""
        return await self.storage.list_journal_entries(
            correlation_id=correlation_id,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def verify_integrity(entries: list[JournalEntry]) -> tuple[bool, str]:
        """Verify unbroken cryptographic integrity across an ordered sequence of journal entries.

        Returns:
            tuple[bool, str]: (is_valid, explanation_message)
        """
        if not entries:
            return True, "Journal is empty."

        for i, entry in enumerate(entries):
            # 1. Verify entry's own hash matches its contents
            expected_hash = compute_journal_hash(
                entry_id=entry.entry_id,
                timestamp_iso=entry.timestamp.isoformat(),
                correlation_id=entry.correlation_id,
                event_type=entry.event_type.value,
                policy_version=entry.policy_version,
                payload=entry.payload,
                previous_hash=entry.previous_hash,
            )
            if entry.entry_hash != expected_hash:
                return (
                    False,
                    f"Tamper detected at index {i} (entry '{entry.entry_id}'): "
                    f"Stored hash {entry.entry_hash} != calculated hash {expected_hash}.",
                )

            # 2. Verify link with previous entry
            if i > 0:
                prev_entry = entries[i - 1]
                if entry.previous_hash != prev_entry.entry_hash:
                    return (
                        False,
                        f"Broken chain detected between entry {i-1} ('{prev_entry.entry_id}') "
                        f"and entry {i} ('{entry.entry_id}').",
                    )

        return True, f"Cryptographic integrity verified for {len(entries)} entries."
