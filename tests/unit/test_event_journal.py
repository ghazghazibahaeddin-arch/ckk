"""Unit tests for Event Journal and cryptographic chain verification."""

from pathlib import Path

import pytest

from cck.core.types import JournalEventType
from cck.reliability.journal import EventJournal
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_journal_hash_chain_and_retrieval(temp_db_path: Path) -> None:
    """Journal entries form an unbroken SHA-256 chain that verifies successfully."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    journal = EventJournal(storage=storage)

    # 1. Entry 1
    e1 = await journal.record_event(
        correlation_id="corr-1",
        event_type=JournalEventType.FACT_OBSERVED,
        payload={"entity": "order:1", "status": "paid"},
    )
    assert e1.previous_hash is None
    assert len(e1.entry_hash) == 64

    # 2. Entry 2
    e2 = await journal.record_event(
        correlation_id="corr-1",
        event_type=JournalEventType.GATE_DECISION,
        payload={"decision": "ALLOW"},
    )
    assert e2.previous_hash == e1.entry_hash

    # 3. Entry 3
    e3 = await journal.record_event(
        correlation_id="corr-1",
        event_type=JournalEventType.ACTION_EXECUTED,
        payload={"action_id": "act-1", "result": "success"},
    )
    assert e3.previous_hash == e2.entry_hash

    # Verify integrity of complete chain
    entries = await journal.list_events(correlation_id="corr-1")
    assert len(entries) == 3
    is_valid, msg = EventJournal.verify_integrity(entries)
    assert is_valid is True
    assert "Cryptographic integrity verified" in msg

    await storage.close()


@pytest.mark.asyncio
async def test_journal_tamper_detection(temp_db_path: Path) -> None:
    """Tampering with a historical payload is detected by verify_integrity."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    journal = EventJournal(storage=storage)

    await journal.record_event("c1", JournalEventType.FACT_OBSERVED, {"val": 10})
    await journal.record_event("c1", JournalEventType.GATE_DECISION, {"val": 20})

    entries = await journal.list_events("c1")

    # Maliciously mutate payload of entry 0
    tampered_entry0 = entries[0].model_copy(update={"payload": {"val": 99999}})
    tampered_chain = [tampered_entry0, entries[1]]

    is_valid, msg = EventJournal.verify_integrity(tampered_chain)
    assert is_valid is False
    assert "Tamper detected" in msg

    await storage.close()
