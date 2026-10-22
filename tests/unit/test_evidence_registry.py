"""Unit tests for Evidence Registry."""

from pathlib import Path

import pytest

from cck.core.exceptions import EvidenceNotFoundError, EvidenceTamperedError
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_system_issued_evidence_ids(temp_db_path: Path) -> None:
    """Evidence IDs must be minted by the system, prefixed with 'evi_'."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EvidenceRegistry(storage=storage)

    raw_data = {"status": "paid", "transaction_id": "tx_99812", "amount": 250.0}
    evidence = await registry.record_evidence(
        entity_id="order:100",
        field_name="status",
        raw_payload=raw_data,
        source="stripe_webhook",
    )

    assert evidence.evidence_id.startswith("evi_")
    assert len(evidence.payload_hash) == 64
    assert evidence.source == "stripe_webhook"

    # Verify lookup and integrity
    loaded = await registry.get_evidence(evidence.evidence_id)
    assert loaded.raw_payload == raw_data
    assert await registry.verify_evidence(evidence.evidence_id, expected_payload=raw_data) is True

    await storage.close()


@pytest.mark.asyncio
async def test_reject_untracked_or_fabricated_evidence_id(temp_db_path: Path) -> None:
    """Fabricated or hallucinated evidence IDs must be rejected."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EvidenceRegistry(storage=storage)

    fake_id = "evi_fabricated_hallucination_999"
    with pytest.raises(EvidenceNotFoundError):
        await registry.get_evidence(fake_id)

    assert await registry.is_valid_evidence_id(fake_id) is False

    await storage.close()


@pytest.mark.asyncio
async def test_evidence_tamper_detection(temp_db_path: Path) -> None:
    """Tampering with evidence payload triggers EvidenceTamperedError."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = EvidenceRegistry(storage=storage)

    evidence = await registry.record_evidence(
        entity_id="order:200",
        field_name="amount",
        raw_payload={"amount": 100.0},
        source="bank_feed",
    )

    # Simulate malicious out-of-band edit to raw payload while keeping original hash
    tampered_evidence = evidence.model_copy(update={"raw_payload": {"amount": 999999.0}})
    await storage.save_evidence(tampered_evidence)

    # Verification must detect the tamper
    with pytest.raises(EvidenceTamperedError):
        await registry.verify_evidence(evidence.evidence_id)

    await storage.close()
