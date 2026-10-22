"""Unit tests for Fact Registry."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cck.core.exceptions import EvidenceNotFoundError, VersionConflictError
from cck.core.types import FactState
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_fact_record_and_fingerprint(temp_db_path: Path) -> None:
    """Test standard fact recording and field fingerprint calculation."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    evidence_reg = EvidenceRegistry(storage=storage)
    registry = FactRegistry(storage=storage, evidence_registry=evidence_reg)

    evidence = await evidence_reg.record_evidence(
        entity_id="order:501",
        field_name="status",
        raw_payload={"status": "paid"},
        source="stripe",
    )

    fact = await registry.record_fact(
        entity_id="order:501",
        field_name="status",
        value="paid",
        source="stripe",
        version=1,
        evidence_id=evidence.evidence_id,
        ttl_seconds=300.0,
    )

    assert fact.state == FactState.VALID
    assert fact.version == 1
    assert len(fact.field_fingerprint) == 64

    # Loaded check
    loaded = await registry.get_fact("order:501", "status")
    assert loaded is not None
    assert loaded.value == "paid"
    assert loaded.state == FactState.VALID

    await storage.close()


@pytest.mark.asyncio
async def test_absence_of_update_does_not_imply_validity_ttl(temp_db_path: Path) -> None:
    """Explicit Rule: Absence of an update does NOT mean the fact remains valid.

    Expired TTL must cause the fact to degrade from VALID to STALE.
    """
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = FactRegistry(storage=storage)

    t0 = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)
    fact = await registry.record_fact(
        entity_id="stock:ticker",
        field_name="price",
        value=150.25,
        source="nasdaq",
        ttl_seconds=10.0,  # 10 seconds TTL
        observed_at=t0,
    )
    assert fact.is_fresh(t0) is True

    # Check at t0 + 5 seconds -> still fresh
    t_mid = t0 + timedelta(seconds=5)
    f_mid = await registry.get_fact("stock:ticker", "price", current_time=t_mid)
    assert f_mid is not None
    assert f_mid.state == FactState.VALID

    # Check at t0 + 15 seconds (exceeds TTL) -> must degrade to STALE
    t_stale = t0 + timedelta(seconds=15)
    f_stale = await registry.get_fact("stock:ticker", "price", current_time=t_stale)
    assert f_stale is not None
    assert f_stale.state == FactState.STALE
    assert f_stale.is_fresh(t_stale) is False

    await storage.close()


@pytest.mark.asyncio
async def test_version_conflict_rejection(temp_db_path: Path) -> None:
    """Out-of-order delayed update with version < current version must be rejected."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = FactRegistry(storage=storage)

    await registry.record_fact(
        entity_id="order:600",
        field_name="status",
        value="shipped",
        source="warehouse",
        version=5,
    )

    # Attempt to record an older version 3 (e.g. delayed 'processing' event)
    with pytest.raises(VersionConflictError):
        await registry.record_fact(
            entity_id="order:600",
            field_name="status",
            value="processing",
            source="warehouse",
            version=3,
        )

    # Verify fact still has version 5
    current = await registry.get_fact("order:600", "status")
    assert current is not None
    assert current.value == "shipped"
    assert current.version == 5

    await storage.close()


@pytest.mark.asyncio
async def test_fact_linking_to_missing_evidence_fails(temp_db_path: Path) -> None:
    """Attempting to link a fact to non-existent evidence raises EvidenceNotFoundError."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    registry = FactRegistry(storage=storage)

    with pytest.raises(EvidenceNotFoundError):
        await registry.record_fact(
            entity_id="order:700",
            field_name="status",
            value="paid",
            source="stripe",
            evidence_id="evi_non_existent_fake_id",
        )

    await storage.close()
