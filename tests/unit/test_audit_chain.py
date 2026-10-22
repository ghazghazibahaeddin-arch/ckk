"""Unit tests verifying audit logging and cryptographic hash chain integrity."""

from pathlib import Path

import pytest

from cck.audit.service import AuditService
from cck.contracts.action import AgentAction
from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import RiskLevel, VerdictDecision
from cck.storage.sqlite import SQLiteStorageBackend


@pytest.mark.asyncio
async def test_audit_hash_chain_integrity(temp_db_path: Path, safe_action: AgentAction) -> None:
    """Ensure audit records create an unbroken, verifiable hash chain."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()
    service = AuditService(storage=storage)

    # 1. First record (previous_hash should be None)
    await storage.save_action(safe_action)
    dummy_verdict = ExecutionVerdict(
        action_id=safe_action.action_id,
        decision=VerdictDecision.ALLOW,
        risk_level=RiskLevel.LOW,
        risk_score=0.1,
        reason="Conforms to policy",
    )
    rec1 = await service.record_evaluation(safe_action, dummy_verdict)
    assert rec1.previous_hash is None
    assert len(rec1.action_hash) == 64

    # 2. Second record (previous_hash must match rec1.action_hash)
    action2 = safe_action.model_copy(update={"action_id": "act-2"})
    await storage.save_action(action2)
    verdict2 = dummy_verdict.model_copy(update={"action_id": "act-2"})
    rec2 = await service.record_evaluation(action2, verdict2)
    assert rec2.previous_hash == rec1.action_hash

    # 3. Third record (previous_hash must match rec2.action_hash)
    action3 = safe_action.model_copy(update={"action_id": "act-3"})
    await storage.save_action(action3)
    verdict3 = dummy_verdict.model_copy(update={"action_id": "act-3"})
    rec3 = await service.record_evaluation(action3, verdict3)
    assert rec3.previous_hash == rec2.action_hash

    # Verify chain
    chain = [rec1, rec2, rec3]
    assert AuditService.verify_chain_integrity(chain) is True

    # Tampered chain detection
    tampered_chain = [rec1, rec3]  # Skipping rec2 breaks chain
    assert AuditService.verify_chain_integrity(tampered_chain) is False

    await storage.close()
