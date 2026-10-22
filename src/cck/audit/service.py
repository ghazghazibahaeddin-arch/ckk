"""Tamper-evident audit service maintaining cryptographic action provenance."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from cck.contracts.action import AgentAction
from cck.contracts.audit import AuditRecord
from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import ActionStatus
from cck.storage.base import StorageBackend


def compute_action_hash(action: AgentAction) -> str:
    """Compute a deterministic SHA-256 hash for canonical agent action data."""
    canonical_dict = {
        "action_id": action.action_id,
        "agent_id": action.agent.agent_id,
        "session_id": action.session_id,
        "capability": action.capability,
        "target": action.target,
        "parameters": sorted(action.parameters.items()),
        "severity": action.severity.value,
        "timestamp": action.timestamp.isoformat(),
    }
    encoded = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AuditService:
    """Service responsible for creating, recording, and verifying audit records."""

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    async def record_evaluation(
        self,
        action: AgentAction,
        verdict: ExecutionVerdict,
        status: ActionStatus = ActionStatus.EVALUATED,
    ) -> AuditRecord:
        """Create and store an audit record linked to the previous record hash."""
        action_hash = compute_action_hash(action)
        previous_hash = await self.storage.get_last_audit_hash()

        record = AuditRecord(
            audit_id=str(uuid4()),
            action_id=action.action_id,
            agent_id=action.agent.agent_id,
            action_hash=action_hash,
            previous_hash=previous_hash,
            verdict=verdict,
            execution_status=status,
            execution_result=None,
            recorded_at=datetime.now(timezone.utc),
        )

        await self.storage.record_audit(record)
        return record

    @staticmethod
    def verify_chain_integrity(records: list[AuditRecord]) -> bool:
        """Verify that the cryptographic hash chain is unbroken.

        Records must be provided in ascending chronological order.
        """
        if not records or len(records) <= 1:
            return True

        for i in range(1, len(records)):
            current = records[i]
            prev = records[i - 1]
            if current.previous_hash != prev.action_hash:
                return False

        return True
