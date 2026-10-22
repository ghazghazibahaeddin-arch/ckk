"""Evidence Registry for CCK.

Issues, validates, and stores tamper-evident provenance records for facts.
Strictly requires system-issued evidence identifiers to prevent AI agents
from fabricating citations or passing unverified strings as trusted proof.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cck.contracts.evidence import Evidence, compute_payload_hash
from cck.core.exceptions import EvidenceNotFoundError, EvidenceTamperedError
from cck.storage.base import StorageBackend


class EvidenceRegistry:
    """Registry maintaining authoritative, system-minted evidence records."""

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    async def record_evidence(
        self,
        entity_id: str,
        field_name: str,
        raw_payload: Any,
        source: str,
        observed_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """Create and persist a new evidence record with a system-minted identifier.

        The system computes the cryptographic SHA-256 hash of the canonical raw payload
        to ensure subsequent tamper-evidence.
        """
        evidence_id = f"evi_{uuid4().hex}"
        obs_time = observed_at or datetime.now(timezone.utc)
        payload_hash = compute_payload_hash(raw_payload)

        evidence = Evidence(
            evidence_id=evidence_id,
            entity_id=entity_id,
            field_name=field_name,
            raw_payload=raw_payload,
            source=source,
            observed_at=obs_time,
            payload_hash=payload_hash,
            metadata=metadata or {},
        )

        await self.storage.save_evidence(evidence)
        return evidence

    async def get_evidence(self, evidence_id: str) -> Evidence:
        """Fetch an evidence record by ID.

        Raises EvidenceNotFoundError if the ID does not exist in the registry.
        """
        evidence = await self.storage.get_evidence(evidence_id)
        if evidence is None:
            raise EvidenceNotFoundError(
                f"Evidence '{evidence_id}' does not exist in the trusted Evidence Registry."
            )
        return evidence

    async def verify_evidence(
        self,
        evidence_id: str,
        expected_payload: Any | None = None,
    ) -> bool:
        """Verify that an evidence record exists, is untampered, and optionally matches expected data.

        Raises:
            EvidenceNotFoundError: If evidence_id is unknown or fabricated.
            EvidenceTamperedError: If the stored payload hash does not match the raw payload.
        """
        evidence = await self.get_evidence(evidence_id)

        # 1. Cryptographic tamper verification
        recomputed_hash = compute_payload_hash(evidence.raw_payload)
        if evidence.payload_hash != recomputed_hash:
            raise EvidenceTamperedError(
                f"Evidence '{evidence_id}' has been tampered with! "
                f"Recorded hash: {evidence.payload_hash}, computed hash: {recomputed_hash}"
            )

        # 2. Expected data match verification
        return not (expected_payload is not None and evidence.raw_payload != expected_payload)

    async def is_valid_evidence_id(self, evidence_id: str) -> bool:
        """Check if an evidence ID is syntactically valid and registered."""
        if not evidence_id or not evidence_id.startswith("evi_"):
            return False
        try:
            await self.get_evidence(evidence_id)
            return True
        except EvidenceNotFoundError:
            return False
