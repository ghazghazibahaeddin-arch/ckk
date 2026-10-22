"""Audit Export and Integrity Verification for CCK Enterprise (Layer 7).

Provides secure export of immutable event journal records and cryptographic
integrity verification for compliance and auditing.
"""

import json

from cck.contracts.journal import JournalEntry
from cck.reliability.journal import EventJournal


class AuditExporter:
    """Exports audit logs in verified portable JSON/CSV formats."""

    @staticmethod
    def export_json(entries: list[JournalEntry]) -> str:
        """Export journal entries as formatted JSON."""
        dicts = [e.model_dump(mode="json") for e in entries]
        return json.dumps(dicts, indent=2, ensure_ascii=False)

    @staticmethod
    def verify_exported_audit(entries: list[JournalEntry]) -> tuple[bool, str]:
        """Verify cryptographic hash chain integrity of exported audit logs."""
        return EventJournal.verify_integrity(entries)
