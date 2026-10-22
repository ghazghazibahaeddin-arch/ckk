"""Abstract Storage Backend boundary and interfaces for CCK."""

from abc import ABC, abstractmethod

from cck.contracts.action import AgentAction
from cck.contracts.audit import AuditRecord
from cck.contracts.entity import Entity
from cck.contracts.evidence import Evidence
from cck.contracts.fact import Fact
from cck.contracts.journal import JournalEntry
from cck.contracts.policy import PolicyRule


class StorageBackend(ABC):
    """Abstract interface defining the persistence layer contract for CCK.

    This abstraction decouples CCK domains from the concrete database engine,
    allowing zero-friction local development on SQLite and future horizontal
    scaling with PostgreSQL.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize connection pools and execute necessary schema migrations."""

    @abstractmethod
    async def close(self) -> None:
        """Gracefully release all database resources and connection pools."""

    # Actions
    @abstractmethod
    async def save_action(self, action: AgentAction) -> None:
        """Persist an agent action record."""

    @abstractmethod
    async def get_action(self, action_id: str) -> AgentAction | None:
        """Retrieve an action by its unique identifier."""

    # Policies
    @abstractmethod
    async def save_policy(self, policy: PolicyRule) -> None:
        """Insert or update a policy rule."""

    @abstractmethod
    async def get_policy(self, rule_id: str) -> PolicyRule | None:
        """Retrieve a policy rule by its rule_id."""

    @abstractmethod
    async def list_policies(self, active_only: bool = True) -> list[PolicyRule]:
        """List all registered policies, optionally filtered by active status."""

    # Audits
    @abstractmethod
    async def record_audit(self, audit: AuditRecord) -> None:
        """Append an immutable audit entry to the audit log."""

    @abstractmethod
    async def list_audits(self, limit: int = 50, offset: int = 0) -> list[AuditRecord]:
        """Retrieve paginated audit entries in chronological order."""

    @abstractmethod
    async def get_last_audit_hash(self) -> str | None:
        """Return the SHA-256 hash of the most recent audit entry for chain integrity."""

    # Entities
    @abstractmethod
    async def save_entity(self, entity: Entity) -> None:
        """Persist or update an entity."""

    @abstractmethod
    async def get_entity(self, entity_id: str) -> Entity | None:
        """Retrieve an entity by unique entity_id."""

    @abstractmethod
    async def list_entities(self, entity_type: str | None = None) -> list[Entity]:
        """List entities optionally filtered by entity_type."""

    # Facts
    @abstractmethod
    async def save_fact(self, fact: Fact) -> None:
        """Persist or update a fact."""

    @abstractmethod
    async def get_fact(self, entity_id: str, field_name: str) -> Fact | None:
        """Retrieve fact by entity_id and field_name."""

    @abstractmethod
    async def list_facts_for_entity(self, entity_id: str) -> list[Fact]:
        """Retrieve all facts known for an entity."""

    # Evidence
    @abstractmethod
    async def save_evidence(self, evidence: Evidence) -> None:
        """Persist an evidence record."""

    @abstractmethod
    async def get_evidence(self, evidence_id: str) -> Evidence | None:
        """Retrieve evidence by ID."""

    # Event Journal
    @abstractmethod
    async def append_journal(self, entry: JournalEntry) -> None:
        """Append a journal entry."""

    @abstractmethod
    async def list_journal_entries(
        self,
        correlation_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[JournalEntry]:
        """List chronological journal entries."""

    @abstractmethod
    async def get_last_journal_hash(self) -> str | None:
        """Return SHA-256 hash of the most recent journal entry."""
