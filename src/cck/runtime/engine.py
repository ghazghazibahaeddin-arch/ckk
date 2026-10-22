"""CCK Control Plane runtime engine orchestrating policies, audit, storage, and reliability."""

from cck.audit.service import AuditService
from cck.contracts.action import AgentAction
from cck.contracts.audit import AuditRecord
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.policy import PolicyRule
from cck.contracts.verdict import ExecutionVerdict
from cck.core.config import CCKSettings, get_settings
from cck.core.logging import logger
from cck.core.types import ActionStatus, JournalEventType
from cck.policies.engine import DEFAULT_BASELINE_POLICIES, PolicyEngine
from cck.reliability.action_gate import ActionGate
from cck.reliability.contract_registry import ContractRegistry
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.entity_registry import EntityRegistry
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.reliability.freshness_engine import FreshnessEngine
from cck.reliability.journal import EventJournal
from cck.reliability.replay_engine import ReplayEngine
from cck.storage.base import StorageBackend
from cck.storage.sqlite import SQLiteStorageBackend


class CCKControlPlane:
    """The central control plane gateway intercepting external AI agent actions."""

    def __init__(
        self,
        storage: StorageBackend | None = None,
        policy_engine: PolicyEngine | None = None,
        settings: CCKSettings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.storage = storage or SQLiteStorageBackend(db_path=self.settings.sqlite_db_path)
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit_service = AuditService(storage=self.storage)

        # Layer 1: Core Reliability Engine Registries & Engines
        self.entity_registry = EntityRegistry(storage=self.storage)
        self.evidence_registry = EvidenceRegistry(storage=self.storage)
        self.fact_registry = FactRegistry(
            storage=self.storage, evidence_registry=self.evidence_registry
        )
        self.dependency_graph = DependencyGraph()
        self.freshness_engine = FreshnessEngine(
            fact_registry=self.fact_registry,
            dependency_graph=self.dependency_graph,
        )
        self.action_gate = ActionGate(
            evidence_registry=self.evidence_registry,
            fact_registry=self.fact_registry,
            dependency_graph=self.dependency_graph,
            policy_engine=self.policy_engine,
            shadow_mode=self.settings.shadow_mode,
        )
        self.event_journal = EventJournal(storage=self.storage)
        self.replay_engine = ReplayEngine(policy_engine=self.policy_engine)
        self.contract_registry = ContractRegistry()

        self._is_initialized: bool = False

    async def initialize(self) -> None:
        """Initialize persistence layer and load baseline policy rules."""
        if self._is_initialized:
            return

        logger.info("Initializing CCK Control Plane runtime engine...")
        await self.storage.initialize()

        # Seed default policies if none exist
        existing_policies = await self.storage.list_policies(active_only=False)
        if not existing_policies:
            logger.info("Seeding baseline security policies (%d rules)...", len(DEFAULT_BASELINE_POLICIES))
            for policy in DEFAULT_BASELINE_POLICIES:
                await self.storage.save_policy(policy)
            self.policy_engine.set_policies(DEFAULT_BASELINE_POLICIES)
        else:
            self.policy_engine.set_policies(existing_policies)

        self._is_initialized = True
        logger.info("CCK Control Plane initialized successfully.")

    async def shutdown(self) -> None:
        """Gracefully shut down connections."""
        await self.storage.close()
        self._is_initialized = False

    async def evaluate_action(
        self,
        action: AgentAction,
        spec: ActionDependencySpec | None = None,
    ) -> ExecutionVerdict:
        """Evaluate an incoming agent action through the Action Gate and record audit + journal events."""
        if not self._is_initialized:
            await self.initialize()

        # 1. Persist proposed action
        await self.storage.save_action(action)

        # 2. Evaluate through the Action Gate (checks evidence, fact freshness, dependencies, policies)
        verdict = await self.action_gate.evaluate_action(action=action, spec=spec)

        # 3. Append tamper-evident audit record
        await self.audit_service.record_evaluation(
            action=action,
            verdict=verdict,
            status=ActionStatus.EVALUATED,
        )

        # 4. Record to Event Journal for deterministic replayability
        await self.event_journal.record_event(
            correlation_id=action.session_id,
            event_type=JournalEventType.GATE_DECISION,
            payload={
                "action": action.model_dump(mode="json"),
                "spec": spec.model_dump(mode="json") if spec else None,
                "decision": verdict.decision.value,
                "risk_score": verdict.risk_score,
                "reason": verdict.reason,
            },
            policy_version="1.0.0",
        )

        logger.info(
            "Evaluated action [%s] for agent [%s]: %s (Risk: %s, Score: %.2f)",
            action.action_id,
            action.agent.agent_id,
            verdict.decision.value,
            verdict.risk_level.value,
            verdict.risk_score,
        )

        return verdict

    async def get_action(self, action_id: str) -> AgentAction | None:
        """Retrieve an action from storage."""
        return await self.storage.get_action(action_id)

    async def list_policies(self, active_only: bool = True) -> list[PolicyRule]:
        """List current policy rules."""
        return await self.storage.list_policies(active_only=active_only)

    async def list_audits(self, limit: int = 50, offset: int = 0) -> list[AuditRecord]:
        """List audit ledger entries."""
        return await self.storage.list_audits(limit=limit, offset=offset)
