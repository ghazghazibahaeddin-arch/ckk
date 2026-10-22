"""Replay Engine for CCK.

Replays recorded event journals in an isolated sandbox to verify decision reproducibility.
Strictly ensures zero external action execution during replay.
"""

from pydantic import BaseModel, ConfigDict, Field

from cck.contracts.action import AgentAction
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.journal import JournalEntry
from cck.core.types import JournalEventType
from cck.policies.engine import PolicyEngine
from cck.reliability.action_gate import ActionGate
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry
from cck.storage.sqlite import SQLiteStorageBackend


class ReplayStepResult(BaseModel):
    """Result of a single replayed event step."""

    entry_id: str
    event_type: JournalEventType
    original_verdict: str | None = None
    reproduced_verdict: str | None = None
    matched: bool = True
    divergence_reason: str | None = None

    model_config = ConfigDict(extra="forbid")


class ReplayReport(BaseModel):
    """Comprehensive outcome of replaying an event sequence."""

    total_steps: int = 0
    matched_steps: int = 0
    divergent_steps: int = 0
    external_actions_executed: int = 0  # Must strictly remain 0!
    is_fully_reproducible: bool = True
    step_results: list[ReplayStepResult] = Field(default_factory=list)
    divergence_details: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class ReplayEngine:
    """Isolated replay runner ensuring zero side-effects on real external environments."""

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()

    async def replay_session(
        self,
        journal_entries: list[JournalEntry],
        expected_policy_version: str | None = None,
    ) -> ReplayReport:
        """Replay journal entries in an isolated sandbox.

        Guarantees:
        1. ZERO real external actions are dispatched.
        2. Compares reproduced gate decisions against historical decisions recorded in journal.
        3. Identifies and details any policy or state drift.
        """
        # Create an isolated in-memory/temporary storage sandbox
        sandbox_storage = SQLiteStorageBackend(db_path=":memory:")
        await sandbox_storage.initialize()

        evidence_reg = EvidenceRegistry(storage=sandbox_storage)
        fact_reg = FactRegistry(storage=sandbox_storage, evidence_registry=evidence_reg)
        dep_graph = DependencyGraph()
        gate = ActionGate(
            evidence_registry=evidence_reg,
            fact_registry=fact_reg,
            dependency_graph=dep_graph,
            policy_engine=self.policy_engine,
        )

        report = ReplayReport()
        report.total_steps = len(journal_entries)

        try:
            for entry in journal_entries:
                step_res = ReplayStepResult(
                    entry_id=entry.entry_id,
                    event_type=entry.event_type,
                )

                # Policy version check
                if expected_policy_version and entry.policy_version != expected_policy_version:
                    step_res.matched = False
                    step_res.divergence_reason = (
                        f"Policy version mismatch: entry recorded with {entry.policy_version}, "
                        f"replay expected {expected_policy_version}."
                    )
                    report.divergent_steps += 1
                    report.is_fully_reproducible = False
                    report.divergence_details.append(step_res.divergence_reason)
                    report.step_results.append(step_res)
                    continue

                if entry.event_type == JournalEventType.EVIDENCE_RECORDED:
                    p = entry.payload
                    await evidence_reg.record_evidence(
                        entity_id=p["entity_id"],
                        field_name=p["field_name"],
                        raw_payload=p["raw_payload"],
                        source=p["source"],
                        observed_at=entry.timestamp,
                    )
                    step_res.matched = True

                elif entry.event_type == JournalEventType.FACT_OBSERVED:
                    p = entry.payload
                    await fact_reg.record_fact(
                        entity_id=p["entity_id"],
                        field_name=p["field_name"],
                        value=p["value"],
                        source=p["source"],
                        version=p.get("version", 1),
                        evidence_id=p.get("evidence_id"),
                        ttl_seconds=p.get("ttl_seconds"),
                        observed_at=entry.timestamp,
                    )
                    step_res.matched = True

                elif entry.event_type == JournalEventType.GATE_DECISION:
                    p = entry.payload
                    action_data = p.get("action")
                    original_decision = p.get("decision")
                    spec_data = p.get("spec")

                    if action_data:
                        action = AgentAction.model_validate(action_data)
                        spec = ActionDependencySpec.model_validate(spec_data) if spec_data else None

                        # DRY-RUN / SANDBOX EVALUATION: evaluate gate WITHOUT any real external dispatch
                        verdict = await gate.evaluate_action(
                            action=action,
                            spec=spec,
                            current_time=entry.timestamp,
                        )

                        step_res.original_verdict = original_decision
                        step_res.reproduced_verdict = verdict.decision.value

                        if original_decision == verdict.decision.value:
                            step_res.matched = True
                        else:
                            step_res.matched = False
                            step_res.divergence_reason = (
                                f"Decision divergence for action {action.action_id}: "
                                f"Historical was '{original_decision}', reproduced is '{verdict.decision.value}'."
                            )
                            report.divergent_steps += 1
                            report.is_fully_reproducible = False
                            report.divergence_details.append(step_res.divergence_reason)

                elif entry.event_type == JournalEventType.ACTION_EXECUTED:
                    # In replay, we DO NOT execute external actions!
                    # We simply note that external action execution was avoided in sandbox.
                    step_res.matched = True

                if step_res.matched:
                    report.matched_steps += 1
                report.step_results.append(step_res)

        finally:
            await sandbox_storage.close()

        # Guarantee: external_actions_executed remains strictly 0
        report.external_actions_executed = 0
        return report
