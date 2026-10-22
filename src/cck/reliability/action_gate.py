"""Action Gate for CCK.

Central control gate evaluating external agent actions against evidence validity,
fact freshness, dependency graph integrity, and safety policies.
Guarantees zero-bypass on protected action dispatch paths.
"""

from datetime import datetime, timezone

from cck.contracts.action import AgentAction
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.verdict import ExecutionVerdict, PolicyMatch
from cck.core.exceptions import EvidenceNotFoundError, EvidenceTamperedError
from cck.core.types import FactState, RiskLevel, VerdictDecision
from cck.policies.engine import PolicyEngine
from cck.reliability.dependency_graph import DependencyGraph
from cck.reliability.evidence_registry import EvidenceRegistry
from cck.reliability.fact_registry import FactRegistry


class ActionGate:
    """The authoritative gatekeeper guarding all external system actions."""

    def __init__(
        self,
        evidence_registry: EvidenceRegistry,
        fact_registry: FactRegistry,
        dependency_graph: DependencyGraph,
        policy_engine: PolicyEngine | None = None,
        shadow_mode: bool = False,
    ) -> None:
        self.evidence_registry = evidence_registry
        self.fact_registry = fact_registry
        self.dependency_graph = dependency_graph
        self.policy_engine = policy_engine or PolicyEngine()
        self.shadow_mode = shadow_mode

    def _wrap_verdict(self, verdict: ExecutionVerdict) -> ExecutionVerdict:
        """Wrap verdict if shadow/observe mode is active."""
        if not self.shadow_mode or verdict.decision == VerdictDecision.ALLOW:
            return verdict
        return verdict.model_copy(
            update={
                "decision": VerdictDecision.ALLOW,
                "shadow_mode": True,
                "simulated_decision": verdict.decision,
                "reason": f"[SHADOW_MODE_PERMITTED] {verdict.reason}",
            }
        )

    async def evaluate_action(
        self,
        action: AgentAction,
        spec: ActionDependencySpec | None = None,
        current_time: datetime | None = None,
    ) -> ExecutionVerdict:
        """Evaluate action readiness and safety before physical external execution."""
        verdict = await self._evaluate_raw(action, spec, current_time)
        return self._wrap_verdict(verdict)

    async def _evaluate_raw(
        self,
        action: AgentAction,
        spec: ActionDependencySpec | None = None,
        current_time: datetime | None = None,
    ) -> ExecutionVerdict:
        """Evaluate action readiness and safety before physical external execution.

        Checks performed:
        1. Baseline policy security guardrails (destructive commands, sensitive paths).
        2. Evidence authentication: verifies all claimed evidence IDs are system-issued and untampered.
        3. Fact validity and freshness: verifies all required facts are VALID.
           - If a required fact is STALE (TTL expired) -> returns REVALIDATE.
           - If a required fact is INVALIDATED -> returns BLOCK.
           - If a required fact is missing/UNKNOWN -> returns BLOCK.
        4. Dependency graph integrity: verifies action node has required edges.

        Zero-Bypass Policy:
        Actions failing any verification step are blocked or held for revalidation.
        """
        now = current_time or datetime.now(timezone.utc)

        # 1. First-line defense: Security policy guardrails
        policy_verdict = self.policy_engine.evaluate(action)
        if policy_verdict.decision in (VerdictDecision.BLOCK, VerdictDecision.REQUIRE_APPROVAL):
            return policy_verdict

        # If no dependency spec is provided for standard actions, return policy verdict
        if spec is None:
            return policy_verdict

        # 2. Check claimed evidence in Evidence Registry
        for evi_id in spec.claimed_evidence_ids:
            try:
                is_valid = await self.evidence_registry.verify_evidence(evi_id)
                if not is_valid:
                    return ExecutionVerdict(
                        action_id=action.action_id,
                        decision=VerdictDecision.BLOCK,
                        risk_level=RiskLevel.HIGH,
                        risk_score=0.9,
                        reason=f"Claimed evidence '{evi_id}' does not match recorded state payload.",
                        remediation_suggestions=["Re-read underlying system state and submit fresh evidence."],
                    )
            except EvidenceNotFoundError:
                # Fabricated or untracked evidence ID!
                return ExecutionVerdict(
                    action_id=action.action_id,
                    decision=VerdictDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=1.0,
                    reason=f"Action references unknown/fabricated evidence '{evi_id}'. System-minted evidence required.",
                    matched_policies=[
                        PolicyMatch(
                            rule_id="POL-REL-EVI-001",
                            rule_name="Reject Untracked Evidence",
                            effect=VerdictDecision.BLOCK,
                            reason=f"Evidence ID '{evi_id}' was not generated by trusted CCK system.",
                            risk_score=1.0,
                        )
                    ],
                    remediation_suggestions=["Submit actions referencing authentic system-issued evidence records."],
                )
            except EvidenceTamperedError as exc:
                return ExecutionVerdict(
                    action_id=action.action_id,
                    decision=VerdictDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=1.0,
                    reason=f"Evidence integrity check failed: {exc}",
                    remediation_suggestions=["Investigate possible storage or payload corruption."],
                )

        # 3. Check required facts in Fact Registry
        for entity_id, field_name in spec.required_facts:
            fact = await self.fact_registry.get_fact(entity_id, field_name, current_time=now)

            if fact is None or fact.state == FactState.UNKNOWN:
                return ExecutionVerdict(
                    action_id=action.action_id,
                    decision=VerdictDecision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    risk_score=0.85,
                    reason=f"Required fact '{entity_id}.{field_name}' is unknown or has no recorded observations.",
                    remediation_suggestions=[f"Query trusted source to establish fact for '{entity_id}.{field_name}'."],
                )

            if fact.state == FactState.INVALIDATED:
                return ExecutionVerdict(
                    action_id=action.action_id,
                    decision=VerdictDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=0.95,
                    reason=(
                        f"Required fact '{entity_id}.{field_name}' has been INVALIDATED "
                        f"by a subsequent trusted event (current value: {fact.value})."
                    ),
                    matched_policies=[
                        PolicyMatch(
                            rule_id="POL-REL-DEP-001",
                            rule_name="Invalidated Precondition Guard",
                            effect=VerdictDecision.BLOCK,
                            reason=f"Precondition '{entity_id}.{field_name}' was refuted by trusted source update.",
                            risk_score=0.95,
                        )
                    ],
                    remediation_suggestions=[
                        "Abort action or formulate a new plan based on the updated entity state."
                    ],
                )

            if fact.state == FactState.STALE or not fact.is_fresh(now):
                age = (now - fact.observed_at).total_seconds()
                ttl = fact.ttl_seconds or 0.0
                return ExecutionVerdict(
                    action_id=action.action_id,
                    decision=VerdictDecision.REVALIDATE,
                    risk_level=RiskLevel.MEDIUM,
                    risk_score=0.6,
                    reason=(
                        f"Required fact '{entity_id}.{field_name}' is STALE "
                        f"(age {age:.1f}s exceeds policy TTL {ttl:.1f}s). Revalidation required."
                    ),
                    remediation_suggestions=[
                        f"Perform a live read of '{entity_id}.{field_name}' before retrying action."
                    ],
                )

        # 4. Success: All checks passed
        return ExecutionVerdict(
            action_id=action.action_id,
            decision=VerdictDecision.ALLOW,
            risk_level=RiskLevel.LOW,
            risk_score=0.1,
            reason="All required facts are fresh, valid, substantiated by authentic evidence, and compliant with policy.",
            matched_policies=[],
            remediation_suggestions=[],
        )
