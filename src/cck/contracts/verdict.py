"""Contracts for execution verdicts and policy evaluation results."""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import RiskLevel, VerdictDecision


class PolicyMatch(BaseModel):
    """Details of an individual policy rule match during evaluation."""

    rule_id: str = Field(..., description="ID of the matched policy rule")
    rule_name: str = Field(..., description="Name of the matched policy rule")
    effect: VerdictDecision = Field(..., description="Effect mandated by this rule")
    reason: str = Field(..., description="Specific trigger reason or matched constraint")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk contribution (0.0 to 1.0)")

    model_config = ConfigDict(frozen=True)


class ExecutionVerdict(BaseModel):
    """The authoritative decision produced by the CCK control plane for an action."""

    verdict_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this verdict",
    )
    action_id: str = Field(..., description="Identifier of the evaluated AgentAction")
    decision: VerdictDecision = Field(
        ...,
        description="Final verdict decision (ALLOW, BLOCK, REQUIRE_APPROVAL)",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Composite risk tier determined by evaluation",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Aggregated risk score between 0.0 (safe) and 1.0 (critical)",
    )
    reason: str = Field(..., description="Executive summary of the decision rationale")
    matched_policies: list[PolicyMatch] = Field(
        default_factory=list,
        description="List of policy rules that matched during evaluation",
    )
    remediation_suggestions: list[str] = Field(
        default_factory=list,
        description="Suggestions or mitigation steps if the action was blocked or gated",
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when evaluation finished",
    )
    shadow_mode: bool = Field(
        default=False,
        description="Whether this verdict was evaluated in Observe/Shadow mode",
    )
    simulated_decision: VerdictDecision | None = Field(
        default=None,
        description="The simulated non-allowed decision that would have been enforced",
    )

    model_config = ConfigDict(extra="forbid")
