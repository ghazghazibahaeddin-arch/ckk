"""Contracts for safety policies, guardrails, and control rules."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import RiskLevel, VerdictDecision


class PolicyRule(BaseModel):
    """Specification of an active governance rule or guardrail."""

    rule_id: str = Field(
        ...,
        description="Unique identifier for the policy rule (e.g. 'POL-BASH-001')",
    )
    name: str = Field(..., description="Short name of the policy rule")
    description: str = Field(..., description="Detailed rationale and explanation of the rule")
    capability_pattern: str = Field(
        ...,
        description="Glob or wildcard pattern for capabilities this rule applies to (e.g. 'bash.*')",
    )
    target_pattern: str = Field(
        default="*",
        description="Pattern matching the action target",
    )
    action_effect: VerdictDecision = Field(
        ...,
        description="Outcome when this rule matches (ALLOW, BLOCK, REQUIRE_APPROVAL)",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Associated risk tier assigned by this policy",
    )
    is_active: bool = Field(
        default=True,
        description="Whether this rule is currently enforced",
    )
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Declarative parameter conditions (e.g. forbidden keywords, regexes)",
    )

    model_config = ConfigDict(extra="forbid")
