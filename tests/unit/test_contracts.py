"""Unit tests verifying CCK Pydantic data contracts, serialization, and constraints."""

import pytest
from pydantic import ValidationError

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.policy import PolicyRule
from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import ActionSeverity, RiskLevel, VerdictDecision


def test_agent_identity_immutability(sample_agent: AgentIdentity) -> None:
    """AgentIdentity must be frozen and enforce integrity."""
    assert sample_agent.agent_id == "agt-sec-dev-01"
    with pytest.raises(ValidationError):
        # Trying to mutate frozen model attribute
        sample_agent.name = "TamperedAgent"  # type: ignore


def test_agent_action_serialization_roundtrip(safe_action: AgentAction) -> None:
    """AgentAction must serialize to JSON and reconstruct cleanly."""
    json_str = safe_action.model_dump_json()
    assert "act-safe-001" in json_str

    deserialized = AgentAction.model_validate_json(json_str)
    assert deserialized.action_id == safe_action.action_id
    assert deserialized.agent.agent_id == safe_action.agent.agent_id
    assert deserialized.capability == "filesystem.read"
    assert deserialized.severity == ActionSeverity.INFORMATIONAL


def test_agent_action_forbids_extra_fields() -> None:
    """Ensure strict schema adherence by disallowing undeclared fields."""
    with pytest.raises(ValidationError):
        AgentAction(
            action_id="act-extra-001",
            agent=AgentIdentity(agent_id="agt-1", name="Bot"),
            session_id="sess-1",
            capability="bash.execute",
            target="local",
            rogue_unauthorized_field="malicious_payload",  # type: ignore
        )


def test_execution_verdict_risk_score_bounds() -> None:
    """Risk score must strictly be constrained between 0.0 and 1.0."""
    with pytest.raises(ValidationError):
        ExecutionVerdict(
            verdict_id="vrd-1",
            action_id="act-1",
            decision=VerdictDecision.ALLOW,
            risk_level=RiskLevel.LOW,
            risk_score=1.5,  # Exceeds max 1.0
            reason="Invalid score",
        )

    with pytest.raises(ValidationError):
        ExecutionVerdict(
            verdict_id="vrd-1",
            action_id="act-1",
            decision=VerdictDecision.ALLOW,
            risk_level=RiskLevel.LOW,
            risk_score=-0.2,  # Subceeds min 0.0
            reason="Invalid score",
        )


def test_policy_rule_defaults() -> None:
    """Verify default values and active state for newly instantiated rules."""
    rule = PolicyRule(
        rule_id="POL-TEST-01",
        name="Test Rule",
        description="Verifies rule initialization",
        capability_pattern="api.*",
        action_effect=VerdictDecision.ALLOW,
    )
    assert rule.is_active is True
    assert rule.risk_level == RiskLevel.MEDIUM
    assert rule.target_pattern == "*"
    assert rule.conditions == {}
