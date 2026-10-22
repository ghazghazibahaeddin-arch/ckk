"""Unit tests verifying policy evaluation engine decisions and guardrails."""


from cck.contracts.action import AgentAction
from cck.core.types import RiskLevel, VerdictDecision
from cck.policies.engine import PolicyEngine


def test_safe_action_allowed(safe_action: AgentAction) -> None:
    """Safe actions conforming to rules must be ALLOWED with low risk."""
    engine = PolicyEngine()
    verdict = engine.evaluate(safe_action)

    assert verdict.decision == VerdictDecision.ALLOW
    assert verdict.risk_level == RiskLevel.LOW
    assert verdict.risk_score < 0.3
    assert len(verdict.matched_policies) == 0


def test_destructive_command_blocked(dangerous_action: AgentAction) -> None:
    """Destructive shell commands must be strictly BLOCKED with CRITICAL risk."""
    engine = PolicyEngine()
    verdict = engine.evaluate(dangerous_action)

    assert verdict.decision == VerdictDecision.BLOCK
    assert verdict.risk_level == RiskLevel.CRITICAL
    assert verdict.risk_score == 1.0
    assert any(m.rule_id == "POL-SEC-001" for m in verdict.matched_policies)
    assert len(verdict.remediation_suggestions) > 0


def test_sensitive_path_blocked(safe_action: AgentAction) -> None:
    """Attempting to access /etc/shadow or credentials must be BLOCKED."""
    malicious_path_action = safe_action.model_copy(
        update={
            "action_id": "act-shadow-001",
            "parameters": {"path": "/etc/shadow"},
        }
    )
    engine = PolicyEngine()
    verdict = engine.evaluate(malicious_path_action)

    assert verdict.decision == VerdictDecision.BLOCK
    assert any(m.rule_id == "POL-SEC-002" for m in verdict.matched_policies)


def test_system_mutation_requires_approval(approval_action: AgentAction) -> None:
    """System configuration changes like systemctl stop must REQUIRE_APPROVAL."""
    engine = PolicyEngine()
    verdict = engine.evaluate(approval_action)

    assert verdict.decision == VerdictDecision.REQUIRE_APPROVAL
    assert verdict.risk_level == RiskLevel.HIGH
    assert any(m.rule_id == "POL-SEC-003" for m in verdict.matched_policies)
