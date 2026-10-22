"""Policy evaluation engine and standard security guardrails."""

import fnmatch
import re
from collections.abc import Sequence

from cck.contracts.action import AgentAction
from cck.contracts.policy import PolicyRule
from cck.contracts.verdict import ExecutionVerdict, PolicyMatch
from cck.core.types import ActionSeverity, RiskLevel, VerdictDecision

# Baseline security guardrails established for CCK
DEFAULT_BASELINE_POLICIES: list[PolicyRule] = [
    PolicyRule(
        rule_id="POL-SEC-001",
        name="Block Destructive Shell Invocations",
        description="Prevents execution of catastrophic or irreversible filesystem and system commands.",
        capability_pattern="bash.*",
        target_pattern="*",
        action_effect=VerdictDecision.BLOCK,
        risk_level=RiskLevel.CRITICAL,
        is_active=True,
        conditions={
            "forbidden_command_patterns": [
                r"\brm\s+-[rRfF]*\s+/",
                r"\bmkfs\b",
                r"\bdd\s+if=",
                r">\s*/dev/sd[a-z]",
                r":\(\)\s*\{\s*:\|:&\s*\};:",  # Fork bomb
                r"\bchmod\s+-R\s+777\s+/",
            ]
        },
    ),
    PolicyRule(
        rule_id="POL-SEC-002",
        name="Block Sensitive Path Access",
        description="Prohibits agent actions attempting to read or tamper with security credentials and system keys.",
        capability_pattern="filesystem.*",
        target_pattern="*",
        action_effect=VerdictDecision.BLOCK,
        risk_level=RiskLevel.HIGH,
        is_active=True,
        conditions={
            "forbidden_path_substrings": [
                "/etc/shadow",
                "/etc/sudoers",
                ".ssh/id_rsa",
                ".ssh/id_ed25519",
                ".aws/credentials",
            ]
        },
    ),
    PolicyRule(
        rule_id="POL-SEC-003",
        name="Require Approval for System Mutations",
        description="Demands human operator approval for privileged service or network changes.",
        capability_pattern="bash.*",
        target_pattern="*",
        action_effect=VerdictDecision.REQUIRE_APPROVAL,
        risk_level=RiskLevel.HIGH,
        is_active=True,
        conditions={
            "approval_command_patterns": [
                r"\buseradd\b",
                r"\buserdel\b",
                r"\biptables\b",
                r"\bsystemctl\s+stop\b",
                r"\bsystemctl\s+disable\b",
            ]
        },
    ),
]


class PolicyEngine:
    """Evaluates proposed AgentAction objects against active policy rules."""

    def __init__(self, policies: Sequence[PolicyRule] | None = None) -> None:
        self._policies: list[PolicyRule] = list(policies or DEFAULT_BASELINE_POLICIES)

    def set_policies(self, policies: Sequence[PolicyRule]) -> None:
        """Update active policies."""
        self._policies = [p for p in policies if p.is_active]

    def add_policy(self, policy: PolicyRule) -> None:
        """Register an additional policy."""
        self._policies.append(policy)

    def evaluate(self, action: AgentAction) -> ExecutionVerdict:
        """Evaluate an action against all active rules and formulate an authoritative verdict."""
        matches: list[PolicyMatch] = []
        suggestions: list[str] = []

        command_param = str(
            action.parameters.get("command")
            or action.parameters.get("cmd")
            or action.parameters.get("script")
            or ""
        )
        path_param = str(action.parameters.get("path") or action.target or "")

        for policy in self._policies:
            if not policy.is_active:
                continue

            # Check capability matching
            if not fnmatch.fnmatch(action.capability, policy.capability_pattern):
                continue

            # Check target pattern matching
            if policy.target_pattern != "*" and not fnmatch.fnmatch(
                action.target, policy.target_pattern
            ):
                continue

            # Check pattern conditions: destructive commands
            forbidden_cmds = policy.conditions.get("forbidden_command_patterns", [])
            for pattern in forbidden_cmds:
                if re.search(pattern, command_param, re.IGNORECASE):
                    matches.append(
                        PolicyMatch(
                            rule_id=policy.rule_id,
                            rule_name=policy.name,
                            effect=policy.action_effect,
                            reason=f"Command matches forbidden destructive pattern: '{pattern}'",
                            risk_score=1.0,
                        )
                    )
                    suggestions.append(
                        "Remove recursive root deletions or destructive disk write operations."
                    )
                    break

            # Check pattern conditions: forbidden sensitive paths
            forbidden_paths = policy.conditions.get("forbidden_path_substrings", [])
            for path_sub in forbidden_paths:
                if path_sub in path_param or path_sub in command_param:
                    matches.append(
                        PolicyMatch(
                            rule_id=policy.rule_id,
                            rule_name=policy.name,
                            effect=policy.action_effect,
                            reason=f"Action touches protected sensitive path: '{path_sub}'",
                            risk_score=0.9,
                        )
                    )
                    suggestions.append(
                        "Route sensitive credentials access through a verified Secrets Manager."
                    )
                    break

            # Check approval patterns
            approval_cmds = policy.conditions.get("approval_command_patterns", [])
            for pattern in approval_cmds:
                if re.search(pattern, command_param, re.IGNORECASE):
                    matches.append(
                        PolicyMatch(
                            rule_id=policy.rule_id,
                            rule_name=policy.name,
                            effect=policy.action_effect,
                            reason=f"Command modifies privileged system state: '{pattern}'",
                            risk_score=0.7,
                        )
                    )
                    suggestions.append(
                        "Request supervisor authorization token before executing system configuration changes."
                    )
                    break

        # Decision Resolution Logic
        # Priority: BLOCK > REQUIRE_APPROVAL > ALLOW
        block_matches = [m for m in matches if m.effect == VerdictDecision.BLOCK]
        approval_matches = [m for m in matches if m.effect == VerdictDecision.REQUIRE_APPROVAL]

        if block_matches:
            top_match = max(block_matches, key=lambda m: m.risk_score)
            return ExecutionVerdict(
                action_id=action.action_id,
                decision=VerdictDecision.BLOCK,
                risk_level=RiskLevel.CRITICAL if top_match.risk_score >= 0.9 else RiskLevel.HIGH,
                risk_score=top_match.risk_score,
                reason=f"Action blocked by policy [{top_match.rule_id}]: {top_match.reason}",
                matched_policies=matches,
                remediation_suggestions=suggestions or ["Action violates safety policies."],
            )

        if approval_matches:
            top_match = max(approval_matches, key=lambda m: m.risk_score)
            return ExecutionVerdict(
                action_id=action.action_id,
                decision=VerdictDecision.REQUIRE_APPROVAL,
                risk_level=RiskLevel.HIGH,
                risk_score=top_match.risk_score,
                reason=f"Human approval required by [{top_match.rule_id}]: {top_match.reason}",
                matched_policies=matches,
                remediation_suggestions=suggestions
                or ["Submit approval request ticket to administrator."],
            )

        # Baseline safe allow
        base_score = 0.1
        if action.severity == ActionSeverity.MUTATION:
            base_score = 0.4
        elif action.severity == ActionSeverity.DESTRUCTIVE:
            base_score = 0.7

        risk_level = RiskLevel.LOW if base_score < 0.3 else RiskLevel.MEDIUM

        return ExecutionVerdict(
            action_id=action.action_id,
            decision=VerdictDecision.ALLOW,
            risk_level=risk_level,
            risk_score=base_score,
            reason="Action conforms to all active security policies and guardrails.",
            matched_policies=matches,
            remediation_suggestions=[],
        )
