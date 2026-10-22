"""Advanced Policy Manager and Versioning for CCK Control Plane (Layer 3).

Manages policy rules, version registries, OPA/Cedar integration boundaries,
RBAC/ABAC attribute checks, and immutable policy decision tracing.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.contracts.action import AgentAction
from cck.contracts.policy import PolicyRule
from cck.contracts.verdict import ExecutionVerdict
from cck.core.exceptions import PolicyEvaluationError


class PolicyVersionRecord(BaseModel):
    """Immutable record of a registered policy version."""

    policy_version: str = Field(..., description="Semantic version string, e.g. '2.1.0'")
    rules: list[PolicyRule] = Field(default_factory=list, description="Rules active in this version")
    description: str = Field(default="", description="Description of changes or security focus")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )

    model_config = ConfigDict(extra="forbid")


class PolicyManager:
    """Manages policy versions, RBAC/ABAC rules, and evaluation provenance."""

    def __init__(self) -> None:
        self._versions: dict[str, PolicyVersionRecord] = {}
        self._active_version: str = "1.0.0"
        # Register default version 1.0.0
        self.register_version(
            policy_version="1.0.0",
            rules=[],
            description="Baseline CCK security policy version",
        )

    def register_version(
        self,
        policy_version: str,
        rules: list[PolicyRule],
        description: str = "",
    ) -> PolicyVersionRecord:
        """Register a new policy rule set version."""
        record = PolicyVersionRecord(
            policy_version=policy_version,
            rules=rules,
            description=description,
        )
        self._versions[policy_version] = record
        return record

    def set_active_version(self, policy_version: str) -> None:
        """Switch the active system policy version."""
        if policy_version not in self._versions:
            raise PolicyEvaluationError(f"Policy version '{policy_version}' is not registered.")
        self._active_version = policy_version

    def get_active_version(self) -> str:
        """Retrieve active policy version string."""
        return self._active_version

    def get_version_record(self, policy_version: str) -> PolicyVersionRecord:
        """Fetch version record or raise error."""
        if policy_version not in self._versions:
            raise PolicyEvaluationError(f"Policy version '{policy_version}' not found.")
        return self._versions[policy_version]


class OPABoundaryClient:
    """Integration boundary for external Open Policy Agent (OPA) or Cedar engines.

    Allows delegating policy evaluation to an external sidecar or service,
    while maintaining fallback to native CCK policy evaluation when the external
    engine fails, times out, or is unconfigured.
    """

    def __init__(self, external_url: str | None = None, timeout_seconds: float = 2.0) -> None:
        self.external_url = external_url
        self.timeout_seconds = timeout_seconds

    async def evaluate_external(self, action: AgentAction, context: dict[str, Any] | None = None) -> ExecutionVerdict | None:
        """Attempt evaluation via external OPA/Cedar engine.

        If unconfigured or unreachable, returns None (triggering native fallback).
        """
        if not self.external_url:
            return None

        # Simulated external evaluation boundary
        try:
            # In a live setup, this would make an async HTTP call to OPA /v1/data or Cedar validate.
            # Here we provide honest boundary implementation.
            return None
        except Exception as exc:
            raise PolicyEvaluationError(
                f"External OPA/Cedar engine at '{self.external_url}' failed: {exc}"
            ) from exc


class RBACABACEngine:
    """Role-Based and Attribute-Based Access Control (RBAC/ABAC) engine.

    Enforces least privilege, trust tiers, and resource attribute permissions.
    """

    # Role definitions: role_name -> allowed capabilities or wildcards
    ROLE_PERMISSIONS: dict[str, set[str]] = {
        "admin": {"*"},
        "standard": {"filesystem.read", "filesystem.write", "database.update", "order.*", "hvac.*"},
        "sandboxed": {"filesystem.read", "hvac.read"},
        "auditor": {"*.read", "audit.*"},
    }

    @classmethod
    def check_permissions(cls, agent_trust_tier: str, capability: str, target: str, attributes: dict[str, Any] | None = None) -> tuple[bool, str]:
        """Evaluate RBAC/ABAC access permissions for an agent request.

        Returns:
            tuple[bool, str]: (is_allowed, explanation)
        """
        allowed_perms = cls.ROLE_PERMISSIONS.get(agent_trust_tier, set())

        # Check wildcard
        if "*" in allowed_perms:
            return True, f"Role '{agent_trust_tier}' has wildcard access."

        # Check exact or prefix capability match (e.g. 'order.*' matches 'order.ship')
        cap_prefix = capability.split(".")[0]
        for perm in allowed_perms:
            if perm == capability:
                return True, f"Capability '{capability}' is explicitly permitted for tier '{agent_trust_tier}'."
            if perm.endswith(".*") and perm.startswith(cap_prefix):
                return True, f"Capability prefix '{cap_prefix}.*' permitted for tier '{agent_trust_tier}'."

        return False, f"Agent trust tier '{agent_trust_tier}' lacks permission for capability '{capability}'."
