"""Core data models for CCK Python SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    STANDARD = "STANDARD"
    MUTATION = "MUTATION"
    DESTRUCTIVE = "DESTRUCTIVE"


class VerdictDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REVALIDATE = "REVALIDATE"
    SIMULATE_ONLY = "SIMULATE_ONLY"


@dataclass
class AgentIdentity:
    agent_id: str
    name: str
    version: Optional[str] = "1.0.0"
    tenant_id: Optional[str] = None
    trust_tier: str = "standard"


@dataclass
class AgentAction:
    agent: AgentIdentity
    session_id: str
    capability: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    severity: ActionSeverity = ActionSeverity.MUTATION
    idempotency_key: Optional[str] = None
    action_id: Optional[str] = None


@dataclass
class PolicyMatch:
    rule_id: str
    rule_name: str
    effect: str
    reason: str
    risk_score: float


@dataclass
class ExecutionVerdict:
    verdict_id: str
    action_id: str
    decision: VerdictDecision
    risk_level: str
    risk_score: float
    reason: str
    matched_policies: List[PolicyMatch] = field(default_factory=list)
    remediation_suggestions: List[str] = field(default_factory=list)
    evaluated_at: Optional[str] = None
    shadow_mode: bool = False


@dataclass
class DecisionReceipt:
    receipt_id: str
    action_id: str
    decision: str
    agent_id: str
    tenant_id: str
    project_id: str
    capability: str
    target_resource: str
    risk_score: float
    timestamp: str
    rule_name: str
    receipt_hash: str
    verified_chain_status: bool
