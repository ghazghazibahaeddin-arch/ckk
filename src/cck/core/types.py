"""Core enumeration types for the CCK platform."""

from enum import Enum


class VerdictDecision(str, Enum):
    """The decision rendered by CCK for an incoming agent action."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REVALIDATE = "REVALIDATE"
    SIMULATE_ONLY = "SIMULATE_ONLY"


class RiskLevel(str, Enum):
    """Calculated risk tier for an agent action."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionSeverity(str, Enum):
    """Inherent severity level of the action requested by an agent."""

    INFORMATIONAL = "INFORMATIONAL"
    STANDARD = "STANDARD"
    MUTATION = "MUTATION"
    DESTRUCTIVE = "DESTRUCTIVE"


class ActionStatus(str, Enum):
    """State transition lifecycle of an action inside the CCK platform."""

    PENDING = "PENDING"
    EVALUATED = "EVALUATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class FactState(str, Enum):
    """Lifecycle and trustworthiness status of a known fact."""

    VALID = "VALID"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"
    UNKNOWN = "UNKNOWN"


class DependencyType(str, Enum):
    """Category of node or edge in the reliability dependency graph."""

    ENTITY = "ENTITY"
    FACT = "FACT"
    EVIDENCE = "EVIDENCE"
    DECISION = "DECISION"
    ACTION = "ACTION"


class JournalEventType(str, Enum):
    """Types of entries recorded in the immutable event journal."""

    ENTITY_REGISTERED = "ENTITY_REGISTERED"
    FACT_OBSERVED = "FACT_OBSERVED"
    FACT_INVALIDATED = "FACT_INVALIDATED"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    DEPENDENCY_LINKED = "DEPENDENCY_LINKED"
    ACTION_EVALUATED = "ACTION_EVALUATED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    GATE_DECISION = "GATE_DECISION"
    COMPENSATION_EXECUTED = "COMPENSATION_EXECUTED"


class ConnectorCapability(str, Enum):
    """Capabilities supported by external execution connectors."""

    READ = "READ"
    WRITE = "WRITE"
    CONDITIONAL_WRITE = "CONDITIONAL_WRITE"
    IDEMPOTENCY = "IDEMPOTENCY"
    COMPENSATION = "COMPENSATION"
    VERSION_CHECK = "VERSION_CHECK"
    HEALTH_CHECK = "HEALTH_CHECK"


class NormalizedErrorCategory(str, Enum):
    """Normalized categories for connector and external system failures."""

    AUTHENTICATION = "AUTHENTICATION"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITING = "RATE_LIMITING"
    CONNECTIVITY = "CONNECTIVITY"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    TIMEOUT = "TIMEOUT"
    EXECUTION_FAILURE = "EXECUTION_FAILURE"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    UNKNOWN = "UNKNOWN"


class IdempotencyStatus(str, Enum):
    """Status lifecycle of an idempotent action execution attempt."""

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"


class ApprovalStatus(str, Enum):
    """Status lifecycle of a human approval workflow request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ReservationStatus(str, Enum):
    """Status lifecycle of a resource reservation lease."""

    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class RecoveryState(str, Enum):
    """State lifecycle of a recovery and repair orchestration session."""

    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    REEVALUATING = "REEVALUATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REPAIRING = "REPAIRING"
    VERIFYING = "VERIFYING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    MANUAL_INTERVENTION = "MANUAL_INTERVENTION"
