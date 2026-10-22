"""Domain exception hierarchy for CCK."""


class CCKError(Exception):
    """Base exception for all errors raised by CCK."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(CCKError):
    """Raised when environment or platform configuration is invalid."""


class ValidationError(CCKError):
    """Raised when contract or payload validation fails."""


class StorageError(CCKError):
    """Raised when an operation on the storage backend fails."""


class RecordNotFoundError(StorageError):
    """Raised when a requested record does not exist in storage."""


class PolicyViolationError(CCKError):
    """Raised when an action violates an active strict security policy."""


class PolicyEvaluationError(CCKError):
    """Raised when policy evaluation fails or version is not found."""


class ActionBlockedError(CCKError):
    """Raised when execution of an action is actively prevented by the gatekeeper."""


class EntityNotFoundError(CCKError):
    """Raised when an entity is requested but cannot be found."""


class EntityConflictError(CCKError):
    """Raised when an entity ID or unique property conflicts with an existing entity."""


class EvidenceNotFoundError(CCKError):
    """Raised when a referenced evidence ID does not exist in the Evidence Registry."""


class EvidenceTamperedError(CCKError):
    """Raised when an evidence payload does not match its recorded cryptographic hash."""


class StaleFactError(CCKError):
    """Raised when a fact's freshness has expired or its state is STALE."""


class VersionConflictError(CCKError):
    """Raised when an older version attempts to overwrite a newer fact observation."""


class CircularDependencyError(CCKError):
    """Raised when a cycle is detected in the dependency graph."""


class ContractValidationError(CCKError):
    """Raised when a payload does not conform to its registered contract schema."""


class ContractVersionError(CCKError):
    """Raised when an unsupported or obsolete contract version is used."""


class ReplayDivergenceError(CCKError):
    """Raised when replaying an event sequence yields a diverging verdict or state."""


class ActionGateError(CCKError):
    """Raised when an action fails gate validation rules."""


class ApprovalError(CCKError):
    """Raised when a human approval workflow error occurs."""


class ReservationError(CCKError):
    """Raised when resource reservation fails."""


class ReservationConflictError(ReservationError):
    """Raised when resource reservation encounters a concurrency conflict."""


class RecoveryLimitExceededError(CCKError):
    """Raised when recovery attempts or limits are exceeded."""


class ConnectorError(CCKError):
    """Base exception for all connector and adapter operations."""


class NormalizedConnectorError(ConnectorError):
    """Connector failure mapped into a normalized category."""

    def __init__(
        self,
        message: str,
        category: str,
        connector_id: str = "unknown",
        retryable: bool = False,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.category = category
        self.connector_id = connector_id
        self.retryable = retryable


class UnsupportedCapabilityError(ConnectorError):
    """Raised when an operation requests a capability not supported by the connector."""


class TargetValidationError(ConnectorError):
    """Raised when target entity state does not match precondition assumptions."""


class IdempotencyConflictError(ConnectorError):
    """Raised when an idempotency key conflict occurs."""


class UnknownExecutionOutcomeError(ConnectorError):
    """Raised when communication fails after dispatch and execution status is unknown."""


class NonReversibleActionError(ConnectorError):
    """Raised when compensation is attempted on an action that cannot be safely reversed."""
