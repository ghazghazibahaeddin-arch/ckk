"""CCK Connectors and Execution Adapters (Layer 2).

Provides unified connectors, read and write adapters with Action Gate enforcement,
target preconditions validator, idempotency management, compensation adapters,
and health monitoring.
"""

from cck.connectors.adapters.read_adapter import ReadAdapter
from cck.connectors.adapters.write_adapter import WriteAdapter
from cck.connectors.capabilities import CapabilityRegistry
from cck.connectors.compensation import ActionReversibilitySpec, CompensationAdapter
from cck.connectors.errors import normalize_connector_error
from cck.connectors.health import ConnectorHealthMonitor
from cck.connectors.idempotency import IdempotencyAdapter, IdempotencyRecord
from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.connectors.implementations.stubs import (
    SalesforceConnectorStub,
    StripeConnectorStub,
    ZendeskConnectorStub,
)
from cck.connectors.interface import (
    CompensationResult,
    Connector,
    ConnectorHealthStatus,
    ReadResult,
    WriteResult,
)
from cck.connectors.security import scrub_secrets
from cck.connectors.target_validator import TargetValidator
from cck.core.types import ConnectorCapability, IdempotencyStatus, NormalizedErrorCategory

__all__ = [
    "ActionReversibilitySpec",
    "CapabilityRegistry",
    "CompensationAdapter",
    "CompensationResult",
    "Connector",
    "ConnectorCapability",
    "ConnectorHealthMonitor",
    "ConnectorHealthStatus",
    "IdempotencyAdapter",
    "IdempotencyRecord",
    "IdempotencyStatus",
    "InMemorySandboxConnector",
    "NormalizedErrorCategory",
    "ReadAdapter",
    "ReadResult",
    "SalesforceConnectorStub",
    "StripeConnectorStub",
    "TargetValidator",
    "WriteAdapter",
    "WriteResult",
    "ZendeskConnectorStub",
    "normalize_connector_error",
    "scrub_secrets",
]
