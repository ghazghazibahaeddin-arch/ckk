"""Unified Connector Interface for CCK Connectors and Adapters."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.core.types import ConnectorCapability


class ReadResult(BaseModel):
    """Normalized response of a read operation on an external connector."""

    target: str = Field(..., description="Target resource or entity path")
    data: dict[str, Any] = Field(default_factory=dict, description="Normalized field dictionary")
    version: int | None = Field(default=None, description="Current entity/resource version if supported")
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the observation",
    )
    is_trusted: bool = Field(default=True, description="Whether the data source is authenticated and verified")
    exists: bool = Field(default=True, description="Whether the entity was found in the external system")
    raw_response: Any = Field(default=None, description="Exact raw reading for Evidence creation")

    model_config = ConfigDict(extra="forbid")


class WriteResult(BaseModel):
    """Normalized result of an executed write action on an external connector."""

    execution_id: str = Field(
        default_factory=lambda: f"exec_{uuid4().hex}",
        description="Unique execution dispatch ID",
    )
    target: str = Field(..., description="Target resource modified")
    success: bool = Field(default=True, description="Whether the external write was accepted")
    new_version: int | None = Field(default=None, description="Updated version after write if supported")
    response_data: dict[str, Any] = Field(default_factory=dict, description="Response payload from connector")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC execution timestamp",
    )

    model_config = ConfigDict(extra="forbid")


class CompensationResult(BaseModel):
    """Result of attempting a compensation (rollback) action."""

    compensation_action_id: str = Field(..., description="ID of the compensation action")
    target: str = Field(..., description="Target resource compensated")
    success: bool = Field(..., description="Whether compensation succeeded")
    details: dict[str, Any] = Field(default_factory=dict, description="Output payload or error message")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC compensation timestamp",
    )

    model_config = ConfigDict(extra="forbid")


class ConnectorHealthStatus(BaseModel):
    """Health, latency, and availability metrics for a connector."""

    connector_id: str = Field(..., description="Connector identifier")
    healthy: bool = Field(..., description="Liveness and responsiveness status")
    latency_ms: float = Field(..., ge=0.0, description="Round-trip latency in milliseconds")
    error_rate: float = Field(..., ge=0.0, le=1.0, description="Error rate over recent window (0.0 to 1.0)")
    last_checked: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the health check",
    )
    message: str = Field(default="Healthy", description="Status description or error diagnosis")

    model_config = ConfigDict(extra="forbid")


class Connector(ABC):
    """Unified Abstract Base Class for external system connectors.

    Every connector must declare its supported capabilities, provide normalized
    reads and writes, support health checks, and handle compensations where possible.
    """

    def __init__(self, connector_id: str, name: str) -> None:
        self.connector_id = connector_id
        self.name = name

    @property
    @abstractmethod
    def supported_capabilities(self) -> set[ConnectorCapability]:
        """Set of capabilities explicitly supported by this connector."""

    def supports(self, capability: ConnectorCapability) -> bool:
        """Check if this connector supports a given capability."""
        return capability in self.supported_capabilities

    @abstractmethod
    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        """Read data from the external target."""

    @abstractmethod
    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        """Execute a mutating action against the external target.

        If expected_version is provided and the connector supports CONDITIONAL_WRITE,
        it performs a conditional check. If the connector does NOT support conditional
        writes, it must declare its limitation.
        """

    @abstractmethod
    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        """Compensate (rollback) a previously executed action if reversible."""

    @abstractmethod
    async def check_health(self) -> ConnectorHealthStatus:
        """Perform a liveness and responsiveness probe on the connector."""
