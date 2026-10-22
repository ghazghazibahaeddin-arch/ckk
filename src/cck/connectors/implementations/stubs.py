"""Future Integration Connector Stubs for CCK.

Defines typed interfaces and capability declarations for planned 3rd-party connectors.

DISCLOSURE & INTEGRATION NOTICE:
-------------------------------
These stubs declare the required capabilities and API contracts for Stripe, Zendesk,
and Salesforce, but are explicitly marked as UNCONFIGURED STUBS.
No claim is made that integration with these services is complete without live
API credentials, authentication flows, and verified network tests.
"""

from typing import Any

from cck.connectors.interface import (
    CompensationResult,
    Connector,
    ConnectorHealthStatus,
    ReadResult,
    WriteResult,
)
from cck.core.exceptions import NormalizedConnectorError
from cck.core.types import ConnectorCapability, NormalizedErrorCategory


class StripeConnectorStub(Connector):
    """Stub interface for planned Stripe Payment Gateway integration."""

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(connector_id="stripe-api", name="Stripe Payments Connector (Stub)")
        self.api_key = api_key

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        return {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.IDEMPOTENCY,
            ConnectorCapability.COMPENSATION,  # Refund
            ConnectorCapability.HEALTH_CHECK,
        }

    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        if not self.api_key:
            raise NormalizedConnectorError(
                message="Stripe connector requires configured 'STRIPE_API_KEY'. Integration unconfigured.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Stripe HTTP calls require active test credentials.")

    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        if not self.api_key:
            raise NormalizedConnectorError(
                message="Stripe connector requires configured 'STRIPE_API_KEY'. Integration unconfigured.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Stripe write calls require active test credentials.")

    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        raise NotImplementedError("Live Stripe refunds require active test credentials.")

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            connector_id=self.connector_id,
            healthy=bool(self.api_key),
            latency_ms=0.0,
            error_rate=0.0 if self.api_key else 1.0,
            message="Stub initialized (Unconfigured credentials)" if not self.api_key else "Ready",
        )


class ZendeskConnectorStub(Connector):
    """Stub interface for planned Zendesk Support Ticketing integration."""

    def __init__(self, subdomain: str | None = None, token: str | None = None) -> None:
        super().__init__(connector_id="zendesk-api", name="Zendesk Support Connector (Stub)")
        self.subdomain = subdomain
        self.token = token

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        return {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.VERSION_CHECK,
            ConnectorCapability.HEALTH_CHECK,
        }

    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        if not self.token or not self.subdomain:
            raise NormalizedConnectorError(
                message="Zendesk connector requires 'subdomain' and 'token'. Integration unconfigured.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Zendesk calls require active credentials.")

    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        if not self.token:
            raise NormalizedConnectorError(
                message="Zendesk connector unconfigured.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Zendesk calls require active credentials.")

    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        raise NotImplementedError("Zendesk ticket compensation requires active credentials.")

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            connector_id=self.connector_id,
            healthy=bool(self.token),
            latency_ms=0.0,
            error_rate=0.0 if self.token else 1.0,
            message="Stub initialized (Unconfigured credentials)",
        )


class SalesforceConnectorStub(Connector):
    """Stub interface for planned Salesforce CRM integration."""

    def __init__(self, instance_url: str | None = None, access_token: str | None = None) -> None:
        super().__init__(connector_id="salesforce-api", name="Salesforce CRM Connector (Stub)")
        self.instance_url = instance_url
        self.access_token = access_token

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        return {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.CONDITIONAL_WRITE,
            ConnectorCapability.VERSION_CHECK,
            ConnectorCapability.HEALTH_CHECK,
        }

    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        if not self.access_token:
            raise NormalizedConnectorError(
                message="Salesforce connector requires OAuth token. Integration unconfigured.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Salesforce calls require active credentials.")

    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        if not self.access_token:
            raise NormalizedConnectorError(
                message="Salesforce connector requires OAuth token.",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        raise NotImplementedError("Live Salesforce calls require active credentials.")

    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        raise NotImplementedError("Salesforce rollback requires active credentials.")

    async def check_health(self) -> ConnectorHealthStatus:
        return ConnectorHealthStatus(
            connector_id=self.connector_id,
            healthy=bool(self.access_token),
            latency_ms=0.0,
            error_rate=0.0 if self.access_token else 1.0,
            message="Stub initialized (Unconfigured credentials)",
        )
