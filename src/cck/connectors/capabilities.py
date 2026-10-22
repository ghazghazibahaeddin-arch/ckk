"""Capability Registry and definitions for CCK Connectors."""

from cck.core.exceptions import UnsupportedCapabilityError
from cck.core.types import ConnectorCapability


class CapabilityRegistry:
    """Registry maintaining declared and verified capabilities for connectors.

    Enforces that connectors explicitly declare supported operations
    (e.g. CONDITIONAL_WRITE, COMPENSATION, IDEMPOTENCY) and rejects unsupported calls.
    """

    def __init__(self) -> None:
        # connector_id -> set of ConnectorCapability
        self._capabilities: dict[str, set[ConnectorCapability]] = {}

    def register_connector_capabilities(
        self,
        connector_id: str,
        capabilities: set[ConnectorCapability],
    ) -> None:
        """Register the capability profile for a connector."""
        self._capabilities[connector_id] = set(capabilities)

    def get_capabilities(self, connector_id: str) -> set[ConnectorCapability]:
        """Retrieve the set of capabilities supported by a connector."""
        return set(self._capabilities.get(connector_id, set()))

    def supports(self, connector_id: str, capability: ConnectorCapability) -> bool:
        """Check if a connector supports a given capability."""
        return capability in self._capabilities.get(connector_id, set())

    def assert_supports(self, connector_id: str, capability: ConnectorCapability) -> None:
        """Assert that a connector supports a capability or raise UnsupportedCapabilityError."""
        if not self.supports(connector_id, capability):
            supported = [c.value for c in self.get_capabilities(connector_id)]
            raise UnsupportedCapabilityError(
                f"Connector '{connector_id}' does not support capability '{capability.value}'. "
                f"Declared supported capabilities: {supported}."
            )
