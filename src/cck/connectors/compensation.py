"""Compensation Adapter for CCK Connectors.

Defines rollback interfaces for reversible actions, tracks non-reversible actions,
and strictly enforces that unsafe automatic compensations are NEVER executed.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict

from cck.connectors.interface import CompensationResult, Connector
from cck.core.exceptions import NonReversibleActionError, UnsupportedCapabilityError
from cck.core.types import ConnectorCapability


class ActionReversibilitySpec(BaseModel):
    """Specification of whether an action type can be safely compensated."""

    capability: str
    is_reversible: bool
    description: str
    default_compensation_capability: str | None = None

    model_config = ConfigDict(extra="forbid")


# Canonical catalog of reversibility
STANDARD_REVERSIBILITY_CATALOG: dict[str, ActionReversibilitySpec] = {
    # Reversible actions
    "database.update": ActionReversibilitySpec(
        capability="database.update",
        is_reversible=True,
        description="Reversible via compensating inverse update",
        default_compensation_capability="database.update",
    ),
    "inventory.reserve": ActionReversibilitySpec(
        capability="inventory.reserve",
        is_reversible=True,
        description="Reversible by releasing reservation hold",
        default_compensation_capability="inventory.release",
    ),
    "order.cancel": ActionReversibilitySpec(
        capability="order.cancel",
        is_reversible=True,
        description="Reversible by reopening or un-canceling order",
        default_compensation_capability="order.reopen",
    ),
    # Irreversible actions (CANNOT be undone safely)
    "email.send": ActionReversibilitySpec(
        capability="email.send",
        is_reversible=False,
        description="Non-reversible: External recipient has already received message",
    ),
    "webhook.dispatch": ActionReversibilitySpec(
        capability="webhook.dispatch",
        is_reversible=False,
        description="Non-reversible: External endpoint consumed webhook event",
    ),
    "wire_transfer.execute": ActionReversibilitySpec(
        capability="wire_transfer.execute",
        is_reversible=False,
        description="Non-reversible: Funds have cleared interbank settlement",
    ),
    "hardware.poweroff": ActionReversibilitySpec(
        capability="hardware.poweroff",
        is_reversible=False,
        description="Non-reversible: Physical power disruption",
    ),
}


class CompensationAdapter:
    """Orchestrates compensation for reversible actions."""

    def __init__(self, catalog: dict[str, ActionReversibilitySpec] | None = None) -> None:
        self._catalog = catalog or dict(STANDARD_REVERSIBILITY_CATALOG)
        # action_id -> compensation_payload
        self._registered_compensations: dict[str, dict[str, Any]] = {}

    def is_reversible(self, capability: str) -> bool:
        """Check if an action capability is declared as reversible."""
        spec = self._catalog.get(capability)
        if spec is None:
            # Default to False for safety if unknown!
            return False
        return spec.is_reversible

    def register_compensation(
        self,
        action_id: str,
        capability: str,
        compensation_payload: dict[str, Any],
    ) -> None:
        """Register compensating data for a reversible action."""
        if not self.is_reversible(capability):
            raise NonReversibleActionError(
                f"Action '{action_id}' with capability '{capability}' is non-reversible! "
                f"Cannot register compensation for an irreversible operation."
            )
        self._registered_compensations[action_id] = compensation_payload

    async def execute_compensation(
        self,
        action_id: str,
        capability: str,
        connector: Connector,
        target: str,
    ) -> CompensationResult:
        """Execute a compensating action through the connector.

        Guarantees:
        1. Checks capability reversibility; raises NonReversibleActionError if irreversible.
        2. Checks connector support for COMPENSATION; raises UnsupportedCapabilityError if unsupported.
        3. Never executes automatically without explicit orchestration call.
        """
        if not self.is_reversible(capability):
            raise NonReversibleActionError(
                f"Cannot compensate action '{action_id}': Capability '{capability}' is permanently non-reversible."
            )

        if not connector.supports(ConnectorCapability.COMPENSATION):
            raise UnsupportedCapabilityError(
                f"Connector '{connector.connector_id}' does not support COMPENSATION capability."
            )

        payload = self._registered_compensations.get(action_id, {})
        return await connector.compensate(
            target=target,
            original_action_id=action_id,
            compensation_payload=payload,
        )
