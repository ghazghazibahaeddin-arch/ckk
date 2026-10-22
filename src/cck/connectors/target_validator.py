"""Target Validator for CCK Execution Adapters.

Validates that the target external entity, version, and prerequisite conditions
still match the gate decision immediately prior to physical action execution.
"""

from typing import Any

from cck.connectors.interface import Connector
from cck.core.exceptions import TargetValidationError
from cck.core.types import ConnectorCapability


class TargetValidator:
    """Validates pre-flight target entity conditions against live connector state."""

    async def validate_preconditions(
        self,
        connector: Connector,
        target: str,
        expected_version: int | None = None,
        expected_values: dict[str, Any] | None = None,
    ) -> bool:
        """Verify target state before dispatch.

        If connector supports READ, reads current state and asserts:
        1. Target entity exists in external system.
        2. Live version matches expected_version (detects concurrent mutations).
        3. Field values match expected_values.

        Raises:
            TargetValidationError: If live target state differs from decision prerequisites.
        """
        if not connector.supports(ConnectorCapability.READ):
            # Connector doesn't support reading live state for pre-validation
            return True

        read_res = await connector.read(target)

        # 1. Existence check
        if not read_res.exists:
            raise TargetValidationError(
                f"Target validation failed: Resource '{target}' does not exist on connector '{connector.connector_id}'."
            )

        # 2. Version consistency check (precondition / CAS check)
        if (
            expected_version is not None
            and read_res.version is not None
            and read_res.version != expected_version
        ):
            raise TargetValidationError(
                f"Target validation failed on '{target}': "
                f"Expected version {expected_version}, but live version is {read_res.version}. "
                f"Concurrent modification detected!"
            )

        # 3. Field values check
        if expected_values:
            for field, exp_val in expected_values.items():
                live_val = read_res.data.get(field)
                if live_val != exp_val:
                    raise TargetValidationError(
                        f"Target validation failed on '{target}.{field}': "
                        f"Expected value '{exp_val}', but live value is '{live_val}'."
                    )

        return True
