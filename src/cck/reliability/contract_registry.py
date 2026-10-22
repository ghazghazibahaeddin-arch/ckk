"""Contract Registry for CCK.

Registers, versions, and validates schemas for agent actions and decision payloads.
Rejects invalid contracts or deprecated/unsupported versions with descriptive errors.
"""

from typing import Any

from cck.contracts.contract_def import ContractDefinition
from cck.core.exceptions import ContractValidationError, ContractVersionError


class ContractRegistry:
    """Registry maintaining active and historical contract definitions."""

    def __init__(self) -> None:
        # Key: (contract_id, version) -> ContractDefinition
        self._contracts: dict[tuple[str, str], ContractDefinition] = {}

    def register_contract(self, contract: ContractDefinition) -> None:
        """Register a contract definition."""
        self._contracts[(contract.contract_id, contract.version)] = contract

    def get_contract(self, contract_id: str, version: str) -> ContractDefinition:
        """Fetch a specific contract by ID and semantic version."""
        key = (contract_id, version)
        if key not in self._contracts:
            available_versions = [
                v for (c_id, v) in self._contracts if c_id == contract_id
            ]
            if available_versions:
                raise ContractVersionError(
                    f"Contract '{contract_id}' version '{version}' is not supported. "
                    f"Available versions: {available_versions}."
                )
            raise ContractValidationError(
                f"Contract '{contract_id}' is not registered in the Contract Registry."
            )

        contract = self._contracts[key]
        if not contract.is_active or contract.deprecated:
            raise ContractVersionError(
                f"Contract '{contract_id}' version '{version}' is deprecated or inactive and cannot be used."
            )

        return contract

    def validate_payload(
        self,
        contract_id: str,
        version: str,
        payload: dict[str, Any],
        is_input: bool = True,
    ) -> bool:
        """Validate a payload against the input or output schema of the specified contract.

        Rules:
        - Required keys must be present.
        - Disallowed extra keys are flagged.
        - Types are strictly checked against schema specifications.
        """
        contract = self.get_contract(contract_id, version)
        schema = contract.input_schema if is_input else contract.output_schema

        if not schema:
            return True

        # Check required fields
        required_fields = schema.get("required", [])
        for field in required_fields:
            if field not in payload:
                raise ContractValidationError(
                    f"Contract '{contract_id}:{version}' validation failed: "
                    f"Missing mandatory field '{field}' in {'input' if is_input else 'output'}."
                )

        # Check field types if 'properties' are defined
        properties = schema.get("properties", {})
        for field_name, spec in properties.items():
            if field_name in payload:
                val = payload[field_name]
                expected_type = spec.get("type")
                if expected_type == "string" and not isinstance(val, str):
                    raise ContractValidationError(
                        f"Contract '{contract_id}:{version}' validation failed: "
                        f"Field '{field_name}' must be of type string, got {type(val).__name__}."
                    )
                elif expected_type == "integer" and not (isinstance(val, int) and not isinstance(val, bool)):
                    raise ContractValidationError(
                        f"Contract '{contract_id}:{version}' validation failed: "
                        f"Field '{field_name}' must be of type integer, got {type(val).__name__}."
                    )
                elif expected_type == "number" and not isinstance(val, (int, float)):
                    raise ContractValidationError(
                        f"Contract '{contract_id}:{version}' validation failed: "
                        f"Field '{field_name}' must be of type number, got {type(val).__name__}."
                    )
                elif expected_type == "boolean" and not isinstance(val, bool):
                    raise ContractValidationError(
                        f"Contract '{contract_id}:{version}' validation failed: "
                        f"Field '{field_name}' must be of type boolean, got {type(val).__name__}."
                    )

        return True
