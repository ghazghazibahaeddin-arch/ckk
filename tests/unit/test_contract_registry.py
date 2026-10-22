"""Unit tests for Contract Registry."""

import pytest

from cck.contracts.contract_def import ContractDefinition
from cck.core.exceptions import ContractValidationError, ContractVersionError
from cck.reliability.contract_registry import ContractRegistry


def test_contract_registration_and_validation() -> None:
    """Register contract schema and validate conforming payloads."""
    registry = ContractRegistry()

    contract = ContractDefinition(
        contract_id="order.refund.v1",
        name="Order Refund Request Contract",
        version="1.0.0",
        input_schema={
            "required": ["order_id", "amount", "reason"],
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "number"},
                "reason": {"type": "string"},
            },
        },
    )
    registry.register_contract(contract)

    # Valid payload passes
    valid_payload = {"order_id": "ord_99", "amount": 49.99, "reason": "Damaged goods"}
    assert registry.validate_payload("order.refund.v1", "1.0.0", valid_payload) is True

    # Missing mandatory field raises ContractValidationError
    invalid_payload = {"order_id": "ord_99", "amount": 49.99}  # missing 'reason'
    with pytest.raises(ContractValidationError) as exc_info:
        registry.validate_payload("order.refund.v1", "1.0.0", invalid_payload)
    assert "Missing mandatory field 'reason'" in str(exc_info.value)

    # Wrong data type raises ContractValidationError
    bad_type_payload = {"order_id": "ord_99", "amount": "not_a_number", "reason": "Return"}
    with pytest.raises(ContractValidationError) as exc_info:
        registry.validate_payload("order.refund.v1", "1.0.0", bad_type_payload)
    assert "Field 'amount' must be of type number" in str(exc_info.value)


def test_unsupported_or_deprecated_contract_version() -> None:
    """Requesting unsupported or deprecated contract versions raises ContractVersionError."""
    registry = ContractRegistry()

    contract = ContractDefinition(
        contract_id="billing.v1",
        name="Billing API Contract",
        version="1.0.0",
        deprecated=True,
    )
    registry.register_contract(contract)

    # Deprecated contract
    with pytest.raises(ContractVersionError) as exc_info:
        registry.get_contract("billing.v1", "1.0.0")
    assert "deprecated or inactive" in str(exc_info.value)

    # Unsupported version
    with pytest.raises(ContractVersionError) as exc_info:
        registry.get_contract("billing.v1", "9.9.9")
    assert "not supported" in str(exc_info.value)
