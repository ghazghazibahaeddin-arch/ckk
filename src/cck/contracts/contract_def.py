"""Contract Registry definitions and schema contracts for CCK."""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SEMVER_REGEX = re.compile(r"^\d+\.\d+\.\d+$")


class ContractDefinition(BaseModel):
    """Specification of an authorized data contract with schema validation rules."""

    contract_id: str = Field(..., description="Unique contract identifier (e.g. 'order.action.v1')")
    name: str = Field(..., description="Human-readable contract name")
    version: str = Field(..., description="Semantic version string (e.g. '1.0.0')")
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema or field specifications for input validation",
    )
    output_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema or field specifications for output validation",
    )
    is_active: bool = Field(default=True, description="Whether this contract version is active")
    deprecated: bool = Field(default=False, description="Whether this contract version has been deprecated")

    model_config = ConfigDict(extra="forbid")

    @field_validator("version")
    @classmethod
    def validate_semver(cls, v: str) -> str:
        if not SEMVER_REGEX.match(v):
            raise ValueError(
                f"Invalid contract version '{v}'. Must conform to semantic versioning format (e.g. '1.0.0')."
            )
        return v
