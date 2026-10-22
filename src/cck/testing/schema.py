"""Scenario Schema definition for CCK Testing & Evaluation Lab (Layer 5).

Defines the unified contract for test scenarios including initial entity state,
reads, world mutations, injected faults, execution attempts, and expected verdicts.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScenarioStep(BaseModel):
    """An individual step or mutation within a test scenario."""

    action: str = Field(..., description="Step action type: 'seed', 'read', 'mutate_world', 'inject_fault', 'execute'")
    target: str = Field(..., description="Target resource or entity")
    payload: dict[str, Any] = Field(default_factory=dict)
    expected_verdict: str | None = Field(default=None, description="Expected verdict if execute step")
    expected_error: str | None = Field(default=None, description="Expected exception or error category")

    model_config = ConfigDict(extra="forbid")


class ScenarioDefinition(BaseModel):
    """Unified schema definition for a repeatable CCK test scenario."""

    scenario_id: str = Field(..., description="Unique scenario identifier")
    title: str = Field(..., description="Human-readable scenario title")
    category: str = Field(..., description="Error category, e.g. 'stale_fact', 'version_conflict', 'fault_injection'")
    steps: list[ScenarioStep] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
