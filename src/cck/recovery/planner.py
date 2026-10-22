"""Repair and Compensation Planner for CCK Recovery & Repair (Layer 4).

Generates actionable repair plans, assesses action reversibility, and identifies
prerequisites, side effects, and human approval requirements.
"""

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.connectors.compensation import CompensationAdapter


class RepairPlanItem(BaseModel):
    """An individual corrective step in a repair plan."""

    step_id: str = Field(default_factory=lambda: f"step_{uuid4().hex}")
    action_type: str = Field(..., description="Action capability required, e.g. 'inventory.release'")
    target: str = Field(..., description="Target resource")
    parameters: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = Field(default=False)
    risk_level: str = Field(default="MEDIUM")

    model_config = ConfigDict(extra="forbid")


class RepairPlan(BaseModel):
    """Complete recovery and repair plan for an impacted workflow."""

    plan_id: str = Field(default_factory=lambda: f"plan_{uuid4().hex}")
    problem_description: str = Field(..., description="Identified failure or state inconsistency")
    impacted_nodes: list[str] = Field(default_factory=list)
    steps: list[RepairPlanItem] = Field(default_factory=list)
    requires_human_signoff: bool = Field(default=False)

    model_config = ConfigDict(extra="forbid")


class RepairPlanner:
    """Generates repair plans based on impact analysis and compensation specs."""

    def __init__(self, compensation_adapter: CompensationAdapter | None = None) -> None:
        self.compensation_adapter = compensation_adapter or CompensationAdapter()

    def create_repair_plan(
        self,
        problem_description: str,
        impacted_nodes: list[str],
        recommended_steps: list[dict[str, Any]],
    ) -> RepairPlan:
        """Construct a validated repair plan."""
        steps = []
        requires_signoff = False

        for st in recommended_steps:
            capability = st.get("capability", "database.update")
            is_rev = self.compensation_adapter.is_reversible(capability)
            # Irreversible or high-risk steps automatically demand human approval
            needs_approval = not is_rev or st.get("requires_approval", False)
            if needs_approval:
                requires_signoff = True

            steps.append(
                RepairPlanItem(
                    action_type=capability,
                    target=st["target"],
                    parameters=st.get("parameters", {}),
                    requires_approval=needs_approval,
                    risk_level="HIGH" if needs_approval else "MEDIUM",
                )
            )

        return RepairPlan(
            problem_description=problem_description,
            impacted_nodes=impacted_nodes,
            steps=steps,
            requires_human_signoff=requires_signoff,
        )
