"""Decision Re-evaluator for CCK Recovery & Repair (Layer 4).

Re-evaluates action verdicts using current facts, evidence, and active policies,
preserving historical audit provenance without silent overwrites.
"""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.contracts.action import AgentAction
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.verdict import ExecutionVerdict
from cck.reliability.action_gate import ActionGate


class ReevaluationRecord(BaseModel):
    """Record of a decision re-evaluation triggered by a state change."""

    reevaluation_id: str = Field(
        default_factory=lambda: f"reeval_{uuid4().hex}",
        description="Unique re-evaluation run ID",
    )
    action_id: str = Field(..., description="Target action ID evaluated")
    previous_verdict: ExecutionVerdict | None = Field(default=None, description="Original recorded verdict")
    new_verdict: ExecutionVerdict = Field(..., description="New re-evaluated verdict")
    trigger_reason: str = Field(..., description="Reason triggering re-evaluation (e.g. fact invalidated)")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC re-evaluation timestamp",
    )

    model_config = ConfigDict(extra="forbid")


class DecisionReevaluator:
    """Orchestrates re-evaluation of affected decisions through the ActionGate."""

    def __init__(self, action_gate: ActionGate) -> None:
        self.action_gate = action_gate

    async def reevaluate_action(
        self,
        action: AgentAction,
        spec: ActionDependencySpec | None = None,
        previous_verdict: ExecutionVerdict | None = None,
        trigger_reason: str = "State change detected",
    ) -> ReevaluationRecord:
        """Re-evaluate an action's execution verdict against current state."""
        new_verdict = await self.action_gate.evaluate_action(action=action, spec=spec)
        return ReevaluationRecord(
            action_id=action.action_id,
            previous_verdict=previous_verdict,
            new_verdict=new_verdict,
            trigger_reason=trigger_reason,
        )
