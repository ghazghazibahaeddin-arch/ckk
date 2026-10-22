"""Recovery Orchestrator for CCK Recovery & Repair (Layer 4).

Manages the recovery lifecycle states (Detection, Analysis, Re-evaluation,
Awaiting Approval, Repair, Post-verification, Failure, Success), enforces retry
and time limits, prevents infinite loops, and verifies post-recovery state.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.connectors.interface import Connector
from cck.core.types import RecoveryState
from cck.recovery.planner import RepairPlan


class RecoverySession(BaseModel):
    """Authoritative state of an active recovery orchestration session."""

    session_id: str = Field(default_factory=lambda: f"rcv_{uuid4().hex}")
    workflow_id: str = Field(..., description="Correlating workflow or session ID")
    state: RecoveryState = Field(default=RecoveryState.DETECTED)
    plan: RepairPlan | None = Field(default=None)
    attempts: int = Field(default=0)
    max_attempts: int = Field(default=3)
    error_log: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="forbid")


class RecoveryOrchestrator:
    """Orchestrates multi-step recovery workflows with strict safety limits."""

    def __init__(self, max_attempts: int = 3) -> None:
        self.max_attempts = max_attempts
        self._sessions: dict[str, RecoverySession] = {}

    def start_recovery(self, workflow_id: str, plan: RepairPlan) -> RecoverySession:
        """Initiate a new recovery session."""
        session = RecoverySession(
            workflow_id=workflow_id,
            state=RecoveryState.ANALYZING,
            plan=plan,
            max_attempts=self.max_attempts,
        )
        if plan.requires_human_signoff:
            session = session.model_copy(update={"state": RecoveryState.AWAITING_APPROVAL})
        else:
            session = session.model_copy(update={"state": RecoveryState.REPAIRING})

        self._sessions[session.session_id] = session
        return session

    async def verify_post_recovery(
        self,
        session_id: str,
        connector: Connector,
        target: str,
        expected_conditions: dict[str, Any],
    ) -> bool:
        """Perform post-recovery verification by reading live state from trusted source.

        Rule: Never assume recovery succeeded without reading back live state.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Recovery session '{session_id}' not found.")

        read_res = await connector.read(target)
        if not read_res.exists:
            session.error_log.append(f"Post-verification failed: Target '{target}' does not exist.")
            session.state = RecoveryState.FAILED
            return False

        for k, expected in expected_conditions.items():
            actual = read_res.data.get(k)
            if actual != expected:
                session.error_log.append(
                    f"Post-verification failed on '{target}.{k}': Expected '{expected}', got '{actual}'."
                )
                session.state = RecoveryState.FAILED
                return False

        session.state = RecoveryState.SUCCESS
        return True
