"""Python SDK for CCK Platform (Layer 6).

Provides a fluent client for initiating session context, recording evidence and facts,
evaluating policy decisions, and executing actions through governance pipelines.
"""

from typing import Any
from uuid import uuid4

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import ActionSeverity
from cck.runtime.engine import CCKControlPlane


class CCKClient:
    """Synchronous/Asynchronous client SDK for CCK integration."""

    def __init__(self, control_plane: CCKControlPlane, default_agent: AgentIdentity | None = None) -> None:
        self.control_plane = control_plane
        self.default_agent = default_agent or AgentIdentity(
            agent_id="agt-sdk-default",
            name="SDKDefaultAgent",
            trust_tier="standard",
        )
        self.session_id: str = f"sess_sdk_{uuid4().hex[:8]}"

    async def evaluate(
        self,
        capability: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        severity: ActionSeverity = ActionSeverity.STANDARD,
        agent: AgentIdentity | None = None,
    ) -> ExecutionVerdict:
        """Evaluate an action proposal against CCK governance and policy engines."""
        action = AgentAction(
            agent=agent or self.default_agent,
            session_id=self.session_id,
            capability=capability,
            target=target,
            parameters=parameters or {},
            severity=severity,
        )
        return await self.control_plane.evaluate_action(action)
