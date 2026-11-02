"""LangGraph Integration Hook for CCK Action Gate."""

from typing import Any, Callable, Dict
from cck_sdk.client import CCKClient
from cck_sdk.models import ActionSeverity, AgentAction, AgentIdentity, VerdictDecision


class CCKLangGraphGuard:
    """Pre-tool execution node hook for LangGraph agent workflows."""

    def __init__(self, client: CCKClient, agent_id: str, agent_name: str = "LangGraphAgent") -> None:
        self.client = client
        self.agent_id = agent_id
        self.agent_name = agent_name

    def check_tool_call(self, tool_name: str, tool_args: Dict[str, Any], session_id: str = "langgraph-session") -> Dict[str, Any]:
        """Verify tool call before execution in LangGraph graph."""
        action = AgentAction(
            agent=AgentIdentity(agent_id=self.agent_id, name=self.agent_name),
            session_id=session_id,
            capability=tool_name,
            target=str(tool_args.get("resource_id", tool_args.get("order_id", tool_args.get("target", "*")))),
            parameters=tool_args,
            severity=ActionSeverity.MUTATION,
        )

        verdict = self.client.evaluate_action(action)
        if verdict.decision != VerdictDecision.ALLOW:
            return {
                "allowed": False,
                "error": f"CCK Action Gate BLOCKED tool call '{tool_name}': {verdict.reason}",
                "verdict_id": verdict.verdict_id,
                "risk_score": verdict.risk_score,
            }
        return {"allowed": True, "verdict_id": verdict.verdict_id}
