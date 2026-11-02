"""OpenAI Function Calling Guard for CCK Action Gate."""

from typing import Any, Callable, Dict
from cck_sdk.client import CCKClient
from cck_sdk.exceptions import CCKActionBlockedError
from cck_sdk.models import ActionSeverity, AgentAction, AgentIdentity, VerdictDecision


class CCKOpenAIGuard:
    """Interceps OpenAI Assistant / Function tool calls before execution."""

    def __init__(self, client: CCKClient, agent_id: str, agent_name: str = "OpenAIAssistant") -> None:
        self.client = client
        self.agent_id = agent_id
        self.agent_name = agent_name

    def execute_tool_call(
        self,
        tool_call_id: str,
        function_name: str,
        arguments: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Any],
        session_id: str = "openai-session",
    ) -> Dict[str, Any]:
        """Evaluate function call against CCK before calling actual tool handler."""
        action = AgentAction(
            agent=AgentIdentity(agent_id=self.agent_id, name=self.agent_name),
            session_id=session_id,
            capability=function_name,
            target=str(arguments.get("account_id", arguments.get("order_id", arguments.get("target", "*")))),
            parameters=arguments,
            severity=ActionSeverity.MUTATION,
        )

        verdict = self.client.evaluate_action(action)
        if verdict.decision != VerdictDecision.ALLOW:
            raise CCKActionBlockedError(
                verdict,
                f"OpenAI function '{function_name}' call [{tool_call_id}] was BLOCKED by CCK: {verdict.reason}",
            )

        output = handler(arguments)
        return {
            "tool_call_id": tool_call_id,
            "output": output,
            "verdict_id": verdict.verdict_id,
        }
