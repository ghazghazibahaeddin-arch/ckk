"""Model Context Protocol (MCP) Server and Proxy for CCK (Layer 6).

Exposes CCK capabilities as MCP tools and provides an interceptor proxy
that evaluates tool calls through policy, records evidence, and blocks unsafe actions.
"""

from typing import Any

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.verdict import ExecutionVerdict
from cck.core.types import ActionSeverity
from cck.runtime.engine import CCKControlPlane


class MCPServerTools:
    """Defines CCK tools exposed over Model Context Protocol."""

    @staticmethod
    def list_tools() -> list[dict[str, Any]]:
        return [
            {
                "name": "cck_evaluate_action",
                "description": "Evaluate an agent action against CCK reliability rules and safety policies.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "capability": {"type": "string"},
                        "target": {"type": "string"},
                        "command": {"type": "string"},
                    },
                    "required": ["capability", "target"],
                },
            }
        ]


class MCPProxyInterceptor:
    """Interceptor proxying and gating MCP tool calls before external execution."""

    def __init__(self, control_plane: CCKControlPlane) -> None:
        self.control_plane = control_plane

    async def intercept_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str = "agt-mcp-client",
    ) -> ExecutionVerdict:
        """Intercept an MCP tool call, evaluate via CCK policy gate, and return verdict."""
        action = AgentAction(
            agent=AgentIdentity(agent_id=agent_id, name="MCPCaller", trust_tier="standard"),
            session_id=f"mcp_{tool_name}",
            capability=arguments.get("capability", tool_name),
            target=arguments.get("target", "mcp.resource"),
            parameters=arguments,
            severity=ActionSeverity.MUTATION,
        )
        return await self.control_plane.evaluate_action(action)
