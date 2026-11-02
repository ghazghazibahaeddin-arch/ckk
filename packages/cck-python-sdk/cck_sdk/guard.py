"""CCK Action Gate Fail-Closed Guard Decorator and Wrapper."""

import functools
from typing import Any, Callable, TypeVar
from cck_sdk.client import CCKClient
from cck_sdk.exceptions import CCKActionBlockedError, CCKApprovalRequiredError
from cck_sdk.models import AgentAction, VerdictDecision

T = TypeVar("T")


def with_cck_guard(client: CCKClient, action: AgentAction, tool_fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Execute a protected agent tool with authoritative fail-closed CCK verification.

    The tool is executed if and only if CCK Action Gate returns ALLOW.
    """
    verdict = client.evaluate_action(action)

    if verdict.decision == VerdictDecision.ALLOW:
        return tool_fn(*args, **kwargs)

    if verdict.decision == VerdictDecision.BLOCK:
        raise CCKActionBlockedError(verdict)

    if verdict.decision == VerdictDecision.REQUIRE_APPROVAL:
        raise CCKApprovalRequiredError(verdict)

    # Any non-ALLOW verdict (REVALIDATE, SIMULATE_ONLY) defaults to fail-closed block
    raise CCKActionBlockedError(verdict)


def cck_protect(client: CCKClient, action_factory: Callable[..., AgentAction]):
    """Decorator to protect any Python function with CCK Action Gate."""
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            action = action_factory(*args, **kwargs)
            return with_cck_guard(client, action, fn, *args, **kwargs)
        return wrapper
    return decorator
