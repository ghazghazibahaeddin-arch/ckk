"""Exceptions for CCK Python SDK."""

from typing import Optional
from cck_sdk.models import ExecutionVerdict


class CCKError(Exception):
    """Base exception for CCK SDK."""
    pass


class CCKConnectionError(CCKError):
    """Raised when the CCK Control Plane is unreachable."""
    pass


class CCKActionBlockedError(CCKError):
    """Raised when the CCK Action Gate returns a BLOCK verdict."""

    def __init__(self, verdict: ExecutionVerdict, message: Optional[str] = None):
        msg = message or f"CCK Action Gate BLOCKED action: {verdict.reason} (Risk: {verdict.risk_score})"
        super().__init__(msg)
        self.verdict = verdict


class CCKApprovalRequiredError(CCKError):
    """Raised when an action requires human approval before execution."""

    def __init__(self, verdict: ExecutionVerdict):
        super().__init__(f"CCK requires human approval: {verdict.reason}")
        self.verdict = verdict
