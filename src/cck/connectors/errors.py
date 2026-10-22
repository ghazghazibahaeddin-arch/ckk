"""Error Normalization for CCK Connectors and Adapters."""

import asyncio
from typing import Any

from cck.core.exceptions import NormalizedConnectorError
from cck.core.types import NormalizedErrorCategory


def normalize_connector_error(
    exc: Exception,
    connector_id: str = "unknown",
    custom_details: dict[str, Any] | None = None,
) -> NormalizedConnectorError:
    """Normalize arbitrary external or driver exceptions into standard CCK error categories."""
    if isinstance(exc, NormalizedConnectorError):
        return exc

    err_str = str(exc).lower()
    details = custom_details or {}

    # 1. Timeout
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)) or "timeout" in err_str or "timed out" in err_str:
        return NormalizedConnectorError(
            message=f"Timeout communicating with connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.TIMEOUT.value,
            connector_id=connector_id,
            retryable=False,  # Security rule: Never auto-retry unsafe actions with unknown outcome!
            details=details,
        )

    # 2. Authentication
    if "unauthorized" in err_str or "401" in err_str or "invalid_token" in err_str or "authentication" in err_str:
        return NormalizedConnectorError(
            message=f"Authentication failure on connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.AUTHENTICATION.value,
            connector_id=connector_id,
            retryable=False,
            details=details,
        )

    # 3. Permission / Forbidden
    if "forbidden" in err_str or "403" in err_str or "permission" in err_str or "access denied" in err_str:
        return NormalizedConnectorError(
            message=f"Permission denied for connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.PERMISSION_DENIED.value,
            connector_id=connector_id,
            retryable=False,
            details=details,
        )

    # 4. Rate Limiting
    if "rate limit" in err_str or "429" in err_str or "too many requests" in err_str:
        return NormalizedConnectorError(
            message=f"Rate limit exceeded on connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.RATE_LIMITING.value,
            connector_id=connector_id,
            retryable=True,
            details=details,
        )

    # 5. Connectivity / Network
    if (
        isinstance(exc, (ConnectionError, ConnectionResetError, ConnectionRefusedError))
        or "connection reset" in err_str
        or "disconnect" in err_str
        or "network unreachable" in err_str
    ):
        return NormalizedConnectorError(
            message=f"Network connectivity error on connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.CONNECTIVITY.value,
            connector_id=connector_id,
            retryable=True,
            details=details,
        )

    # 6. Version Conflict / Precondition Failed
    if "conflict" in err_str or "409" in err_str or "version" in err_str or "etag" in err_str:
        return NormalizedConnectorError(
            message=f"Version conflict or state mismatch on connector '{connector_id}': {exc}",
            category=NormalizedErrorCategory.VERSION_CONFLICT.value,
            connector_id=connector_id,
            retryable=False,
            details=details,
        )

    # Default fallback: Execution Failure
    return NormalizedConnectorError(
        message=f"Execution error on connector '{connector_id}': {exc}",
        category=NormalizedErrorCategory.EXECUTION_FAILURE.value,
        connector_id=connector_id,
        retryable=False,
        details=details,
    )
