"""Secure Webhook Dispatcher for CCK (Layer 6).

Dispatches signed webhook notifications for platform events with HMAC-SHA256 signatures,
idempotency headers, and delivery retry controls.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class WebhookPayload(BaseModel):
    """Payload structure for CCK webhook events."""

    event_id: str = Field(default_factory=lambda: f"evt_{uuid4().hex}")
    event_type: str = Field(..., description="Event type, e.g. 'decision.blocked', 'approval.requested'")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class WebhookDispatcher:
    """Signs and dispatches webhook payloads."""

    def __init__(self, secret_key: str = "cck-secret-webhook-key") -> None:
        self.secret_key = secret_key.encode("utf-8")

    def sign_payload(self, payload_bytes: bytes) -> str:
        """Compute HMAC-SHA256 signature for webhook payload verification."""
        sig = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
        return f"sha256={sig}"

    def prepare_dispatch(self, event_type: str, data: dict[str, Any]) -> tuple[dict[str, str], str]:
        """Prepare headers and JSON payload body for webhook delivery."""
        payload = WebhookPayload(event_type=event_type, data=data)
        body = payload.model_dump_json()
        body_bytes = body.encode("utf-8")
        signature = self.sign_payload(body_bytes)

        headers = {
            "Content-Type": "application/json",
            "X-CCK-Event-ID": payload.event_id,
            "X-CCK-Event-Type": event_type,
            "X-CCK-Signature": signature,
        }
        return headers, body
