"""CCK Official Python Client."""

import os
import time
from typing import Any, Dict, Optional
import httpx

from cck_sdk.exceptions import CCKActionBlockedError, CCKConnectionError, CCKError
from cck_sdk.models import (
    ActionSeverity,
    AgentAction,
    DecisionReceipt,
    ExecutionVerdict,
    PolicyMatch,
    VerdictDecision,
)


class CCKClient:
    """Client for interacting with the CCK Action Gate and Reliability Control Plane."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self.base_url = (base_url or os.getenv("CCK_BASE_URL", "http://localhost:3000")).rstrip("/")
        self.api_key = api_key or os.getenv("CCK_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["x-api-key"] = self.api_key
        return headers

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.request(method, url, headers=headers, **kwargs)
                    if resp.status_code >= 400:
                        detail = resp.text
                        try:
                            parsed = resp.json()
                            detail = parsed.get("detail", parsed.get("error", resp.text))
                        except Exception:
                            pass
                        raise CCKError(f"CCK API Error [HTTP {resp.status_code}]: {detail}")
                    return resp.json()
            except CCKError:
                raise
            except Exception as ex:
                last_error = ex
                if attempt == self.max_retries:
                    break
                time.sleep(min(1.0, 0.1 * (2 ** attempt)))

        raise CCKConnectionError(f"Failed to connect to CCK at {url}: {last_error}")

    def health(self) -> Dict[str, Any]:
        """Check status and health of the CCK Control Plane."""
        return self._request("GET", "/health")

    def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        """Send authenticated heartbeat for agent, transitioning it to CONNECTED."""
        return self._request("POST", f"/api/v1/agents/{agent_id}/heartbeat")

    def evaluate_action(self, action: AgentAction) -> ExecutionVerdict:
        """Evaluate an action against CCK Action Gate rules."""
        payload = {
            "session_id": action.session_id,
            "agent": {
                "agent_id": action.agent.agent_id,
                "name": action.agent.name,
                "trust_tier": action.agent.trust_tier,
                "tenant_id": action.agent.tenant_id,
            },
            "capability": action.capability,
            "target": action.target,
            "parameters": action.parameters,
            "severity": action.severity.value if isinstance(action.severity, ActionSeverity) else action.severity,
        }
        data = self._request("POST", "/api/v1/actions/evaluate", json=payload)
        matched = [
            PolicyMatch(
                rule_id=m.get("rule_id", ""),
                rule_name=m.get("rule_name", ""),
                effect=m.get("effect", ""),
                reason=m.get("reason", ""),
                risk_score=float(m.get("risk_score", 0.0)),
            )
            for m in data.get("matched_policies", [])
        ]
        return ExecutionVerdict(
            verdict_id=data.get("verdict_id", ""),
            action_id=data.get("action_id", ""),
            decision=VerdictDecision(data.get("decision", "BLOCK")),
            risk_level=data.get("risk_level", "UNKNOWN"),
            risk_score=float(data.get("risk_score", 1.0)),
            reason=data.get("reason", ""),
            matched_policies=matched,
            remediation_suggestions=data.get("remediation_suggestions", []),
            evaluated_at=data.get("evaluated_at"),
            shadow_mode=bool(data.get("shadow_mode", False)),
        )

    def record_evidence(
        self,
        entity_id: str,
        field_name: str,
        value: Any,
        source: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record external evidence updating an entity fact."""
        return self._request(
            "POST",
            "/api/v1/webhooks/ingest",
            json={
                "entity_id": entity_id,
                "field_name": field_name,
                "value": value,
                "source": source or "python-sdk",
                "payload": payload,
            },
        )

    def get_receipt(self, receipt_id: str) -> DecisionReceipt:
        """Retrieve durable decision receipt."""
        data = self._request("GET", f"/api/v1/receipts/{receipt_id}")
        return DecisionReceipt(
            receipt_id=data.get("receipt_id", ""),
            action_id=data.get("action_id", ""),
            decision=data.get("decision", ""),
            agent_id=data.get("agent_id", ""),
            tenant_id=data.get("tenant_id", ""),
            project_id=data.get("project_id", ""),
            capability=data.get("capability", ""),
            target_resource=data.get("target_resource", ""),
            risk_score=float(data.get("risk_score", 0.0)),
            timestamp=data.get("timestamp", ""),
            rule_name=data.get("rule_name", ""),
            receipt_hash=data.get("receipt_hash", ""),
            verified_chain_status=bool(data.get("verified_chain_status", False)),
        )
