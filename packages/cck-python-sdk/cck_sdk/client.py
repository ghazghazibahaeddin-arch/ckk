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
        tenant_id: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self.base_url = (base_url or os.getenv("CCK_BASE_URL", "http://localhost:3000")).rstrip("/")
        self.api_key = api_key or os.getenv("CCK_API_KEY")
        self.tenant_id = tenant_id or os.getenv("CCK_TENANT_ID")
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
        if self.tenant_id:
            headers["x-tenant-id"] = self.tenant_id
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
            "entity_id": action.entity_id,
            "tool_id": action.tool_id,
            "delegation_id": action.delegation_id,
            "trace_id": action.trace_id,
            "tenant_id": action.tenant_id or self.tenant_id,
            "idempotency_key": action.idempotency_key,
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
        idempotency_key: Optional[str] = None,
        trace_id: Optional[str] = None,
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
                "idempotency_key": idempotency_key,
                "trace_id": trace_id,
            },
        )

    def evaluate_freshness(self, entity_id: str, field_name: str) -> Dict[str, Any]:
        """Evaluate adaptive freshness state of a fact."""
        return self._request(
            "POST",
            "/api/v1/freshness/evaluate",
            json={"entity_id": entity_id, "field_name": field_name},
        )

    def evaluate_permissions(
        self,
        agent_id: str,
        tool_id: str,
        resource: str = "*",
        action: str = "*",
        requested_scopes: Optional[list] = None,
    ) -> Dict[str, Any]:
        """Evaluate least-privilege effective permissions via Permission Graph."""
        return self._request(
            "POST",
            "/api/v1/permissions/evaluate",
            json={
                "agent_id": agent_id,
                "tool_id": tool_id,
                "resource": resource,
                "action": action,
                "requested_scopes": requested_scopes or [],
            },
        )

    def mcp_gateway_call(
        self,
        agent_id: str,
        tool_name: str,
        target: str,
        arguments: Optional[Dict[str, Any]] = None,
        entity_id: Optional[str] = None,
        required_fact_field: Optional[str] = None,
        secret_ref: Optional[str] = None,
        secret_scope: Optional[str] = None,
        session_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a downstream MCP tool through CCK Runtime Enforcement Gateway."""
        return self._request(
            "POST",
            "/api/v1/mcp/gateway/invoke",
            json={
                "agent_id": agent_id,
                "tool_name": tool_name,
                "target": target,
                "arguments": arguments or {},
                "entity_id": entity_id,
                "required_fact_field": required_fact_field,
                "secret_ref": secret_ref,
                "secret_scope": secret_scope,
                "session_id": session_id,
                "trace_id": trace_id,
                "idempotency_key": idempotency_key,
            },
        )

    def evaluate_conflict(
        self,
        entity_id: str,
        field_name: str,
        manual_winner_observation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate multi-source conflict state for a fact."""
        return self._request(
            "POST",
            "/api/v1/conflicts/evaluate",
            json={
                "entity_id": entity_id,
                "field_name": field_name,
                "manual_winner_observation_id": manual_winner_observation_id,
            },
        )

    def run_smart_revalidation(
        self,
        mode: str = "DELTA",
        entity_id: Optional[str] = None,
        field_name: Optional[str] = None,
        source_id: Optional[str] = None,
        refresh_budget: int = 10,
    ) -> Dict[str, Any]:
        """Plan and run selective smart revalidation or delta refresh."""
        return self._request(
            "POST",
            "/api/v1/revalidation/plan-and-run",
            json={
                "mode": mode,
                "entity_id": entity_id,
                "field_name": field_name,
                "source_id": source_id,
                "refresh_budget": refresh_budget,
            },
        )

    def lease_ephemeral_secret(
        self,
        secret_ref: str,
        agent_id: str,
        tool_id: str,
        requested_scope: str,
        resource_scope: str = "*",
        purpose: str = "runtime_invocation",
        ttl_seconds: int = 60,
    ) -> Dict[str, Any]:
        """Request a short-lived scoped secret lease handle (never returns raw secret)."""
        return self._request(
            "POST",
            "/api/v1/secrets/lease",
            json={
                "secret_ref": secret_ref,
                "agent_id": agent_id,
                "tool_id": tool_id,
                "requested_scope": requested_scope,
                "resource_scope": resource_scope,
                "purpose": purpose,
                "ttl_seconds": ttl_seconds,
            },
        )

    def evaluate_data_flow(self, destination: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate Data Flow & Leakage Guard policy for a destination."""
        return self._request(
            "POST",
            "/api/v1/data-flow/evaluate",
            json={"destination": destination, "payload": payload},
        )

    def evaluate_egress(
        self,
        url: str,
        tool_id: str = "*",
        agent_id: str = "*",
        method: str = "POST",
    ) -> Dict[str, Any]:
        """Evaluate Network Egress Policy against destination URL & DNS resolution."""
        return self._request(
            "POST",
            "/api/v1/egress/evaluate",
            json={"url": url, "tool_id": tool_id, "agent_id": agent_id, "method": method},
        )

    def run_safe_replay(self, replay_pack_id: str) -> Dict[str, Any]:
        """Execute a declarative sanitized safe replay pack in dry-run isolation."""
        return self._request("POST", f"/api/v1/replay-packs/safe/{replay_pack_id}/run")

    def compute_source_health(self, source_id: str, is_public: Optional[bool] = None) -> Dict[str, Any]:
        """Compute live Source Health Profile from Change Radar & Freshness metrics."""
        payload: Dict[str, Any] = {}
        if is_public is not None:
            payload["is_public"] = is_public
        return self._request("POST", f"/api/v1/sources/{source_id}/health/compute", json=payload)

    def run_connector_harness(self, manifest: Dict[str, Any], sample_items: Optional[list] = None) -> Dict[str, Any]:
        """Execute CCK 12-check Connector Test Harness against a connector manifest."""
        return self._request("POST", "/api/v1/connectors/harness/run", json={"manifest": manifest, "sample_items": sample_items})

    def evaluate_pr_guardian(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate GitHub PR tool/MCP/policy diffs via CCK PR Guardian."""
        return self._request("POST", "/api/v1/pr-guardian/evaluate", json=payload)

    def create_trust_profile(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Publish or record a signed CCK Trust Profile."""
        return self._request("POST", "/api/v1/trust/profiles", json=payload)

    def search_trust_registry(self, query: str = "") -> list:
        """Discover verified MCP tools and connectors in the public CCK Trust Registry."""
        suffix = f"?q={query}" if query else ""
        return self._request("GET", f"/api/v1/trust/registry{suffix}")

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
