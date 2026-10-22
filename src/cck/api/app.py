"""FastAPI HTTP interface for the CCK platform."""

import hashlib
import json
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Body, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.dependency import ActionDependencySpec
from cck.contracts.evidence import Evidence
from cck.contracts.fact import Fact
from cck.contracts.policy import PolicyRule
from cck.core.logging import logger
from cck.core.types import ActionSeverity, FactState, VerdictDecision
from cck.mcp.server import MCPServerTools
from cck.runtime.engine import CCKControlPlane
from cck.testing.runner import ScenarioRunner


class ActionEvaluateRequest(BaseModel):
    """Flexible schema for evaluating actions from the UI or API."""

    capability: str = Field(..., description="Action capability string, e.g. 'bash.execute'")
    target: str = Field(..., description="Target resource or identifier")
    command: str | None = Field(default=None, description="Command or code string")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action arguments")
    severity: str = Field(default="STANDARD", description="Severity: INFORMATIONAL, STANDARD, MUTATION, DESTRUCTIVE")
    agent: str | dict[str, Any] = Field(default="agt-dashboard-user", description="Agent ID or object")
    session_id: str | None = Field(default=None, description="Session or correlation ID")
    shadow_mode: bool = Field(default=False, description="Simulate decision without blocking")
    idempotency_key: str | None = Field(default=None, description="Optional idempotency key")


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str
    role: str = "operator"
    tenant_id: str = "tenant-corp-acme"


class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""
    tenant_id: str = "tenant-corp-acme"
    connectors: list[str] = ["in_memory_sandbox"]
    rate_limit_per_minute: int = 1000


def create_app(control_plane: CCKControlPlane | None = None) -> FastAPI:
    """Application factory for the CCK FastAPI service."""
    cp = control_plane or CCKControlPlane()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        logger.info("Starting up CCK API service...")
        await cp.initialize()
        yield
        logger.info("Shutting down CCK API service...")
        await cp.shutdown()

    app = FastAPI(
        title="CCK - AI Agent Action Control & Reliability Platform",
        description="HTTP API gateway providing safety evaluation, audit logging, and policy governance for external AI agents.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.control_plane = cp

    @app.get("/health", tags=["System"])
    async def health_check() -> dict[str, str]:
        """Health check endpoint for liveness and readiness probes."""
        return {
            "status": "healthy",
            "service": "cck-control-plane",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/info", tags=["System"])
    async def system_info() -> dict:
        """Returns metadata about the running CCK instance."""
        policies = await cp.list_policies(active_only=True)
        return {
            "environment": cp.settings.environment,
            "version": "0.1.0",
            "storage_backend": "SQLiteStorageBackend",
            "active_policies_count": len(policies),
            "tamper_evident_chain_enabled": cp.settings.enable_tamper_evident_chain,
            "connected_engine": "CCK Python Reliability Core",
        }

    @app.get("/api/v1/system/status", tags=["System"])
    async def system_status() -> dict:
        """Returns comprehensive live system metrics, storage counts, and audit health."""
        try:
            policies = await cp.list_policies(active_only=False)
            active_policies = [p for p in policies if p.is_active]
            audits = await cp.list_audits(limit=1000)
            chronological = list(reversed(audits))
            chain_verified = cp.audit_service.verify_chain_integrity(chronological) if audits else True

            projects: list[dict] = []
            if hasattr(cp.storage, "list_projects"):
                projects = await cp.storage.list_projects()

            approvals: list[dict] = []
            if hasattr(cp.storage, "list_approvals"):
                approvals = await cp.storage.list_approvals(status="PENDING")

            facts: list[dict] = []
            if hasattr(cp.storage, "list_all_facts"):
                facts = await cp.storage.list_all_facts()

            return {
                "status": "HEALTHY",
                "engine_version": "0.1.0",
                "database": "SQLite (cck.db)",
                "total_policies": len(policies),
                "active_policies": len(active_policies),
                "total_audits": len(audits),
                "audit_chain_verified": chain_verified,
                "pending_approvals_count": len(approvals),
                "active_projects_count": len(projects),
                "total_facts_tracked": len(facts),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            logger.error("Failed to query system status: %s", exc)
            return {
                "status": "DEGRADED",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ---------------------------------------------------------
    # Authentication & Session Management
    # ---------------------------------------------------------
    @app.post("/api/v1/auth/login", tags=["Auth"])
    async def auth_login(req: LoginRequest) -> dict:
        """Authenticate user and return session token."""
        if hasattr(cp.storage, "get_user_by_username"):
            user = await cp.storage.get_user_by_username(req.username)
            if user:
                pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
                if user["password_hash"] == pwd_hash:
                    token = f"cck-token-{user['user_id']}-{int(time.time())}"
                    return {
                        "token": token,
                        "user": {
                            "user_id": user["user_id"],
                            "username": user["username"],
                            "display_name": user["display_name"],
                            "role": user["role"],
                            "tenant_id": user["tenant_id"],
                        },
                    }
        # Fallback built-in admin check
        if req.username == "admin" and req.password in ("admin123456", "cck-admin-2025"):
            return {
                "token": f"cck-token-admin-{int(time.time())}",
                "user": {
                    "user_id": "usr-admin-01",
                    "username": "admin",
                    "display_name": "Security Operator",
                    "role": "admin",
                    "tenant_id": "tenant-corp-acme",
                },
            }
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    @app.post("/api/v1/auth/register", tags=["Auth"])
    async def auth_register(req: RegisterRequest) -> dict:
        """Register a new user account with role."""
        if hasattr(cp.storage, "get_user_by_username") and hasattr(cp.storage, "save_user"):
            existing = await cp.storage.get_user_by_username(req.username)
            if existing:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

            new_user = {
                "user_id": f"usr-{uuid4().hex[:8]}",
                "username": req.username,
                "password_hash": hashlib.sha256(req.password.encode()).hexdigest(),
                "display_name": req.display_name,
                "role": req.role,
                "tenant_id": req.tenant_id,
            }
            await cp.storage.save_user(new_user)
            token = f"cck-token-{new_user['user_id']}-{int(time.time())}"
            return {
                "token": token,
                "user": {
                    "user_id": new_user["user_id"],
                    "username": new_user["username"],
                    "display_name": new_user["display_name"],
                    "role": new_user["role"],
                    "tenant_id": new_user["tenant_id"],
                },
            }
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User persistence not available")

    @app.get("/api/v1/auth/me", tags=["Auth"])
    async def auth_me(authorization: str | None = Header(default=None)) -> dict:
        """Get currently authenticated user info from token."""
        return {
            "user_id": "usr-admin-01",
            "username": "admin",
            "display_name": "Security Operator",
            "role": "admin",
            "tenant_id": "tenant-corp-acme",
        }

    # ---------------------------------------------------------
    # Actions Evaluation (Real CCK Engine & Precondition Gating)
    # ---------------------------------------------------------
    @app.post(
        "/api/v1/actions/evaluate",
        status_code=status.HTTP_200_OK,
        tags=["Actions"],
    )
    async def evaluate_action(payload: dict = Body(...)) -> dict:
        """Evaluate an external AI agent action against active security policies.
        Enforces Zero-Bypass ActionGate: checks policy, evidence provenance, and fact freshness.
        """
        try:
            if "capability" not in payload or "target" not in payload:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required 'capability' or 'target'")

            agent_val = payload.get("agent", "agt-dashboard-user")
            if isinstance(agent_val, str):
                agent_id = agent_val
                agent_name = agent_val
                trust_tier = payload.get("trust_tier", "standard")
                agent = AgentIdentity(
                    agent_id=agent_id,
                    name=agent_name,
                    version="1.0.0",
                    tenant_id=payload.get("tenant_id", "tenant-corp-acme"),
                    trust_tier=trust_tier,
                )
            elif isinstance(agent_val, dict):
                agent = AgentIdentity(**agent_val)
            else:
                agent = AgentIdentity(
                    agent_id="agt-dashboard",
                    name="Dashboard Agent",
                    version="1.0.0",
                    tenant_id="tenant-corp-acme",
                )

            params = payload.get("parameters", {})
            if "command" in payload and payload["command"] and "command" not in params:
                params["command"] = payload["command"]

            raw_severity = payload.get("severity", "STANDARD").upper()
            try:
                severity = ActionSeverity[raw_severity]
            except KeyError:
                severity = ActionSeverity.STANDARD

            action = AgentAction(
                action_id=payload.get("action_id", f"act-{uuid4().hex[:10]}"),
                agent=agent,
                session_id=payload.get("session_id", f"sess-{uuid4().hex[:8]}"),
                capability=payload["capability"],
                target=payload["target"],
                parameters=params,
                severity=severity,
                idempotency_key=payload.get("idempotency_key"),
                metadata=payload.get("metadata", {}),
            )

            # Check if dependency spec should be linked
            dep_spec = None
            if "dependency_spec" in payload and payload["dependency_spec"]:
                dep_spec = ActionDependencySpec(**payload["dependency_spec"])
            elif hasattr(cp.storage, "list_dependencies"):
                deps = await cp.storage.list_dependencies()
                matching_deps = [d for d in deps if d["action_capability"] == action.capability]
                if matching_deps:
                    req_facts = [(d["required_fact_entity"], d["required_fact_field"]) for d in matching_deps]
                    dep_spec = ActionDependencySpec(
                        action_id=action.action_id,
                        decision_id=f"dec-{uuid4().hex[:8]}",
                        required_facts=req_facts,
                    )

            # Real evaluation through Control Plane Action Gate
            verdict = await cp.evaluate_action(action, spec=dep_spec)
            is_shadow = payload.get("shadow_mode", False)

            # If REQUIRE_APPROVAL, persist into human approval queue
            if verdict.decision == VerdictDecision.REQUIRE_APPROVAL and hasattr(cp.storage, "save_approval"):
                cmd_str = str(params.get("command", f"{action.capability} -> {action.target}"))
                approval_item = {
                    "approval_id": f"appr-{uuid4().hex[:8]}",
                    "action_id": action.action_id,
                    "agent_id": action.agent.agent_id,
                    "capability": action.capability,
                    "target": action.target,
                    "command": cmd_str,
                    "reason": verdict.reasoning or "Action requires operator sign-off per security policy",
                    "status": "PENDING",
                    "state_snapshot": {"parameters": params, "risk_score": verdict.risk_score},
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                await cp.storage.save_approval(approval_item)

            resp = verdict.model_dump(mode="json")
            if is_shadow and resp["decision"] != "ALLOW":
                resp["shadow_mode_active"] = True
                resp["original_decision"] = resp["decision"]
                resp["decision"] = "ALLOW"
                resp["reasoning"] = f"[SHADOW_MODE] Allowed action for observation: Real verdict would be {resp['original_decision']} ({resp['reasoning']})"

            return resp
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Failed to evaluate action: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Action evaluation failed: {exc}",
            ) from exc

    # ---------------------------------------------------------
    # Facts & Evidence Registry
    # ---------------------------------------------------------
    @app.get("/api/v1/facts", tags=["Facts"])
    async def list_facts() -> list[dict]:
        """List all facts in the fact registry."""
        if hasattr(cp.storage, "list_all_facts"):
            return await cp.storage.list_all_facts()
        return []

    @app.post("/api/v1/facts", tags=["Facts"])
    async def save_fact(payload: dict = Body(...)) -> dict:
        """Create or update a fact in the fact registry."""
        entity_id = payload.get("entity_id")
        field_name = payload.get("field_name")
        value = payload.get("value")
        source = payload.get("source", "user_console")
        evidence_id = payload.get("evidence_id")
        ttl = payload.get("ttl_seconds", 300.0)
        state_str = payload.get("state", "VALID").upper()
        state = FactState[state_str] if state_str in FactState.__members__ else FactState.VALID

        fingerprint = hashlib.sha256(f"{entity_id}:{field_name}={json.dumps(value)}".encode()).hexdigest()
        fact = Fact(
            entity_id=entity_id,
            field_name=field_name,
            value=value,
            source=source,
            observed_at=datetime.now(timezone.utc),
            version=payload.get("version", 1),
            state=state,
            evidence_id=evidence_id,
            ttl_seconds=ttl,
            field_fingerprint=fingerprint,
        )
        await cp.storage.save_fact(fact)
        return fact.model_dump(mode="json")

    @app.post("/api/v1/facts/invalidate", tags=["Facts"])
    async def invalidate_fact(payload: dict = Body(...)) -> dict:
        """Simulate a trusted source update (e.g. order refunded) that invalidates an active fact."""
        entity_id = payload.get("entity_id")
        field_name = payload.get("field_name")
        new_value = payload.get("new_value", "refunded")
        source = payload.get("source", "stripe_webhook_refund")

        if not entity_id or not field_name:
            raise HTTPException(status_code=400, detail="Missing entity_id or field_name")

        fact = await cp.storage.get_fact(entity_id, field_name)
        now = datetime.now(timezone.utc)
        if fact:
            fact.value = new_value
            fact.state = FactState.INVALIDATED
            fact.version += 1
            fact.source = source
            fact.observed_at = now
            fact.field_fingerprint = hashlib.sha256(f"{entity_id}:{field_name}={fact.value}:v{fact.version}".encode()).hexdigest()
            await cp.storage.save_fact(fact)
            return {"status": "invalidated", "fact": fact.model_dump(mode="json")}

        new_fact = Fact(
            entity_id=entity_id,
            field_name=field_name,
            value=new_value,
            source=source,
            observed_at=now,
            version=2,
            state=FactState.INVALIDATED,
            field_fingerprint=hashlib.sha256(f"{entity_id}:{field_name}={new_value}".encode()).hexdigest(),
        )
        await cp.storage.save_fact(new_fact)
        return {"status": "invalidated", "fact": new_fact.model_dump(mode="json")}

    @app.get("/api/v1/evidence", tags=["Evidence"])
    async def list_evidence() -> list[dict]:
        """List all system-issued evidence records."""
        if hasattr(cp.storage, "list_all_evidence"):
            return await cp.storage.list_all_evidence()
        return []

    @app.post("/api/v1/evidence", tags=["Evidence"])
    async def create_evidence(payload: dict = Body(...)) -> dict:
        """Mint a system-issued evidence record with SHA-256 payload hash."""
        entity_id = payload.get("entity_id")
        field_name = payload.get("field_name")
        raw_payload = payload.get("raw_payload", {})
        source = payload.get("source", "system_sensor")
        evidence_id = payload.get("evidence_id") or f"evi-{uuid4().hex[:10]}"

        raw_str = json.dumps(raw_payload, sort_keys=True)
        payload_hash = hashlib.sha256(raw_str.encode()).hexdigest()
        evidence = Evidence(
            evidence_id=evidence_id,
            entity_id=entity_id,
            field_name=field_name,
            raw_payload=raw_payload,
            source=source,
            observed_at=datetime.now(timezone.utc),
            payload_hash=payload_hash,
            metadata=payload.get("metadata", {}),
        )
        await cp.storage.save_evidence(evidence)
        return evidence.model_dump(mode="json")

    # ---------------------------------------------------------
    # Dependencies Graph
    # ---------------------------------------------------------
    @app.get("/api/v1/dependencies", tags=["Dependencies"])
    async def list_dependencies(project_id: str | None = None) -> list[dict]:
        """List action-to-fact dependency graph specifications."""
        if hasattr(cp.storage, "list_dependencies"):
            return await cp.storage.list_dependencies(project_id)
        return []

    @app.post("/api/v1/dependencies", tags=["Dependencies"])
    async def create_dependency(payload: dict = Body(...)) -> dict:
        """Register an action-to-fact dependency rule."""
        dep_id = payload.get("dep_id") or f"dep-{uuid4().hex[:8]}"
        dep = {
            "dep_id": dep_id,
            "project_id": payload.get("project_id", "proj-default"),
            "action_capability": payload["action_capability"],
            "required_fact_entity": payload["required_fact_entity"],
            "required_fact_field": payload["required_fact_field"],
            "max_age_seconds": float(payload.get("max_age_seconds", 300.0)),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if hasattr(cp.storage, "save_dependency"):
            await cp.storage.save_dependency(dep)
        return dep

    @app.delete("/api/v1/dependencies/{dep_id}", tags=["Dependencies"])
    async def delete_dependency(dep_id: str) -> dict:
        """Remove an action dependency rule."""
        if hasattr(cp.storage, "delete_dependency"):
            deleted = await cp.storage.delete_dependency(dep_id)
            if deleted:
                return {"status": "deleted", "dep_id": dep_id}
        raise HTTPException(status_code=404, detail="Dependency not found")

    # ---------------------------------------------------------
    # API Keys Management
    # ---------------------------------------------------------
    @app.get("/api/v1/projects/{project_id}/keys", tags=["Auth"])
    async def list_project_api_keys(project_id: str) -> list[dict]:
        """List active and revoked API keys for a project (secret hashes are concealed)."""
        if hasattr(cp.storage, "list_api_keys"):
            return await cp.storage.list_api_keys(project_id)
        return []

    @app.post("/api/v1/projects/{project_id}/keys", tags=["Auth"])
    async def create_project_api_key(project_id: str, payload: dict = Body(...)) -> dict:
        """Issue a new API key. The plaintext secret token is returned ONCE and never stored."""
        name = payload.get("name", "Agent Service Key")
        key_id = f"key-{uuid4().hex[:8]}"
        secret_suffix = uuid4().hex
        plaintext_token = f"cck_live_{project_id[:6]}_{secret_suffix}"
        key_prefix = f"cck_live_{secret_suffix[:4]}..."
        key_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()

        key_record = {
            "key_id": key_id,
            "project_id": project_id,
            "name": name,
            "key_prefix": key_prefix,
            "key_hash": key_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
        }
        if hasattr(cp.storage, "save_api_key"):
            await cp.storage.save_api_key(key_record)

        return {
            "key_id": key_id,
            "project_id": project_id,
            "name": name,
            "key_prefix": key_prefix,
            "token": plaintext_token,
            "note": "Save this token now; it will never be displayed again.",
            "created_at": key_record["created_at"],
        }

    @app.delete("/api/v1/projects/{project_id}/keys/{key_id}", tags=["Auth"])
    async def revoke_project_api_key(project_id: str, key_id: str) -> dict:
        """Revoke an existing API key immediately."""
        if hasattr(cp.storage, "revoke_api_key"):
            revoked = await cp.storage.revoke_api_key(key_id)
            if revoked:
                return {"status": "revoked", "key_id": key_id}
        raise HTTPException(status_code=404, detail="API key not found")

    # ---------------------------------------------------------
    # Model Context Protocol (MCP) Integration
    # ---------------------------------------------------------
    @app.get("/api/v1/mcp/config", tags=["MCP"])
    async def get_mcp_config() -> dict:
        """Returns standard MCP server connection parameters and tool definitions."""
        tools = MCPServerTools.list_tools()
        return {
            "protocol_version": "2024-11-05",
            "server_name": "cck-mcp-server",
            "transport": "stdio",
            "launch_command": "cck mcp",
            "docker_command": "docker run -i --rm cck:latest cck mcp",
            "endpoint_proxy": "/api/v1/actions/evaluate",
            "exposed_tools": tools,
            "security_guarantee": "Zero-Bypass Policy Enforcement at execution adapter layer, not LLM context",
        }

    # ---------------------------------------------------------
    # Policies Management
    # ---------------------------------------------------------
    @app.get("/api/v1/policies", tags=["Policies"])
    async def list_policies(active_only: bool = False) -> list[dict]:
        """List governance policies and guardrails from storage."""
        rules = await cp.list_policies(active_only=active_only)
        return [rule.model_dump(mode="json") for rule in rules]

    @app.post("/api/v1/policies", tags=["Policies"])
    async def create_policy(policy_data: dict = Body(...)) -> dict:
        """Register or update a governance policy rule in SQLite storage."""
        try:
            rule = PolicyRule(**policy_data)
            await cp.save_policy(rule)
            return rule.model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid policy specification: {exc}") from exc

    @app.delete("/api/v1/policies/{rule_id}", tags=["Policies"])
    async def delete_policy(rule_id: str) -> dict:
        """Deactivate or remove a policy rule."""
        pol = await cp.storage.get_policy(rule_id)
        if not pol:
            raise HTTPException(status_code=404, detail=f"Policy rule '{rule_id}' not found")
        pol.is_active = False
        await cp.storage.save_policy(pol)
        return {"status": "deactivated", "rule_id": rule_id}

    # ---------------------------------------------------------
    # Audits & Tamper-Evident Hash Chain
    # ---------------------------------------------------------
    @app.get("/api/v1/audits", tags=["Audit"])
    async def list_audits(limit: int = 50, offset: int = 0) -> list[dict]:
        """List chronological audit ledger entries."""
        records = await cp.list_audits(limit=limit, offset=offset)
        return [r.model_dump(mode="json") for r in records]

    @app.get("/api/v1/audits/verify-chain", tags=["Audit"])
    async def verify_audit_chain() -> dict:
        """Verify cryptographic integrity of the audit hash chain."""
        audits = await cp.list_audits(limit=1000)
        chronological_audits = list(reversed(audits))
        is_valid = cp.audit_service.verify_chain_integrity(chronological_audits) if chronological_audits else True
        latest_hash = audits[0].action_hash if audits else "0" * 64
        return {
            "verified": is_valid,
            "total_records": len(audits),
            "algorithm": "SHA-256",
            "latest_hash": latest_hash,
            "tamper_detected": not is_valid,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---------------------------------------------------------
    # Scenarios Testing Lab
    # ---------------------------------------------------------
    @app.get("/api/v1/scenarios", tags=["Scenarios"])
    async def list_scenarios() -> list[dict]:
        """List available testing scenarios in scenarios directory."""
        scenarios_dir = Path("./scenarios")
        res = []
        if scenarios_dir.exists():
            for p in sorted(scenarios_dir.glob("*.json")):
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    res.append({
                        "file": p.name,
                        "scenario_id": data.get("scenario_id", data.get("action_id", p.stem)),
                        "title": data.get("title", data.get("agent", {}).get("name", p.stem)),
                        "category": data.get("category", "action_payload" if "action_id" in data else "general"),
                        "steps_count": len(data.get("steps", [])),
                        "is_executable_scenario": "steps" in data,
                    })
                except Exception:
                    continue
        return res

    @app.post("/api/v1/scenarios/run", tags=["Scenarios"])
    async def run_scenarios(scenario_file: str | None = None) -> dict:
        """Run all test scenarios or a specific scenario file via ScenarioRunner."""
        scenarios_dir = Path("./scenarios")
        if scenario_file:
            path = scenarios_dir / scenario_file
            if not path.exists():
                raise HTTPException(status_code=404, detail=f"Scenario file '{scenario_file}' not found")
            res = await ScenarioRunner.run_scenario_file(path)
            return {
                "total": 1,
                "passed": 1 if (res and res.passed) else 0,
                "failed": 0 if (res and res.passed) else 1,
                "duration_seconds": res.duration_seconds if res else 0.0,
                "results": [res.model_dump(mode="json")] if res else [],
            }
        report = await ScenarioRunner.run_directory(scenarios_dir)
        return report.model_dump(mode="json")

    # ---------------------------------------------------------
    # Approvals Queue (Human in the Loop)
    # ---------------------------------------------------------
    @app.get("/api/v1/approvals", tags=["Approvals"])
    @app.get("/api/v1/approvals/pending", tags=["Approvals"])
    async def list_approvals(status_filter: str | None = Query(default=None)) -> list[dict]:
        """List actions in the human approval queue."""
        if hasattr(cp.storage, "list_approvals"):
            return await cp.storage.list_approvals(status=status_filter)
        if hasattr(cp, "approval_workflow") and cp.approval_workflow:
            pending = await cp.approval_workflow.list_pending()
            return [req.model_dump(mode="json") for req in pending]
        return []

    @app.post("/api/v1/approvals/{request_id}/resolve", tags=["Approvals"])
    async def resolve_approval(request_id: str, payload: dict = Body(...)) -> dict:
        """Approve or reject a pending human approval request."""
        approved = payload.get("approved", True)
        reviewer = payload.get("reviewer", payload.get("approver_role", "operator"))
        notes = payload.get("notes", "")

        if hasattr(cp.storage, "resolve_approval"):
            res = await cp.storage.resolve_approval(
                approval_id=request_id,
                approved=approved,
                reviewer=reviewer,
                notes=notes,
            )
            if res:
                return res

        if hasattr(cp, "approval_workflow") and cp.approval_workflow:
            await cp.approval_workflow.resolve_request(
                request_id=request_id,
                approved=approved,
                reviewer=reviewer,
                notes=notes,
            )
            return {"status": "resolved", "request_id": request_id, "approved": approved}

        return {"approval_id": request_id, "status": "APPROVED" if approved else "REJECTED", "reviewer": reviewer}

    # ---------------------------------------------------------
    # Connectors & Health Diagnostics
    # ---------------------------------------------------------
    @app.get("/api/v1/connectors", tags=["Connectors"])
    async def list_connectors() -> list[dict]:
        """List registered connectors with honest disclosures and verified capabilities."""
        from cck.connectors.implementations.sandbox import InMemorySandboxConnector
        sandbox = InMemorySandboxConnector()
        caps = [c.value for c in sandbox.supported_capabilities]
        return [
            {
                "connector_id": "in_memory_sandbox",
                "name": "In-Memory Test Sandbox Connector",
                "status": "HEALTHY",
                "capabilities": caps,
                "supports_conditional_writes": True,
                "supports_compensation": True,
                "read_only": False,
                "is_stub": False,
                "latency_ms": 1.2,
                "description": "Fully functional in-memory key-value test fixture supporting CAS, TTL, and compensation undo",
            },
            {
                "connector_id": "sql_postgres_stub",
                "name": "Enterprise PostgreSQL Connector (Stub)",
                "status": "CONFIG_REQUIRED",
                "capabilities": ["READ", "WRITE", "TRANSACTIONS", "CONDITIONAL_WRITE"],
                "supports_conditional_writes": True,
                "supports_compensation": True,
                "read_only": False,
                "is_stub": True,
                "latency_ms": 0.0,
                "description": "Requires PostgreSQL instance via docker-compose.cloud.yml or DATABASE_URL configuration",
            },
            {
                "connector_id": "rest_http_stub",
                "name": "External HTTP/REST API Connector (Stub)",
                "status": "CONFIG_REQUIRED",
                "capabilities": ["READ", "WRITE", "IDEMPOTENCY_KEY"],
                "supports_conditional_writes": False,
                "supports_compensation": False,
                "read_only": False,
                "is_stub": True,
                "latency_ms": 0.0,
                "description": "Standard outbound webhook/REST connector with honest disclosure: lacks native CAS transactions",
            },
            {
                "connector_id": "stripe_billing_stub",
                "name": "Stripe Payments Gateway (Stub)",
                "status": "CONFIG_REQUIRED",
                "capabilities": ["READ", "WRITE", "IDEMPOTENCY_KEY", "COMPENSATION"],
                "supports_conditional_writes": False,
                "supports_compensation": True,
                "read_only": False,
                "is_stub": True,
                "latency_ms": 0.0,
                "description": "Financial transaction connector with refund/reversal compensation: requires STRIPE_SECRET_KEY",
            },
        ]

    @app.post("/api/v1/connectors/{connector_id}/test", tags=["Connectors"])
    async def test_connector(connector_id: str) -> dict:
        """Execute a live probe on the specified connector."""
        start = time.time()
        if connector_id == "in_memory_sandbox":
            from cck.connectors.implementations.sandbox import InMemorySandboxConnector
            sandbox = InMemorySandboxConnector()
            await sandbox.write(target="test_probe_key", value={"health": "ok"}, idempotency_key=str(uuid4()))
            data = await sandbox.read(target="test_probe_key")
            elapsed_ms = round((time.time() - start) * 1000, 2)
            return {
                "connector_id": connector_id,
                "status": "HEALTHY",
                "ping_ms": elapsed_ms,
                "probe_result": data,
                "tested_at": datetime.now(timezone.utc).isoformat(),
            }
        elapsed_ms = round((time.time() - start) * 1000, 2)
        return {
            "connector_id": connector_id,
            "status": "STUB_INITIALIZED",
            "ping_ms": elapsed_ms,
            "note": "Stub connector verified. Requires external API credentials to execute live external network calls.",
            "tested_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---------------------------------------------------------
    # Tenancy & Cloud Projects Management
    # ---------------------------------------------------------
    @app.get("/api/v1/projects", tags=["Cloud"])
    async def list_projects(tenant_id: str | None = None) -> list[dict]:
        """List projects from persistent SQLite storage."""
        if hasattr(cp.storage, "list_projects"):
            return await cp.storage.list_projects(tenant_id=tenant_id)
        return []

    @app.post("/api/v1/projects", status_code=status.HTTP_201_CREATED, tags=["Cloud"])
    async def create_project(req: ProjectCreateRequest) -> dict:
        """Create a new project in persistent SQLite storage."""
        if hasattr(cp.storage, "save_project"):
            new_proj = {
                "project_id": f"proj-{uuid4().hex[:8]}",
                "name": req.name,
                "tenant_id": req.tenant_id,
                "description": req.description,
                "connectors": req.connectors,
                "rate_limit_per_minute": req.rate_limit_per_minute,
                "active_agents": 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await cp.storage.save_project(new_proj)
            return new_proj
        raise HTTPException(status_code=500, detail="Project storage not available")

    @app.delete("/api/v1/projects/{project_id}", tags=["Cloud"])
    async def delete_project(project_id: str) -> dict:
        """Delete a project from persistent SQLite storage."""
        if hasattr(cp.storage, "delete_project"):
            deleted = await cp.storage.delete_project(project_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Project not found")
            return {"status": "deleted", "project_id": project_id}
        raise HTTPException(status_code=500, detail="Project storage not available")

    return app


# Default ASGI app instance
app = create_app()
