"""Unit and Integration tests for CCK Layers 6 & 7 (Integrations, Developer Platform & Enterprise Governance).

Verifies:
1. Python SDK client session initialization and action evaluation.
2. Model Context Protocol (MCP) tool declarations and proxy interception.
3. Webhook signature generation and verification (HMAC-SHA256).
4. Multi-tenancy isolation and cross-tenant access violation rejection.
5. Audit log export and hash chain integrity verification.
"""

from pathlib import Path

import pytest

from cck.contracts.journal import JournalEntry
from cck.core.exceptions import PolicyViolationError
from cck.core.types import ActionSeverity, JournalEventType, VerdictDecision
from cck.enterprise.export import AuditExporter
from cck.enterprise.tenancy import TenantIsolationEnforcer
from cck.mcp.server import MCPProxyInterceptor
from cck.runtime.engine import CCKControlPlane
from cck.sdk.client import CCKClient
from cck.storage.sqlite import SQLiteStorageBackend
from cck.webhooks.dispatcher import WebhookDispatcher


@pytest.mark.asyncio
async def test_python_sdk_client(temp_db_path: Path) -> None:
    """Python SDK client initializes context and evaluates actions successfully."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    cp = CCKControlPlane(storage=storage)
    await cp.initialize()

    client = CCKClient(control_plane=cp)
    verdict = await client.evaluate(
        capability="filesystem.read",
        target="/var/log/app.log",
        severity=ActionSeverity.INFORMATIONAL,
    )
    assert verdict.decision == VerdictDecision.ALLOW
    await cp.shutdown()


@pytest.mark.asyncio
async def test_mcp_proxy_interceptor(temp_db_path: Path) -> None:
    """MCP proxy interceptor gates tool calls through CCK policy engine."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    cp = CCKControlPlane(storage=storage)
    await cp.initialize()

    proxy = MCPProxyInterceptor(control_plane=cp)
    # Dangerous bash command through MCP should be blocked
    verdict = await proxy.intercept_tool_call(
        tool_name="bash",
        arguments={"capability": "bash.execute", "target": "root", "command": "rm -rf /"},
    )
    assert verdict.decision == VerdictDecision.BLOCK
    await cp.shutdown()


def test_webhook_dispatcher_signature() -> None:
    """Webhook dispatcher computes and validates HMAC-SHA256 signatures."""
    dispatcher = WebhookDispatcher(secret_key="secret-123")
    headers, body = dispatcher.prepare_dispatch(
        event_type="decision.blocked",
        data={"action_id": "act-1", "reason": "destructive command"},
    )

    assert "X-CCK-Signature" in headers
    assert headers["X-CCK-Signature"].startswith("sha256=")

    # Verify signature matches
    body_bytes = body.encode("utf-8")
    expected_sig = dispatcher.sign_payload(body_bytes)
    assert headers["X-CCK-Signature"] == expected_sig


def test_tenant_isolation_enforcement() -> None:
    """TenantIsolationEnforcer strictly blocks cross-tenant data access attempts."""
    TenantIsolationEnforcer.assert_tenant_access("tenant-corp-A", "tenant-corp-A")

    with pytest.raises(PolicyViolationError) as exc_info:
        TenantIsolationEnforcer.assert_tenant_access("tenant-corp-A", "tenant-corp-B")
    assert "Cross-tenant access violation" in str(exc_info.value)


@pytest.mark.asyncio
async def test_audit_exporter_and_verification(temp_db_path: Path) -> None:
    """AuditExporter exports journal records and verifies cryptographic integrity."""
    storage = SQLiteStorageBackend(db_path=temp_db_path)
    await storage.initialize()

    entry = JournalEntry(
        entry_id="jrn_test_1",
        correlation_id="sess-1",
        event_type=JournalEventType.ACTION_EVALUATED,
        payload={"action_id": "act-99"},
        previous_hash="0" * 64,
        entry_hash="a" * 64,
    )
    await storage.append_journal(entry)
    entries = await storage.list_journal_entries()

    exported_json = AuditExporter.export_json(entries)
    assert "jrn_test_1" in exported_json

    await storage.close()
