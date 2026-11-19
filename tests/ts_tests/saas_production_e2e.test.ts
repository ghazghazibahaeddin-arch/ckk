/**
 * End-to-End SaaS Acceptance & Reliability Verification Suite
 *
 * Verifies:
 * 1. Agent Registration & Initial DISCONNECTED state
 * 2. Authenticated Heartbeat & CONNECTED transition
 * 3. Invalid credentials & revoked key protection
 * 4. Webhook HMAC-SHA256 signature verification and duplicate replay defense
 * 5. MCP JSON-RPC 2.0 tool execution
 * 6. Distributable SDK fail-closed guard
 * 7. Failure Lab demo isolation from customer production audit metrics
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'crypto';
import { CCKClient, withCCKGuard } from '../../packages/cck-ts-sdk/src/index.js';
import { createTenantSession, type TenantTestSession } from './_test_auth.ts';

const BASE_URL = 'http://localhost:3000';

describe('CCK SaaS Production Verification Suite', () => {
  let session: TenantTestSession;
  let createdAgentId: string;
  let createdApiKey: string;
  let testProjectId: string;

  before(async () => {
    session = await createTenantSession(BASE_URL, 'saas');
  });

  test('1. Agent Registration: Initial state is strictly DISCONNECTED (never CONNECTED)', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        name: 'AutoFulfillmentAgent',
        framework: 'langgraph',
        target_capability: 'logistics.ship',
        target_resource: 'courier.fedex',
        guardrail_mode: 'ENFORCE_AND_BLOCK',
        freshness_ttl_seconds: 300,
      }),
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.agent_id);
    assert.ok(data.credentials?.api_key);
    assert.ok(data.credentials.api_key.startsWith('cck_live_'));

    // INVARIANT: An agent record alone must never be CONNECTED initially
    assert.equal(data.status, 'DISCONNECTED');
    assert.equal(data.agent.status, 'DISCONNECTED');

    createdAgentId = data.agent_id;
    createdApiKey = data.credentials.api_key;
    testProjectId = data.project_id;
  });

  test('2. Agent Heartbeat: Rejects unauthenticated or invalid bearer tokens', async () => {
    // Missing token
    const res1 = await fetch(`${BASE_URL}/api/v1/agents/${createdAgentId}/heartbeat`, {
      method: 'POST',
    });
    assert.equal(res1.status, 401);

    // Invalid token format
    const res2 = await fetch(`${BASE_URL}/api/v1/agents/${createdAgentId}/heartbeat`, {
      method: 'POST',
      headers: { Authorization: 'Bearer invalid_token_123' },
    });
    assert.equal(res2.status, 401);
  });

  test('3. Agent Heartbeat: Valid API key transitions agent to CONNECTED', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/agents/${createdAgentId}/heartbeat`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${createdApiKey}` },
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'CONNECTED');
    assert.equal(data.agent_id, createdAgentId);
    assert.ok(data.last_seen_at);
    assert.equal(data.heartbeat_acknowledged, true);

    // Verify agent record in list is now CONNECTED
    const listRes = await fetch(`${BASE_URL}/api/v1/agents`, {
      headers: session.headers,
    });
    assert.equal(listRes.status, 200);
    const list = await listRes.json();
    const found = list.find((a: any) => a.agent_id === createdAgentId);
    assert.ok(found);
    assert.equal(found.status, 'CONNECTED');
    assert.ok(found.last_seen_at);
  });

  test('4. Webhook Ingestion: Replay attack & duplicate prevention', async () => {
    const uniqueEntity = `order:test_${Date.now()}`;
    const payload = { entity_id: uniqueEntity, field_name: 'payment_status', value: 'paid' };

    // First ingestion
    const res1 = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify(payload),
    });
    assert.equal(res1.status, 200);
    const data1 = await res1.json();
    assert.equal(data1.status, 'success');
    assert.ok(data1.evidence_id);

    // Second ingestion with identical payload
    const res2 = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify(payload),
    });
    assert.equal(res2.status, 200);
    const data2 = await res2.json();
    assert.equal(data2.status, 'duplicate_ignored');
  });

  test('5. Webhook Ingestion: HMAC-SHA256 signature verification', async () => {
    const secret = 'cck_whsec_live_default';
    const payload = { entity_id: 'order:sig_test', field_name: 'refund_status', value: 'refunded', ts: Date.now() };
    const rawStr = JSON.stringify(payload);

    // Invalid signature
    const badRes = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-cck-signature': 'sha256=invalid_signature_hex',
      },
      body: rawStr,
    });
    assert.equal(badRes.status, 401);

    // Valid signature
    const validSig = crypto.createHmac('sha256', secret).update(rawStr).digest('hex');
    const goodRes = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-cck-signature': `sha256=${validSig}`,
      },
      body: rawStr,
    });
    assert.equal(goodRes.status, 200);
    const goodData = await goodRes.json();
    assert.equal(goodData.status, 'success');
  });

  test('6. MCP Server: Model Context Protocol JSON-RPC tool evaluation', async () => {
    // 1. initialize
    const initRes = await fetch(`${BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05' },
      }),
    });
    assert.equal(initRes.status, 200);
    const initData = await initRes.json();
    assert.equal(initData.result.serverInfo.name, 'cck-mcp-server');

    // 2. tools/list
    const listRes = await fetch(`${BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      }),
    });
    assert.equal(listRes.status, 200);
    const listData = await listRes.json();
    const toolNames = listData.result.tools.map((t: any) => t.name);
    assert.ok(toolNames.includes('cck_evaluate_action'));
    assert.ok(toolNames.includes('cck_record_evidence'));
    assert.ok(toolNames.includes('cck_verify_heartbeat'));

    // 3. tools/call cck_evaluate_action
    const callRes = await fetch(`${BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'cck_evaluate_action',
          arguments: {
            capability: 'logistics.ship',
            target: 'courier.fedex',
            parameters: { order_id: '1099' },
          },
        },
      }),
    });
    assert.equal(callRes.status, 200);
    const callData = await callRes.json();
    assert.ok(callData.result.content[0].text);
    const verdict = JSON.parse(callData.result.content[0].text);
    assert.ok(['ALLOW', 'BLOCK', 'REQUIRE_APPROVAL'].includes(verdict.decision));
  });

  test('7. TypeScript Distributable SDK: Fail-closed action guard enforcement', async () => {
    const cck = new CCKClient({ baseUrl: BASE_URL, apiKey: createdApiKey });

    // Ensure prerequisite fact is VALID
    const testEntity = `order:sdk_${Date.now()}`;
    await cck.recordEvidence({
      entity_id: testEntity,
      field_name: 'status',
      value: 'paid',
    });

    let toolExecuted = false;
    const result = await withCCKGuard(
      {
        client: cck,
        action: {
          session_id: 'sdk-test-session',
          agent: { agent_id: createdAgentId, name: 'SDKTestAgent' },
          capability: 'orders.fulfill',
          target: testEntity,
        },
      },
      () => {
        toolExecuted = true;
        return { success: true, tracking: 'TRK-9901' };
      }
    );

    assert.equal(toolExecuted, true);
    assert.equal(result.success, true);

    // Register tenant-scoped dependency rule for logistics.ship -> order:1099 status
    const depRes = await fetch(`${BASE_URL}/api/v1/dependencies`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        project_id: testProjectId,
        action_capability: 'logistics.ship',
        required_fact_entity: 'order:1099',
        required_fact_field: 'status',
      }),
    });
    assert.equal(depRes.status, 200);

    // Now invalidate the prerequisite fact (drift)
    await cck.recordEvidence({
      entity_id: 'order:1099',
      field_name: 'status',
      value: 'refunded',
    });

    // An action depending on order:1099 MUST be BLOCKED fail-closed
    let blockedToolExecuted = false;
    await assert.rejects(
      async () => {
        await withCCKGuard(
          {
            client: cck,
            action: {
              session_id: 'sdk-test-session-drift',
              agent: { agent_id: createdAgentId, name: 'SDKTestAgent' },
              capability: 'logistics.ship',
              target: 'courier.fedex',
            },
          },
          () => {
            blockedToolExecuted = true;
            return { dispatched: true };
          }
        );
      },
      (err: any) => {
        assert.equal(err.name, 'CCKActionBlockedError');
        assert.equal(err.verdict.decision, 'BLOCK');
        return true;
      }
    );

    // INVARIANT: Tool function MUST NOT execute when CCK returns BLOCK
    assert.equal(blockedToolExecuted, false);
  });

  test('8. Failure Lab Isolation: Demo simulation records do NOT pollute production customer counters', async () => {
    const statusBefore = await (await fetch(`${BASE_URL}/api/v1/system/status`, { headers: session.headers })).json();
    const initialAudits = statusBefore.total_audits;

    // Run Failure Lab simulation
    const labRes = await fetch(`${BASE_URL}/api/v1/failure-lab/run`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({ scenario: 'scenario_a_inventory' }),
    });
    assert.equal(labRes.status, 200);

    const statusAfter = await (await fetch(`${BASE_URL}/api/v1/system/status`, { headers: session.headers })).json();

    // INVARIANT: Demo simulations must never increment production customer audits
    assert.equal(statusAfter.total_audits, initialAudits);
  });
});
