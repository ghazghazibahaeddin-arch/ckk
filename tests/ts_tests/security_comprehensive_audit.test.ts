import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  createTenantSession,
  createMemberSession,
  authHeaders,
  type TenantTestSession,
} from './_test_auth.ts';

const BASE_URL = 'http://127.0.0.1:3000';

describe('CCK Comprehensive Security, Reliability & Multi-Tenant Audit Suite', () => {
  let tenantA: TenantTestSession;
  let tenantB: TenantTestSession;
  let viewerA: { token: string; user: Record<string, any>; headers: Record<string, string> };
  let operatorA: { token: string; user: Record<string, any>; headers: Record<string, string> };
  let agentAId = '';
  let agentAApiKey = '';
  let receiptAId = '';
  let shareTokenA = '';

  before(async () => {
    tenantA = await createTenantSession(BASE_URL, 'audit_a');
    tenantB = await createTenantSession(BASE_URL, 'audit_b');
    viewerA = await createMemberSession(BASE_URL, tenantA.token, 'viewer', 'audit_v');
    operatorA = await createMemberSession(BASE_URL, tenantA.token, 'operator', 'audit_op');

    // Create Agent A under Tenant A
    const agRes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({
        name: `AuditAgentA_${Date.now()}`,
        project_id: tenantA.projectId,
        tenant_id: tenantA.tenantId,
        framework: 'langgraph',
        target_capability: 'payments.transfer',
        target_resource: 'vendor:acct_audit',
        guardrail_mode: 'ENFORCE_AND_BLOCK',
      }),
    });
    assert.equal(agRes.status, 201);
    const ag = await agRes.json();
    agentAId = ag.agent_id;
    agentAApiKey = ag.credentials.api_key;

    // Seed an evaluation so Tenant A owns a signed receipt
    const evalRes = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({
        agent_id: agentAId,
        capability: 'telemetry.log',
        target: 'metrics.audit',
        command: 'ping',
      }),
    });
    assert.equal(evalRes.status, 200);
    const evalData = await evalRes.json();
    receiptAId = evalData.receipt_id;
    shareTokenA = evalData.receipt?.shareable_token || '';
  });

  test('SEC-01: Unauthenticated requests & legacy/spoofed headers receive 401 across private Core, Governance & Batch 1-3 endpoints', async () => {
    const protectedEndpoints: Array<[string, string, unknown?]> = [
      ['GET', '/api/v1/projects'],
      ['GET', '/api/v1/agents'],
      ['GET', '/api/v1/facts'],
      ['GET', '/api/v1/receipts'],
      ['GET', '/api/v1/audits'],
      ['GET', '/api/v1/delegations'],
      ['GET', '/api/v1/budgets'],
      ['GET', '/api/v1/mcp/servers'],
      ['GET', '/api/v1/freshness/policies'],
      ['GET', '/api/v1/radar/sources'],
      ['GET', '/api/v1/dependency-graph'],
      ['GET', '/api/v1/tools/identities'],
      ['GET', '/api/v1/secrets'],
      ['GET', '/api/v1/data-flow/policies'],
      ['GET', '/api/v1/egress/policies'],
      ['GET', '/api/v1/replay-packs/safe'],
      ['GET', '/api/v1/connectors/submissions'],
      ['GET', '/api/v1/trust/profiles'],
      ['POST', '/api/v1/actions/evaluate', { capability: 'test.read', target: 'x' }],
      ['POST', '/api/v1/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }],
    ];

    for (const [method, path, body] of protectedEndpoints) {
      // 1. No auth header
      const resNoAuth = await fetch(`${BASE_URL}${path}`, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      assert.equal(resNoAuth.status, 401, `Expected 401 without auth on ${method} ${path}, got ${resNoAuth.status}`);

      // 2. Spoofed unsigned headers + legacy cck-token-* prefix must all be rejected
      const resSpoof = await fetch(`${BASE_URL}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'x-tenant-id': tenantA.tenantId,
          'x-user-role': 'supervisor',
          Authorization: 'Bearer cck-token-legacy-forged',
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      assert.equal(resSpoof.status, 401, `Expected 401 with forged header/legacy token on ${method} ${path}`);
    }
  });

  test('SEC-02: Session & Auth Hardening — Firebase RS256 enforcement, Sandbox isolation, Logout revocation & Login rate limit (429)', async () => {
    // 1. Forged / unsigned firebase-session fails closed with 401
    const fbRes = await fetch(`${BASE_URL}/api/v1/auth/firebase-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: 'not.a.real.firebase.jwt', uid: 'fake-uid' }),
    });
    assert.equal(fbRes.status, 401);

    // 2. Sandbox mints isolated tenant_sandbox_* token cleanly
    const sbRes = await fetch(`${BASE_URL}/api/v1/auth/sandbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sandbox_id: `sandbox_audit_${Date.now()}` }),
    });
    assert.equal(sbRes.status, 200);
    const sbData = await sbRes.json();
    assert.ok(sbData.token.startsWith('cck_sess_'));
    assert.ok(sbData.user.tenant_id.startsWith('tenant_sandbox_'));

    // 3. Logout immediately invalidates the session token
    const meBefore = await fetch(`${BASE_URL}/api/v1/auth/me`, {
      headers: authHeaders(sbData.token),
    });
    assert.equal(meBefore.status, 200);

    const logoutRes = await fetch(`${BASE_URL}/api/v1/auth/logout`, {
      method: 'POST',
      headers: authHeaders(sbData.token),
    });
    assert.equal(logoutRes.status, 200);

    const meAfter = await fetch(`${BASE_URL}/api/v1/auth/me`, {
      headers: authHeaders(sbData.token),
    });
    assert.equal(meAfter.status, 401, 'Logged-out session token must be revoked');

    // 4. Repeated bad login attempts trigger HTTP 429 rate limiting
    const rlTargetUser = tenantA.user.username;
    let saw429 = false;
    for (let i = 0; i < 12; i++) {
      const loginRes = await fetch(`${BASE_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: rlTargetUser, password: `Wrong_${i}` }),
      });
      if (loginRes.status === 429) {
        saw429 = true;
        break;
      }
    }
    assert.equal(saw429, true, 'Repeated failed logins must trigger HTTP 429 rate limit');
  });

  test('SEC-03: Real RBAC Matrix — Viewer blocked on writes, Operator blocked on Supervisor endpoints even with spoofed headers', async () => {
    // Viewer CAN read
    const viewerRead = await fetch(`${BASE_URL}/api/v1/agents`, { headers: viewerA.headers });
    assert.equal(viewerRead.status, 200);

    // Viewer CANNOT write (facts, agents, policies)
    const viewerWriteFact = await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: viewerA.headers,
      body: JSON.stringify({ entity_id: 'order:rbac1', field_name: 'status', value: 'paid' }),
    });
    assert.equal(viewerWriteFact.status, 403);

    const viewerWritePolicy = await fetch(`${BASE_URL}/api/v1/policies`, {
      method: 'POST',
      headers: viewerA.headers,
      body: JSON.stringify({ name: 'Viewer Illegal Policy', capability_pattern: '*' }),
    });
    assert.equal(viewerWritePolicy.status, 403);

    // Operator CAN write facts
    const opWriteFact = await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: operatorA.headers,
      body: JSON.stringify({ entity_id: 'order:rbac_op', field_name: 'status', value: 'paid' }),
    });
    assert.ok(opWriteFact.status === 200 || opWriteFact.status === 201);

    // Operator CANNOT invoke SUPERVISOR routes even when attempting forged x-user-role: supervisor
    const opKillSwitch = await fetch(`${BASE_URL}/api/v1/kill-switches/trigger`, {
      method: 'POST',
      headers: authHeaders(operatorA.token, { 'x-user-role': 'supervisor' }),
      body: JSON.stringify({ scope_type: 'AGENT', scope_value: agentAId, reason: 'Privilege escalation attempt' }),
    });
    assert.equal(opKillSwitch.status, 403);

    const opCreateMember = await fetch(`${BASE_URL}/api/v1/auth/members`, {
      method: 'POST',
      headers: authHeaders(operatorA.token, { 'x-user-role': 'supervisor' }),
      body: JSON.stringify({ username: `esc_${Date.now()}`, password: 'Password123!', role: 'supervisor' }),
    });
    assert.equal(opCreateMember.status, 403);

    // Agent live key works cleanly on agent evaluation endpoints
    const agentEval = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: authHeaders(agentAApiKey),
      body: JSON.stringify({
        agent_id: agentAId,
        capability: 'telemetry.log',
        target: 'metrics.agent',
        command: 'ping',
      }),
    });
    assert.equal(agentEval.status, 200);
  });

  test('SEC-04: Multi-Tenant Isolation across Core, Governance & Batch 1-3 + Body Tenant Spoof Rejection', async () => {
    // 1. Body tenant_id mismatch must return 403
    const bodyMismatch = await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: tenantB.headers,
      body: JSON.stringify({
        tenant_id: tenantA.tenantId,
        entity_id: 'order:spoof',
        field_name: 'status',
        value: 'paid',
      }),
    });
    assert.equal(bodyMismatch.status, 403);

    // 2. Tenant A registers a Secret & Radar Source & Safe Replay Pack
    const secName = `sec_iso_${Date.now()}`;
    const secRes = await fetch(`${BASE_URL}/api/v1/secrets`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({
        secret_ref: secName,
        secret_value: 'sk_live_tenant_a_isolated_999',
        allowed_tools: ['tool.a'],
        allowed_scopes: ['pay:write'],
      }),
    });
    assert.equal(secRes.status, 201);

    // Tenant B attempting to lease Tenant A's secret -> 403
    const crossLease = await fetch(`${BASE_URL}/api/v1/secrets/lease`, {
      method: 'POST',
      headers: tenantB.headers,
      body: JSON.stringify({
        secret_ref: secName,
        agent_id: 'agt-b',
        tool_id: 'tool.a',
        requested_scope: 'pay:write',
      }),
    });
    assert.equal(crossLease.status, 403);

    // Tenant B listing projects/agents/receipts/secrets sees ZERO Tenant A records
    const [bAgents, bReceipts, bSecrets] = await Promise.all([
      (await fetch(`${BASE_URL}/api/v1/agents`, { headers: tenantB.headers })).json(),
      (await fetch(`${BASE_URL}/api/v1/receipts`, { headers: tenantB.headers })).json(),
      (await fetch(`${BASE_URL}/api/v1/secrets`, { headers: tenantB.headers })).json(),
    ]);
    assert.ok(!bAgents.some((a: any) => a.agent_id === agentAId));
    assert.ok(!bReceipts.some((r: any) => r.receipt_id === receiptAId));
    assert.ok(!bSecrets.some((s: any) => s.secret_ref === secName));
  });

  test('SEC-05: Receipt share=true access control, Public Verifier redaction & Audit Chain Integrity', async () => {
    // 1a. Cross-tenant direct receipt access -> 403
    const crossDirectRes = await fetch(`${BASE_URL}/api/v1/receipts/${receiptAId}`, {
      headers: tenantB.headers,
    });
    assert.equal(crossDirectRes.status, 403);

    // 1b. ?share=true without share_token -> 401
    const badShareRes = await fetch(`${BASE_URL}/api/v1/receipts/${receiptAId}?share=true`, {
      headers: tenantB.headers,
    });
    assert.equal(badShareRes.status, 401);

    // 1c. ?share=true with wrong share_token -> 403
    const wrongTokenRes = await fetch(`${BASE_URL}/api/v1/receipts/${receiptAId}?share=true&share_token=wrong_token_xyz`);
    assert.equal(wrongTokenRes.status, 403);

    // 2. Valid share_token grants read access (fetch receipt directly as owner first if shareable_token omitted on eval response)
    let tokenToTest = shareTokenA;
    if (!tokenToTest) {
      const ownerRcpt = await (await fetch(`${BASE_URL}/api/v1/receipts/${receiptAId}`, { headers: tenantA.headers })).json();
      tokenToTest = ownerRcpt.shareable_token;
    }
    assert.ok(tokenToTest, 'Receipt must carry a cryptographic shareable_token');

    const validShareRes = await fetch(
      `${BASE_URL}/api/v1/receipts/${receiptAId}?share=true&share_token=${encodeURIComponent(tokenToTest)}`
    );
    assert.equal(validShareRes.status, 200);

    // 3. Public verifier endpoint works cleanly & strips sensitive fields
    const pubVerify = await fetch(`${BASE_URL}/api/v1/public/verify/${receiptAId}`);
    assert.equal(pubVerify.status, 200);
    const pubData = await pubVerify.json();
    assert.equal(pubData.verification.verified, true);
    assert.equal(pubData.tenant_id, undefined);

    // 4. Cryptographic Audit Chain Verification
    const chainRes = await fetch(`${BASE_URL}/api/v1/audits/verify-chain`, {
      headers: tenantA.headers,
    });
    assert.equal(chainRes.status, 200);
    const chainData = await chainRes.json();
    assert.equal(chainData.verified, true);
  });

  test('SEC-06: SSRF Defense blocks localhost, RFC1918, cloud metadata & integer/hex IP bypasses on Webhooks & Radar Sources', async () => {
    const evilUrls = [
      'http://127.0.0.1:8080/admin',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/internal',
      'http://2130706433/admin', // decimal 127.0.0.1
      'http://0x7f000001/admin', // hex 127.0.0.1
    ];

    for (const url of evilUrls) {
      const whRes = await fetch(`${BASE_URL}/api/v1/alert-webhooks`, {
        method: 'POST',
        headers: tenantA.headers,
        body: JSON.stringify({ name: 'Evil SSRF Webhook', target_url: url }),
      });
      assert.equal(whRes.status, 400, `Alert webhook SSRF URL ${url} must be rejected with 400`);

      const radarRes = await fetch(`${BASE_URL}/api/v1/radar/sources`, {
        method: 'POST',
        headers: tenantA.headers,
        body: JSON.stringify({
          name: 'Evil SSRF Radar',
          source_type: 'HTTP_POLL',
          endpoint_url: url,
        }),
      });
      assert.equal(radarRes.status, 400, `Radar source SSRF URL ${url} must be rejected with 400`);
    }
  });

  test('SEC-07: Data-Flow Leakage Guard & Live MCP JSON-RPC Parity', async () => {
    // Data flow policy blocks restricted SSN (HTTP 403) without leaking raw SSN
    const evalSsn = await fetch(`${BASE_URL}/api/v1/data-flow/evaluate`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({
        destination: 'https://external.example.com/webhook',
        payload: { ssn: '123-45-6789', email: 'alice@example.com' },
      }),
    });
    assert.equal(evalSsn.status, 403);
    const df = await evalSsn.json();
    assert.equal(df.decision, 'BLOCK');
    assert.equal(JSON.stringify(df.sanitized_payload || {}).includes('123-45-6789'), false);

    // Live MCP JSON-RPC initialize & tools/list with real Bearer token
    const initRes = await fetch(`${BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'audit-1',
        method: 'initialize',
        params: { protocolVersion: '2024-11-05' },
      }),
    });
    assert.equal(initRes.status, 200);
    const initJson = await initRes.json();
    assert.equal(initJson.result.serverInfo.name, 'cck-mcp-server');

    const toolsRes = await fetch(`${BASE_URL}/api/v1/mcp`, {
      method: 'POST',
      headers: tenantA.headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: 'audit-2', method: 'tools/list', params: {} }),
    });
    assert.equal(toolsRes.status, 200);
    const toolsJson = await toolsRes.json();
    assert.ok(Array.isArray(toolsJson.result.tools) && toolsJson.result.tools.length >= 3);
  });
});
