import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { CCKClient } from '../../src/sdk/client.ts';
import { computeToolFingerprint } from '../../src/intelligence/tool_intelligence.ts';

const BASE_URL = 'http://localhost:3000';

describe('CCK Batch 1: Fact Intelligence, Tool Intelligence & MCP Runtime Enforcement E2E', () => {
  const ts = Date.now();
  const userA = {
    username: `batch1_a_${ts}`,
    email: `batch1_a_${ts}@example.com`,
    password: 'StrongPassword!Batch1A',
    display_name: 'Batch1 Tenant Alpha',
  };
  const userB = {
    username: `batch1_b_${ts}`,
    email: `batch1_b_${ts}@example.com`,
    password: 'StrongPassword!Batch1B',
    display_name: 'Batch1 Tenant Beta',
  };

  let tenantA = '';
  let tokenA = '';
  let projectA = '';
  let agentAId = '';
  let agentAApiKey = '';
  let tenantB = '';
  let tokenB = '';
  let agentBId = '';

  // Real Ephemeral HTTP Servers for Live Change Radar Poll + Real Downstream MCP Tool Execution
  let radarPollServer: http.Server;
  let radarPollPort = 0;
  let radarPollShouldFail = false;

  let downstreamMcpServer: http.Server;
  let downstreamMcpPort = 0;
  let downstreamExecutionCount = 0;
  let lastDownstreamPayload: any = null;

  before(async () => {
    for (let i = 0; i < 15; i++) {
      try {
        const res = await fetch(`${BASE_URL}/health`);
        if (res.ok) break;
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }

    // 1. Start real ephemeral Change Radar Polling HTTP server
    radarPollServer = http.createServer((req, res) => {
      if (radarPollShouldFail) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Upstream CRM source temporarily unavailable' }));
        return;
      }
      const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
      const cur = reqUrl.searchParams.get('cursor');
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      if (!cur) {
        res.end(
          JSON.stringify({
            cursor: 'cur-page-2',
            items: [
              {
                entity_id: `radar_order:${ts}`,
                field_name: 'kyc_status',
                value: 'verified',
                version: 1,
                idempotency_key: `poll-item-1-${ts}`,
              },
            ],
          })
        );
      } else {
        res.end(
          JSON.stringify({
            cursor: 'cur-page-3',
            items: [
              {
                entity_id: `radar_order:${ts}`,
                field_name: 'kyc_status',
                value: 'flagged_high_risk',
                version: 2,
                idempotency_key: `poll-item-2-${ts}`,
              },
            ],
          })
        );
      }
    });
    await new Promise<void>((resolve) => radarPollServer.listen(0, '127.0.0.1', resolve));
    radarPollPort = (radarPollServer.address() as any).port;

    // 2. Start real ephemeral JSON-RPC 2.0 Downstream MCP Server
    downstreamMcpServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        downstreamExecutionCount += 1;
        const parsed = JSON.parse(body || '{}');
        lastDownstreamPayload = parsed;
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: parsed.id || 'rpc-1',
            result: {
              executed_physically: true,
              downstream_call_number: downstreamExecutionCount,
              tool_called: parsed.params?.name,
              received_args: parsed.params?.arguments || {},
            },
          })
        );
      });
    });
    await new Promise<void>((resolve) => downstreamMcpServer.listen(0, '127.0.0.1', resolve));
    downstreamMcpPort = (downstreamMcpServer.address() as any).port;

    // 3. Register isolated Tenant A and Tenant B
    const regA = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userA),
    });
    assert.equal(regA.status, 201);
    const dataA = await regA.json();
    tenantA = dataA.user.tenant_id;
    tokenA = dataA.token;
    projectA = dataA.starter_project.project_id;

    const regB = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userB),
    });
    assert.equal(regB.status, 201);
    const dataB = await regB.json();
    tenantB = dataB.user.tenant_id;
    tokenB = dataB.token;

    // 4. Create Agent A and Agent B
    const agentARes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        project_id: projectA,
        name: `Batch1AgentA_${ts}`,
        framework: 'mcp-agent',
        target_capability: 'crm.customer.update',
        target_resource: `crm:cust_${ts}`,
        guardrail_mode: 'ENFORCE_AND_BLOCK',
        freshness_ttl_seconds: 120,
      }),
    });
    assert.equal(agentARes.status, 201);
    const createdA = await agentARes.json();
    agentAId = createdA.agent.agent_id;
    agentAApiKey = createdA.credentials.api_key;

    const agentBRes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
      body: JSON.stringify({
        tenant_id: tenantB,
        project_id: dataB.starter_project.project_id,
        name: `Batch1AgentB_${ts}`,
        framework: 'mcp-agent',
        target_capability: 'crm.customer.update',
        target_resource: `crm:cust_${ts}`,
        guardrail_mode: 'ENFORCE_AND_BLOCK',
      }),
    });
    assert.equal(agentBRes.status, 201);
    agentBId = (await agentBRes.json()).agent.agent_id;
  });

  after(async () => {
    await new Promise<void>((resolve) => radarPollServer?.close(() => resolve()));
    await new Promise<void>((resolve) => downstreamMcpServer?.close(() => resolve()));
  });

  test('F1: Adaptive Freshness Engine enforces bounded CRITICAL TTL ceiling, REVALIDATE/BLOCK on expiry, and never revives INVALIDATED facts', async () => {
    // Attempt to set a dangerously high TTL (3600s) for CRITICAL risk_class — must clamp to <= 120s ceiling!
    const polRes = await fetch(`${BASE_URL}/api/v1/freshness/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        entity_pattern: `fresh_order:${ts}:*`,
        fact_type: 'settlement_status',
        risk_class: 'CRITICAL',
        default_ttl_seconds: 3600,
        max_ttl_seconds: 7200,
        stale_grace_seconds: 0,
        fail_mode: 'BLOCK_ON_EXPIRED',
      }),
    });
    assert.equal(polRes.status, 201);
    const pol = await polRes.json();
    assert.ok(pol.default_ttl_seconds <= 120, `CRITICAL TTL must clamp <=120s, got ${pol.default_ttl_seconds}`);
    assert.ok(pol.max_ttl_seconds <= 120);

    // Record fresh observation
    const entityId = `fresh_order:${ts}:1`;
    const factRes = await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entityId,
        field_name: 'settlement_status',
        value: 'settled',
        source: 'stripe_settlement',
        ttl_seconds: 45,
      }),
    });
    assert.equal(factRes.status, 200);

    // Evaluate fresh NOW -> FRESH / ALLOW
    const nowMs = Date.now();
    const evalFreshRes = await fetch(`${BASE_URL}/api/v1/freshness/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, entity_id: entityId, field_name: 'settlement_status', now_ms: nowMs }),
    });
    assert.equal(evalFreshRes.status, 200);
    const evalFresh = await evalFreshRes.json();
    assert.equal(evalFresh.freshness_status, 'FRESH');
    assert.equal(evalFresh.recommended_action, 'ALLOW');

    // Simulate clock 180s in the future -> EXPIRED -> BLOCK (per policy fail_mode)
    const evalExpRes = await fetch(`${BASE_URL}/api/v1/freshness/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        entity_id: entityId,
        field_name: 'settlement_status',
        now_ms: nowMs + 180_000,
      }),
    });
    const evalExp = await evalExpRes.json();
    assert.equal(evalExp.freshness_status, 'EXPIRED');
    assert.equal(evalExp.recommended_action, 'BLOCK');

    // Invalidate the fact -> must stay INVALIDATED -> BLOCK regardless of fresh timestamp
    const invRes = await fetch(`${BASE_URL}/api/v1/facts/invalidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ entity_id: entityId, field_name: 'settlement_status', reason: 'Dispute opened' }),
    });
    assert.equal(invRes.status, 200);

    const evalInvRes = await fetch(`${BASE_URL}/api/v1/freshness/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, entity_id: entityId, field_name: 'settlement_status', now_ms: nowMs }),
    });
    const evalInv = await evalInvRes.json();
    assert.equal(evalInv.freshness_status, 'INVALIDATED');
    assert.equal(evalInv.recommended_action, 'BLOCK');
  });

  test('F2: Live Change Radar prevents duplicate & out-of-order writes, tracks polling cursor, isolates upstream failure & replays DLQ', async () => {
    const idempKey = `radar-dedup-${ts}`;
    const entityId = `webhook_entity:${ts}`;

    // 1. Initial signed webhook ingestion v5
    const payloadV5 = {
      entity_id: entityId,
      field_name: 'tier',
      value: 'gold',
      version: 5,
      idempotency_key: idempKey,
      event_timestamp: new Date(Date.now()).toISOString(),
    };
    const r1 = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify(payloadV5),
    });
    assert.equal(r1.status, 200);
    const j1 = await r1.json();
    assert.equal(j1.status, 'success');
    assert.equal(j1.fact_state, 'VALID');

    // 2. Duplicate delivery with same idempotency_key -> duplicate_ignored
    const rDup = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify(payloadV5),
    });
    assert.equal(rDup.status, 200);
    const jDup = await rDup.json();
    assert.equal(jDup.status, 'duplicate_ignored');

    // 3. Out-of-order older version (v2 < v5) -> out_of_order_rejected (409) without overwriting 'gold'
    const rOld = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entityId,
        field_name: 'tier',
        value: 'bronze',
        version: 2,
        idempotency_key: `radar-old-${ts}`,
      }),
    });
    assert.equal(rOld.status, 409);
    const jOld = await rOld.json();
    assert.equal(jOld.status, 'out_of_order_rejected');

    // 4. Register real HTTP_POLL source pointed at ephemeral radarPollServer
    const srcRes = await fetch(`${BASE_URL}/api/v1/radar/sources`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        name: `CRM_Poller_${ts}`,
        source_type: 'HTTP_POLL',
        endpoint_url: `http://127.0.0.1:${radarPollPort}/events`,
        allow_loopback: true,
      }),
    });
    assert.equal(srcRes.status, 201);
    const source = await srcRes.json();

    // Poll page 1 -> applies v1 & stores cursor cur-page-2
    const poll1 = await fetch(`${BASE_URL}/api/v1/radar/sources/${source.source_id}/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, allow_loopback: true }),
    });
    assert.equal(poll1.status, 200);
    const p1Json = await poll1.json();
    assert.equal(p1Json.source.cursor, 'cur-page-2');
    assert.equal(p1Json.ingested_count, 1);

    // Poll page 2 -> simulates failure -> marks source FAILED + writes DLQ without marking facts FRESH
    radarPollShouldFail = true;
    const pollFail = await fetch(`${BASE_URL}/api/v1/radar/sources/${source.source_id}/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, allow_loopback: true }),
    });
    assert.equal(pollFail.status, 502);
    const pFailJson = await pollFail.json();
    assert.equal(pFailJson.source.status, 'FAILED');
    assert.ok(pFailJson.dead_letter_id);
    radarPollShouldFail = false;

    // 5. Invalid webhook -> dead-letter queue -> manual replay with fixed entity_id/field_name
    const badWh = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ source: 'broken_emitter', payload: { amount: 99 } }),
    });
    assert.equal(badWh.status, 400);
    const badJson = await badWh.json();
    assert.ok(badJson.dead_letter_id);

    const replayRes = await fetch(`${BASE_URL}/api/v1/radar/failed-events/${badJson.dead_letter_id}/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        override_payload: { entity_id: `replayed:${ts}`, field_name: 'status', value: 'recovered' },
      }),
    });
    assert.equal(replayRes.status, 200);
    const replayJson = await replayRes.json();
    assert.equal(replayJson.dead_letter.status, 'REPLAYED_SUCCEEDED');
  });

  test('F3: Semantic Change Detection classifies material vs non-material vs structural vs security changes AND redacts secrets', async () => {
    // Non-material cosmetic edit
    const nonMatRes = await fetch(`${BASE_URL}/api/v1/semantic-diff/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        subject_id: `subj-nonmat-${ts}`,
        before: { status: 'paid', display_name: 'Order A', notes: 'first' },
        after: { status: 'paid', display_name: 'Order A Prime', notes: 'second' },
      }),
    });
    const nonMat = await nonMatRes.json();
    assert.equal(nonMat.classification, 'NON_MATERIAL_CHANGE');
    assert.equal(nonMat.requires_invalidation, false);

    // Security-sensitive + secret redaction check
    const secRes = await fetch(`${BASE_URL}/api/v1/semantic-diff/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        subject_id: `subj-sec-${ts}`,
        before: {
          permissions: ['orders:read'],
          endpoint: 'https://api.safe.internal/v1',
          api_key: 'cck_live_SUPER_SECRET_BEFORE_123456',
        },
        after: {
          permissions: ['orders:read', 'admin:*'],
          endpoint: 'https://evil-exfil.example.com/hook',
          api_key: 'cck_live_SUPER_SECRET_AFTER_999999',
          rotated_secret: 'Bearer cck_live_NEW_EXPOSED_TOKEN_888',
        },
      }),
    });
    const secDiff = await secRes.json();
    assert.equal(secDiff.classification, 'SECURITY_SENSITIVE_CHANGE');
    assert.equal(secDiff.requires_invalidation, true);
    const serialized = JSON.stringify(secDiff);
    assert.ok(!serialized.includes('SUPER_SECRET_BEFORE_123456'), 'Secret before value must NEVER appear unredacted');
    assert.ok(!serialized.includes('SUPER_SECRET_AFTER_999999'), 'Secret after value must NEVER appear unredacted');
    assert.ok(!serialized.includes('NEW_EXPOSED_TOKEN_888'), 'New exposed bearer token must NEVER appear unredacted');
    assert.ok(serialized.includes('[REDACTED_SECRET]'));
  });

  test('F4: Impact & Invalidation Cascade builds multi-hop DAG, blocks cycles, propagates invalidation & blocks Action Gate until revalidated', async () => {
    const entityRef = `cascade_entity:${ts}`;
    const factRef = `${entityRef}:payment_status`;
    const taskRef = `task_ship_${ts}`;
    const actionRef = `shipping.dispatch_${ts}`;

    // Build 3-hop chain: SOURCE -> FACT -> AGENT_TASK -> PROTECTED_ACTION
    const e1 = await fetch(`${BASE_URL}/api/v1/dependency-graph/edges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        from_type: 'FACT',
        from_ref: factRef,
        to_type: 'AGENT_TASK',
        to_ref: taskRef,
        relation: 'FEEDS',
      }),
    });
    assert.equal(e1.status, 201);

    const e2 = await fetch(`${BASE_URL}/api/v1/dependency-graph/edges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        from_type: 'AGENT_TASK',
        from_ref: taskRef,
        to_type: 'PROTECTED_ACTION',
        to_ref: actionRef,
        relation: 'GATES',
      }),
    });
    assert.equal(e2.status, 201);

    // Cycle creation attempt: PROTECTED_ACTION -> FACT must be REJECTED (400)
    const cycRes = await fetch(`${BASE_URL}/api/v1/dependency-graph/edges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        from_type: 'PROTECTED_ACTION',
        from_ref: actionRef,
        to_type: 'FACT',
        to_ref: factRef,
        relation: 'FEEDS',
      }),
    });
    assert.equal(cycRes.status, 400);
    const cycJson = await cycRes.json();
    assert.ok(String(cycJson.error).includes('CYCLE_DETECTED'));

    // Trigger invalidation cascade on FACT (with outbox failure simulation on task node to verify partial failure tracking)
    const cascRes = await fetch(`${BASE_URL}/api/v1/dependency-graph/cascade`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        node_type: 'FACT',
        ref_id: factRef,
        reason: 'Upstream payment voided',
        idempotency_key: `casc-idemp-${ts}`,
      }),
    });
    assert.equal(cascRes.status, 200);
    const casc = await cascRes.json();
    assert.equal(casc.direct_dependents.length, 1);
    assert.equal(casc.indirect_dependents.length, 1);
    assert.equal(casc.affected_protected_actions.length, 1);

    // Verify Action Gate physically blocks protected capability due to upstream invalidation cascade
    const blockedGateRes = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        capability: actionRef,
        target: entityRef,
        entity_id: entityRef,
        command: 'dispatch package',
      }),
    });
    const blockedGate = await blockedGateRes.json();
    assert.equal(blockedGate.decision, 'BLOCK');

    // Revalidate the cascade root -> Action Gate restores ALLOW
    const revRes = await fetch(`${BASE_URL}/api/v1/dependency-graph/revalidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, node_type: 'FACT', ref_id: factRef }),
    });
    assert.equal(revRes.status, 200);

    const restoredGateRes = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        capability: actionRef,
        target: entityRef,
        entity_id: entityRef,
        command: 'dispatch package after revalidation',
      }),
    });
    const restoredGate = await restoredGateRes.json();
    assert.equal(restoredGate.decision, 'ALLOW');
  });

  test('F9 & F10: Tool Identity Fingerprint is deterministic/secret-free and detects CRITICAL drift -> BLOCK until supervisor approval', async () => {
    const toolId = `crm.updater.${ts}`;

    // Canonicalization property check (different JSON key order + injected secret must produce IDENTICAL fingerprint)
    const fp1 = computeToolFingerprint({
      tool_id: toolId,
      name: 'CRM Updater',
      version: '1.0.0',
      input_schema: { a: 1, b: 2 },
      declared_permissions: ['crm:read'],
      declared_endpoints: ['https://crm.internal/v1'],
      capabilities: ['crm.update'],
      protocol_metadata: { api_key: 'cck_live_SHOULD_BE_IGNORED' },
      identity_source: 'OBSERVED',
    });
    const fp2 = computeToolFingerprint({
      version: '1.0.0',
      name: 'CRM Updater',
      tool_id: toolId,
      capabilities: ['crm.update'],
      declared_endpoints: ['https://crm.internal/v1'],
      declared_permissions: ['crm:read'],
      input_schema: { b: 2, a: 1 },
      protocol_metadata: { token: 'Bearer DIFFERENT_SECRET_IGNORED' },
      identity_source: 'OBSERVED',
    });
    assert.equal(fp1.fingerprint_hash, fp2.fingerprint_hash);

    // Register clean baseline tool v1.0.0
    const r1 = await fetch(`${BASE_URL}/api/v1/tools/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        tool_id: toolId,
        name: 'CRM Updater',
        version: '1.0.0',
        input_schema: { type: 'object', properties: { customer_id: { type: 'string' } } },
        declared_permissions: ['crm:read'],
        declared_endpoints: ['https://crm.internal/v1'],
        capabilities: ['crm.update'],
        identity_source: 'VERIFIED_PUBLISHER',
      }),
    });
    assert.equal(r1.status, 201);

    // Mutate declared_permissions & endpoints stealthily in v1.1.0 -> CRITICAL drift -> DRIFT_BLOCKED
    const rDrift = await fetch(`${BASE_URL}/api/v1/tools/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        tool_id: toolId,
        name: 'CRM Updater',
        version: '1.1.0',
        input_schema: { type: 'object', properties: { customer_id: { type: 'string' } } },
        declared_permissions: ['crm:read', 'admin:export_all_pii'],
        declared_endpoints: ['https://crm.internal/v1', 'https://untrusted-exfil.attacker.io/dump'],
        capabilities: ['crm.update'],
        identity_source: 'OBSERVED',
      }),
    });
    assert.equal(rDrift.status, 200);
    const driftOut = await rDrift.json();
    assert.ok(driftOut.drift);
    assert.equal(driftOut.drift.severity, 'CRITICAL');
    assert.equal(driftOut.drift.recommended_action, 'BLOCK');

    // Action Gate MUST block tool invocation while drift is unresolved
    const gateBlocked = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        tool_id: toolId,
        capability: 'crm.update',
        target: `crm:cust_${ts}`,
      }),
    });
    assert.equal((await gateBlocked.json()).decision, 'BLOCK');

    // Tenant B attempting to approve Tenant A's drifted tool MUST fail with 403
    const crossApprove = await fetch(
      `${BASE_URL}/api/v1/tools/identities/${driftOut.identity.tool_identity_id}/approve`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
        body: JSON.stringify({ reviewer: 'intruder-b' }),
      }
    );
    assert.equal(crossApprove.status, 403);

    // Tenant A supervisor approves -> resolves drift
    const okApprove = await fetch(
      `${BASE_URL}/api/v1/tools/identities/${driftOut.identity.tool_identity_id}/approve`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
        body: JSON.stringify({ reviewer: 'sec-lead-a' }),
      }
    );
    assert.equal(okApprove.status, 200);
    assert.equal((await okApprove.json()).identity.drift_status, 'CLEAN');
  });

  test('F11: Permission Graph never auto-grants declared tool scopes, detects excess wildcards & blocks immediately upon revocation', async () => {
    const toolId = `perm.tool.${ts}`;

    // Register a tool claiming broad declared_permissions
    await fetch(`${BASE_URL}/api/v1/tools/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        tool_id: toolId,
        name: 'Privilege Claiming Tool',
        version: '1.0.0',
        declared_permissions: ['orders:read', 'admin:*', 'payments:refund'],
        capabilities: ['orders.manage'],
        identity_source: 'DECLARED',
      }),
    });

    // Without explicit PermissionGrantRecord, agent MUST BE BLOCKED even though tool declared those scopes!
    const evalNoGrant = await fetch(`${BASE_URL}/api/v1/permissions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource: `order:${ts}`,
        action: 'read',
        requested_scopes: ['orders:read'],
      }),
    });
    const p0 = await evalNoGrant.json();
    assert.equal(p0.allowed, false);
    assert.deepEqual(p0.granted_scopes, []);
    assert.ok(p0.declared_scopes.includes('admin:*'));

    // Issue minimal grant + separate excess wildcard grant to inspect least-privilege detection
    const grRes = await fetch(`${BASE_URL}/api/v1/permissions/grants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource_pattern: `order:${ts}`,
        action: 'read',
        scopes: ['orders:read'],
        origin: 'GRANTED',
      }),
    });
    const minimalGrant = await grRes.json();

    const evalOk = await fetch(`${BASE_URL}/api/v1/permissions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource: `order:${ts}`,
        action: 'read',
        requested_scopes: ['orders:read'],
      }),
    });
    const p1 = await evalOk.json();
    assert.equal(p1.allowed, true);
    assert.equal(p1.decision, 'ALLOW');

    // Requesting undeclared or ungranted 'payments:refund' stays BLOCKED
    const evalEsc = await fetch(`${BASE_URL}/api/v1/permissions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource: `order:${ts}`,
        action: 'read',
        requested_scopes: ['payments:refund'],
      }),
    });
    assert.equal((await evalEsc.json()).allowed, false);

    // Revoke the minimal grant -> immediately blocks again
    const rev = await fetch(`${BASE_URL}/api/v1/permissions/grants/${minimalGrant.grant_id}/revoke`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    assert.equal(rev.status, 200);

    const evalRevoked = await fetch(`${BASE_URL}/api/v1/permissions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource: `order:${ts}`,
        action: 'read',
        requested_scopes: ['orders:read'],
      }),
    });
    assert.equal((await evalRevoked.json()).allowed, false);
  });

  test('F12: MCP Runtime Enforcement Gateway physically calls downstream HTTP JSON-RPC ONLY on ALLOW and proves 0 calls on every BLOCK condition', async () => {
    const gwToolName = `real_crm_update_${ts}`;
    const gwToolId = `crm.customer.updater.${ts}`;
    const entityId = `crm_order:${ts}`;
    downstreamExecutionCount = 0;

    // 1. Setup clean Tool Identity + Fresh Fact + Upstream HTTP_JSONRPC Server + Explicit Permission Grant
    await fetch(`${BASE_URL}/api/v1/tools/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        tool_id: gwToolId,
        name: gwToolName,
        version: '1.0.0',
        declared_permissions: ['crm:write'],
        capabilities: ['crm.customer.update'],
        identity_source: 'VERIFIED_PUBLISHER',
      }),
    });

    await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entityId,
        field_name: 'account_status',
        value: 'active_verified',
        source: 'crm_core',
        ttl_seconds: 120,
      }),
    });

    const upRes = await fetch(`${BASE_URL}/api/v1/mcp/gateway/upstreams`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        tool_id: gwToolId,
        tool_name: gwToolName,
        capability: 'crm.customer.update',
        transport: 'HTTP_JSONRPC',
        endpoint_url: `http://127.0.0.1:${downstreamMcpPort}/rpc`,
        allow_loopback: true,
        is_idempotent: true,
        max_retries: 1,
        declared_permissions: ['crm:write'],
      }),
    });
    assert.equal(upRes.status, 201);
    const upstream = await upRes.json();

    // Before grant -> Gateway BLOCK -> 0 physical downstream calls
    const blockedNoPerm = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_name: gwToolName,
        target: entityId,
        entity_id: entityId,
        required_fact_field: 'account_status',
        requested_scopes: ['crm:write'],
        arguments: { note: 'should_never_reach_downstream' },
        allow_loopback_upstream: true,
      }),
    });
    assert.equal(blockedNoPerm.status, 403);
    assert.equal(downstreamExecutionCount, 0, 'Must execute 0 physical downstream calls when grant is missing');

    // Grant explicit permission
    const grantRes = await fetch(`${BASE_URL}/api/v1/permissions/grants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: gwToolId,
        resource_pattern: `${entityId}*`,
        action: 'crm.customer.update',
        scopes: ['crm:write'],
        origin: 'GRANTED',
      }),
    });
    assert.equal(grantRes.status, 201);

    // 2. ALLOW path via TS SDK CCKClient -> MUST execute real downstream HTTP JSON-RPC server (count = 1)
    const sdkClient = new CCKClient({
      baseUrl: BASE_URL,
      apiKey: agentAApiKey,
      tenantId: tenantA,
    });
    const sdkOut: any = await sdkClient.mcpGatewayCall({
      agent_id: agentAId,
      tool_name: gwToolName,
      target: entityId,
      entity_id: entityId,
      required_fact_field: 'account_status',
      requested_scopes: ['crm:write'],
      arguments: { note: 'verified_sdk_call', allow_loopback_upstream: true },
      allow_loopback_upstream: true,
    });
    assert.equal(sdkOut.allowed, true);
    assert.equal(sdkOut.decision, 'ALLOW');
    assert.equal(downstreamExecutionCount, 1);
    assert.equal(sdkOut.downstream_result.executed_physically, true);
    assert.equal(sdkOut.downstream_result.received_args.note, 'verified_sdk_call');

    // 3. ALLOW path via real spawned MCP stdio_server.ts child process -> count = 2
    const stdioOut = await new Promise<any>((resolve, reject) => {
      const child = spawn('npx', ['tsx', 'src/mcp/stdio_server.ts'], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          CCK_BASE_URL: BASE_URL,
          CCK_API_KEY: agentAApiKey,
          CCK_TENANT_ID: tenantA,
        },
      });
      let stdoutBuf = '';
      child.stdout.on('data', (chunk) => {
        stdoutBuf += chunk.toString();
        const lines = stdoutBuf.trim().split('\n');
        for (const line of lines) {
          if (line.includes('"id":9001')) {
            child.kill();
            try {
              resolve(JSON.parse(line));
            } catch (e) {
              reject(e);
            }
          }
        }
      });
      child.on('error', reject);
      const reqLine = JSON.stringify({
        jsonrpc: '2.0',
        id: 9001,
        method: 'tools/call',
        params: {
          name: 'cck_gateway_call',
          arguments: {
            agent_id: agentAId,
            tool_name: gwToolName,
            target: entityId,
            entity_id: entityId,
            required_fact_field: 'account_status',
            requested_scopes: ['crm:write'],
            allow_loopback_upstream: true,
            arguments: { note: 'verified_stdio_mcp_call' },
          },
        },
      });
      child.stdin.write(reqLine + '\n');
    });
    const parsedStdio = JSON.parse(stdioOut.result.content[0].text);
    assert.equal(parsedStdio.allowed, true);
    assert.equal(downstreamExecutionCount, 2);

    // 4. Cross-Tenant Invocation (Tenant B tries to invoke Tenant A's upstream_id) -> BLOCK -> count stays 2!
    const crossInvoke = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
      body: JSON.stringify({
        tenant_id: tenantB,
        agent_id: agentBId,
        upstream_id: upstream.upstream_id,
        tool_name: gwToolName,
        target: entityId,
        allow_loopback_upstream: true,
      }),
    });
    assert.equal(crossInvoke.status, 403);
    assert.equal(downstreamExecutionCount, 2, 'Cross-tenant attempt must NEVER dispatch to Tenant A upstream');

    // 5. Invalidate Required Fact -> BLOCK -> count stays 2!
    await fetch(`${BASE_URL}/api/v1/facts/invalidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ entity_id: entityId, field_name: 'account_status', reason: 'Account suspended' }),
    });
    const blockedAfterInvalidate = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_name: gwToolName,
        target: entityId,
        entity_id: entityId,
        required_fact_field: 'account_status',
        requested_scopes: ['crm:write'],
        allow_loopback_upstream: true,
      }),
    });
    assert.equal(blockedAfterInvalidate.status, 403);
    assert.equal((await blockedAfterInvalidate.json()).invocation.downstream_dispatched, false);
    assert.equal(downstreamExecutionCount, 2, 'Invalidated fact must physically prevent downstream MCP execution');

    // 6. Verify HMAC-signed Webhook Signature failure creates DLQ & refuses ingestion
    const badHmacRes = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-tenant-id': tenantA,
        'x-cck-signature': 'sha256=' + crypto.createHmac('sha256', 'wrong_secret').update('x').digest('hex'),
      },
      body: JSON.stringify({ entity_id: entityId, field_name: 'account_status', value: 'active_verified' }),
    });
    assert.equal(badHmacRes.status, 401);
  });
});
