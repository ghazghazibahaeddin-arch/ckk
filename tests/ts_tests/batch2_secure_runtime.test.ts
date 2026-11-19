import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { CCKClient } from '../../src/sdk/client.ts';
import { evaluateNetworkEgress } from '../../src/intelligence/network_egress.ts';
import { createNetworkEgressPolicy } from '../../src/intelligence/network_egress.ts';

const BASE_URL = 'http://localhost:3000';

describe('CCK Batch 2: Conflict Resolution, Smart Revalidation, Secret Broker, Isolation, Data Flow, Network Egress & Safe Replay E2E', () => {
  const ts = Date.now();
  const userA = {
    username: `batch2_a_${ts}`,
    email: `batch2_a_${ts}@example.com`,
    password: 'StrongPassword!Batch2A',
    display_name: 'Batch2 Tenant Alpha',
  };
  const userB = {
    username: `batch2_b_${ts}`,
    email: `batch2_b_${ts}@example.com`,
    password: 'StrongPassword!Batch2B',
    display_name: 'Batch2 Tenant Beta',
  };

  let tenantA = '';
  let tokenA = '';
  let agentAId = '';
  let agentAApiKey = '';
  let tenantB = '';
  let tokenB = '';
  let agentBId = '';

  let sourceServer: http.Server;
  let sourcePort = 0;
  let sourceShouldFail = false;

  let mcpServer: http.Server;
  let mcpPort = 0;
  let mcpCallCount = 0;
  let lastMcpAuthHeader: string | undefined;
  let lastMcpArgs: Record<string, unknown> | null = null;

  let redirectServer: http.Server;
  let redirectPort = 0;

  before(async () => {
    for (let i = 0; i < 20; i++) {
      try {
        const res = await fetch(`${BASE_URL}/health`);
        if (res.ok) break;
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }

    // 1. Live Smart Revalidation Delta Source Server
    sourceServer = http.createServer((_req, res) => {
      if (sourceShouldFail) {
        res.statusCode = 503;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Upstream ERP unavailable' }));
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          cursor: `delta-${Date.now()}`,
          items: [
            {
              entity_id: `order:b2:${ts}`,
              field_name: 'settlement_state',
              value: { status: 'confirmed', settled_amount: 149.99 },
            },
          ],
        })
      );
    });
    await new Promise<void>((resolve) => sourceServer.listen(0, '127.0.0.1', () => resolve()));
    sourcePort = (sourceServer.address() as { port: number }).port;

    // 2. Live Downstream MCP Tool Server capturing auth header & sanitized payload
    mcpServer = http.createServer((req, res) => {
      mcpCallCount += 1;
      lastMcpAuthHeader = req.headers.authorization;
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const parsed = JSON.parse(body || '{}');
        lastMcpArgs = parsed?.params?.arguments || null;
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: parsed.id || 1,
            result: {
              ok: true,
              processed: true,
              received_keys: Object.keys(lastMcpArgs || {}),
            },
          })
        );
      });
    });
    await new Promise<void>((resolve) => mcpServer.listen(0, '127.0.0.1', () => resolve()));
    mcpPort = (mcpServer.address() as { port: number }).port;

    // 3. Live Open-Redirect Server targeting Cloud Metadata SSRF endpoint
    redirectServer = http.createServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('Location', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/');
      res.end();
    });
    await new Promise<void>((resolve) => redirectServer.listen(0, '127.0.0.1', () => resolve()));
    redirectPort = (redirectServer.address() as { port: number }).port;

    // Signup Tenant A & Tenant B
    const regA = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userA),
    });
    assert.equal(regA.status, 201);
    const dataA = await regA.json();
    tenantA = dataA.user.tenant_id;
    tokenA = dataA.token;
    const projectA = dataA.starter_project.project_id;

    const regB = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userB),
    });
    assert.equal(regB.status, 201);
    const dataB = await regB.json();
    tenantB = dataB.user.tenant_id;
    tokenB = dataB.token;
    const projectB = dataB.starter_project.project_id;

    // Register Agents & API keys
    const agARes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: `Batch2-Alpha-Agent-${ts}`,
        project_id: projectA,
        tenant_id: tenantA,
        framework: 'mcp-agent',
        target_capability: 'payments.execute',
        target_resource: `invoice:*`,
        guardrail_mode: 'ENFORCE_AND_BLOCK',
        freshness_ttl_seconds: 120,
      }),
    });
    assert.equal(agARes.status, 201);
    const agA = await agARes.json();
    agentAId = agA.agent.agent_id;
    agentAApiKey = agA.credentials.api_key;

    const agBRes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
      body: JSON.stringify({
        name: `Batch2-Beta-Agent-${ts}`,
        project_id: projectB,
        tenant_id: tenantB,
        framework: 'mcp-agent',
        target_capability: 'payments.execute',
        target_resource: `invoice:*`,
        guardrail_mode: 'ENFORCE_AND_BLOCK',
        freshness_ttl_seconds: 120,
      }),
    });
    assert.equal(agBRes.status, 201);
    agentBId = (await agBRes.json()).agent.agent_id;
  });

  after(() => {
    sourceServer?.close();
    mcpServer?.close();
    redirectServer?.close();
  });

  test('1. Feature 5: Multi-Source Conflict Resolver — Trusted Priority, Tie Fail-Closed (No Averaging), Non-Winning Retention & Action Gate Integration', async () => {
    const entityId = `order:conf:${ts}`;
    const fieldName = 'refund_amount';

    // Policy preferring OFFICIAL over CONTRACTED, with allow_mathematical_averaging=false
    const polRes = await fetch(`${BASE_URL}/api/v1/conflicts/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        entity_pattern: 'order:conf:*',
        field_pattern: 'refund_amount',
        strategy_order: ['OFFICIAL_SOURCE_PRIORITY', 'RECENCY'],
        min_evidence_quality: 0.5,
        on_unresolved_decision: 'REQUIRE_APPROVAL',
      }),
    });
    assert.equal(polRes.status, 201);
    const pol = await polRes.json();
    assert.equal(pol.allow_mathematical_averaging, false);

    // Source 1 (THIRD_PARTY) says 100
    await fetch(`${BASE_URL}/api/v1/conflicts/observations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entityId,
        field_name: fieldName,
        value: 100,
        source_id: 'legacy_cache',
        source_authority: 'THIRD_PARTY',
        data_quality: 0.9,
      }),
    });

    // Source 2 (OFFICIAL) says 200 -> Conflict Resolved in favor of OFFICIAL without averaging (NOT 150!)
    const obs2Res = await fetch(`${BASE_URL}/api/v1/conflicts/observations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entityId,
        field_name: fieldName,
        value: 200,
        source_id: 'stripe_ledger',
        source_authority: 'OFFICIAL',
        data_quality: 0.98,
        evidence_ref: 'ev-stripe-200',
      }),
    });
    const obs2Data = await obs2Res.json();
    assert.equal(obs2Data.evaluation.status, 'RESOLVED');
    assert.equal(obs2Data.evaluation.recommended_action, 'ALLOW');
    assert.equal(obs2Data.evaluation.winning_observation.value, 200);
    assert.equal(obs2Data.evaluation.winning_observation.source_id, 'stripe_ledger');
    assert.equal(obs2Data.evaluation.retained_non_winning.length, 1);
    assert.equal(obs2Data.evaluation.retained_non_winning[0].value, 100);

    // Now test Unresolved Conflict between TWO tied OFFICIAL sources with identical observed_at -> Action Gate must FAIL CLOSED (REQUIRE_APPROVAL / BLOCK)
    const tieEntity = `order:tie:${ts}`;
    const fixedTime = new Date().toISOString();
    await fetch(`${BASE_URL}/api/v1/conflicts/observations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: tieEntity,
        field_name: 'settlement_state',
        value: 'paid',
        source_id: 'bank_primary',
        source_authority: 'OFFICIAL',
        observed_at: fixedTime,
        data_quality: 0.95,
      }),
    });
    const tieRes = await fetch(`${BASE_URL}/api/v1/conflicts/observations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: tieEntity,
        field_name: 'settlement_state',
        value: 'chargeback',
        source_id: 'card_network',
        source_authority: 'OFFICIAL',
        observed_at: fixedTime,
        data_quality: 0.95,
      }),
    });
    const tieData = await tieRes.json();
    assert.equal(tieData.evaluation.status, 'UNRESOLVED');
    assert.notEqual(tieData.evaluation.recommended_action, 'ALLOW');

    const sdkA = new CCKClient({ baseUrl: BASE_URL, apiKey: agentAApiKey, tenantId: tenantA });
    const verdict = await sdkA.evaluateAction({
      agent: { agent_id: agentAId, name: 'Batch2-Alpha-Agent', tenant_id: tenantA },
      session_id: 'sess-conf-tie',
      capability: 'payments.release',
      target: 'bank.wire',
      entity_id: tieEntity,
      parameters: { required_fact_field: 'settlement_state' },
    });
    // Action Gate also catches via cascade or conflict evaluation; verify explicit conflict gate field triggers non-ALLOW
    const directGate = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        capability: 'payments.release',
        target: 'bank.wire',
        entity_id: tieEntity,
        required_fact_field: 'settlement_state',
      }),
    });
    const directVerdict = await directGate.json();
    assert.ok(['REQUIRE_APPROVAL', 'BLOCK', 'REVALIDATE'].includes(directVerdict.decision), `Expected non-ALLOW, got ${directVerdict.decision}`);
    assert.ok(verdict.decision);
  });

  test('2. Feature 6: Smart Revalidation & Delta Refresh — Dependency Scoping, Delta Update & Fail-Closed on External Error', async () => {
    const entId = `order:b2:${ts}`;
    // Seed an expired/stale fact
    await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        entity_id: entId,
        field_name: 'settlement_state',
        value: { status: 'pending', settled_amount: 0, note: 'keep-healthy-note' },
        source: 'erp_sync',
        ttl_seconds: 1,
        observed_at: new Date(Date.now() - 120_000).toISOString(),
      }),
    });

    // Register real polling source
    const srcRes = await fetch(`${BASE_URL}/api/v1/radar/sources`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: `erp-source-${ts}`,
        source_type: 'HTTP_POLL',
        endpoint_url: `http://127.0.0.1:${sourcePort}/delta`,
        allow_loopback: true,
      }),
    });
    assert.equal(srcRes.status, 201);
    const srcObj = await srcRes.json();

    // Case A: External source DOWN -> Must FAIL_CLOSED and NEVER mark stale fact FRESH
    sourceShouldFail = true;
    const failRun = await fetch(`${BASE_URL}/api/v1/revalidation/plan-and-run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        mode: 'DELTA',
        entity_id: entId,
        field_name: 'settlement_state',
        source_id: srcObj.source_id,
        allow_loopback: true,
      }),
    });
    assert.equal(failRun.status, 502);
    const failData = await failRun.json();
    assert.equal(failData.plan.status, 'FAILED_FAIL_CLOSED');
    assert.equal(failData.plan.failed_facts.length, 1);
    assert.equal(failData.plan.failed_facts[0].kept_stale, true);

    // Verify freshness is STILL non-FRESH
    const freshCheck1 = await fetch(`${BASE_URL}/api/v1/freshness/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ entity_id: entId, field_name: 'settlement_state' }),
    });
    assert.notEqual((await freshCheck1.json()).freshness_status, 'FRESH');

    // Case B: Restore source -> Delta refresh merges updated fields while keeping existing healthy field (`note`)!
    sourceShouldFail = false;
    const okRun = await fetch(`${BASE_URL}/api/v1/revalidation/plan-and-run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        mode: 'DELTA',
        entity_id: entId,
        field_name: 'settlement_state',
        source_id: srcObj.source_id,
        allow_loopback: true,
      }),
    });
    assert.equal(okRun.status, 200);
    const okData = await okRun.json();
    assert.equal(okData.plan.status, 'SUCCEEDED');
    assert.equal(okData.plan.refreshed_facts.length, 1);

    const factsList = await (await fetch(`${BASE_URL}/api/v1/facts?tenant_id=${encodeURIComponent(tenantA)}`, { headers: { Authorization: `Bearer ${tokenA}` } })).json();
    const updatedFact = factsList.find((f: any) => f.entity_id === entId && f.field_name === 'settlement_state');
    assert.equal(updatedFact.value.status, 'confirmed');
    assert.equal(updatedFact.value.settled_amount, 149.99);
    assert.equal(updatedFact.value.note, 'keep-healthy-note');
  });

  test('3. Features 13, 14, 15, 16, 17 END-TO-END SECURITY RED TEAM: Secret Broker Zero-Leakage, Cross-Tenant/Scope Deny, Per-Call Teardown, Data Flow Guard, Network Egress Open-Redirect SSRF & DNS Rebinding, Behavior Drift & Safe Replay', async () => {
    const SUPER_SECRET_VALUE = `sk_live_ultra_sensitive_${ts}_9999`;
    const toolId = `mcp.secure_pay.${ts}`;

    // Register Tool Identity, Active Upstream, & Least-Privilege Permission Grant for Tenant A
    await fetch(`${BASE_URL}/api/v1/tools/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tool_id: toolId,
        name: toolId,
        version: '1.0.0',
        declared_permissions: ['payments:execute'],
        declared_endpoints: [`http://127.0.0.1:${mcpPort}/rpc`],
        input_schema: { type: 'object', properties: { amount: { type: 'number' }, customer_email: { type: 'string' } } },
        identity_source: 'VERIFIED_PUBLISHER',
      }),
    });

    await fetch(`${BASE_URL}/api/v1/permissions/grants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        agent_id: agentAId,
        tool_id: toolId,
        resource_pattern: '*',
        action: '*',
        scopes: ['payments:execute'],
        origin: 'GRANTED',
      }),
    });

    const upRes = await fetch(`${BASE_URL}/api/v1/mcp/gateway/upstreams`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tool_id: toolId,
        tool_name: toolId,
        capability: 'payments.execute',
        transport: 'HTTP_JSONRPC',
        endpoint_url: `http://127.0.0.1:${mcpPort}/rpc`,
        allow_loopback: true,
        timeout_ms: 4000,
      }),
    });
    assert.equal(upRes.status, 201);
    const upstreamObj = await upRes.json();

    // Register Secret for Tenant A scoped strictly to `toolId` and scope `payments:execute`
    const secRegRes = await fetch(`${BASE_URL}/api/v1/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tenant_id: tenantA,
        secret_ref: `sec_pay_${ts}`,
        secret_value: SUPER_SECRET_VALUE,
        allowed_tools: [toolId],
        allowed_scopes: ['payments:execute'],
        allowed_resources: ['invoice:*'],
      }),
    });
    assert.equal(secRegRes.status, 201);
    const secSummary = await secRegRes.json();
    assert.equal(JSON.stringify(secSummary).includes(SUPER_SECRET_VALUE), false, 'Raw secret leaked in registration summary!');

    // Security Test 1 & 2: Cross-tenant secret access & over-scoped lease request -> MUST FAIL
    const crossTenantLease = await fetch(`${BASE_URL}/api/v1/secrets/lease`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
      body: JSON.stringify({
        secret_ref: `sec_pay_${ts}`,
        agent_id: agentBId,
        tool_id: toolId,
        requested_scope: 'payments:execute',
        resource_scope: 'invoice:100',
      }),
    });
    assert.equal(crossTenantLease.status, 403);

    const overScopeLease = await fetch(`${BASE_URL}/api/v1/secrets/lease`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        secret_ref: `sec_pay_${ts}`,
        agent_id: agentAId,
        tool_id: toolId,
        requested_scope: 'admin:root_all',
        resource_scope: 'invoice:100',
      }),
    });
    assert.equal(overScopeLease.status, 403);

    // Security Test 5: Configure Data Flow Policy -> MASK PII email, BLOCK RESTRICTED credentials
    await fetch(`${BASE_URL}/api/v1/data-flow/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: 'Strict PII Redact & Secret Exfil Block',
        allowed_destinations: ['*'],
        max_allowed_tier: 'INTERNAL',
        redaction_mode: 'MASK',
        block_unclassified_sensitive: true,
      }),
    });

    // Attempt exfiltrating SSN (RESTRICTED) through MCP Gateway -> MUST BLOCK before dispatch!
    const beforeBlockCount = mcpCallCount;
    const exfilRes = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        tool_name: toolId,
        target: 'invoice:55',
        secret_ref: `sec_pay_${ts}`,
        secret_scope: 'payments:execute',
        allow_loopback_upstream: true,
        arguments: { amount: 25, ssn: '123-45-6789' },
      }),
    });
    assert.equal(exfilRes.status, 403);
    assert.equal(mcpCallCount, beforeBlockCount, 'Downstream MCP must NEVER execute on Data Flow BLOCK!');

    // Configure Egress Policy allowing localhost test port for MCP tool with redirect_policy=BLOCK
    await fetch(`${BASE_URL}/api/v1/egress/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tool_id: toolId,
        hostname_allowlist: ['127.0.0.1'],
        allowed_ports: [mcpPort, redirectPort],
        protocol_rules: ['http', 'https'],
        allow_loopback_for_test: true,
        redirect_policy: 'BLOCK',
      }),
    });

    // Valid Call A with CONFIDENTIAL `customer_email`: Data Flow Guard MASKS email before upstream call,
    // Secret Broker mints ephemeral lease injected into Authorization header,
    // Per-Call Isolation allocates InvocationContext & REVOKES lease on teardown!
    const okRes = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        tool_name: toolId,
        target: 'invoice:901',
        secret_ref: `sec_pay_${ts}`,
        secret_scope: 'payments:execute',
        session_id: `sess-${ts}`,
        allow_loopback_upstream: true,
        arguments: { amount: 42, customer_email: 'vip@example.com' },
      }),
    });
    assert.equal(okRes.status, 200);
    const okBody = await okRes.json();
    assert.equal(okBody.allowed, true);
    assert.equal(mcpCallCount, beforeBlockCount + 1);
    assert.equal(lastMcpAuthHeader, `Bearer ${SUPER_SECRET_VALUE}`, 'Upstream should receive brokered auth over wire');
    assert.equal(lastMcpArgs?.customer_email, '[REDACTED:CONTACT_PII]', 'PII email must be masked by Data Flow Guard before egress');
    assert.equal(okBody.invocation_isolation.status, 'COMPLETED_CLEANED');
    assert.equal(okBody.invocation_isolation.leases_revoked_count, 1, 'Ephemeral secret lease MUST be revoked at end of call');

    // Proof of ZERO secret leakage across receipts, audits, gateway invocations, secret audit logs, and vault listings
    const [receiptsRaw, auditsRaw, secAuditsRaw, leasesRaw] = await Promise.all([
      (await fetch(`${BASE_URL}/api/v1/receipts`, { headers: { Authorization: `Bearer ${tokenA}` } })).text(),
      (await fetch(`${BASE_URL}/api/v1/audits?tenant_id=${encodeURIComponent(tenantA)}`, { headers: { Authorization: `Bearer ${tokenA}` } })).text(),
      (await fetch(`${BASE_URL}/api/v1/secrets/audit?tenant_id=${encodeURIComponent(tenantA)}`, { headers: { Authorization: `Bearer ${tokenA}` } })).text(),
      (await fetch(`${BASE_URL}/api/v1/secrets/leases?tenant_id=${encodeURIComponent(tenantA)}`, { headers: { Authorization: `Bearer ${tokenA}` } })).text(),
    ]);
    assert.equal(JSON.stringify(okBody).includes(SUPER_SECRET_VALUE), false);
    assert.equal(receiptsRaw.includes(SUPER_SECRET_VALUE), false);
    assert.equal(auditsRaw.includes(SUPER_SECRET_VALUE), false);
    assert.equal(secAuditsRaw.includes(SUPER_SECRET_VALUE), false);

    // Verify issued lease is indeed revoked post-call
    const leasesList = JSON.parse(leasesRaw);
    const usedLease = leasesList.find((l: any) => l.lease_id === okBody.secret_lease_id);
    assert.equal(usedLease.revoked, true);

    // Security Test 7a: Open-Redirect Bypass attempt on Network Egress Controller -> MUST BLOCK!
    const redirCheck = await fetch(`${BASE_URL}/api/v1/egress/fetch-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tool_id: toolId,
        agent_id: agentAId,
        url: `http://127.0.0.1:${redirectPort}/bounce`,
        method: 'POST',
        allow_loopback: true,
      }),
    });
    assert.equal(redirCheck.status, 403);
    const redirBody = await redirCheck.json();
    assert.equal(redirBody.ok, false);
    assert.equal(redirBody.receipt.decision, 'BLOCK');

    // Security Test 7b: DNS Rebinding attempt resolving hostname to private RFC1918 IP 10.0.0.42 -> MUST BLOCK!
    const rebindPolicy = createNetworkEgressPolicy({
      tenant_id: tenantA,
      tool_id: toolId,
      hostname_allowlist: ['evil-rebind.example.com'],
      protocol_rules: ['https'],
    });
    const dnsRebindEval = await evaluateNetworkEgress({
      tenantId: tenantA,
      toolId,
      agentId: agentAId,
      url: 'https://evil-rebind.example.com/hook',
      policies: [rebindPolicy],
      dnsResolverOverride: async () => ['10.0.0.42'],
    });
    assert.equal(dnsRebindEval.allowed, false);
    assert.equal(dnsRebindEval.receipt.decision, 'BLOCK');
    assert.match(dnsRebindEval.receipt.reason, /Private RFC1918/i);

    // Security Test 4: Secret Revocation blocks subsequent MCP call even if principal asks again
    await fetch(`${BASE_URL}/api/v1/secrets/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ tenant_id: tenantA, secret_ref: `sec_pay_${ts}` }),
    });
    const afterRevokeCall = await fetch(`${BASE_URL}/api/v1/mcp/gateway/invoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        agent_id: agentAId,
        tool_name: toolId,
        target: 'invoice:902',
        secret_ref: `sec_pay_${ts}`,
        secret_scope: 'payments:execute',
        allow_loopback_upstream: true,
        arguments: { amount: 15 },
      }),
    });
    assert.equal(afterRevokeCall.status, 403);

    // Security Test 8: Runtime Behavior Baseline Drift Detection
    const driftObsRes = await fetch(`${BASE_URL}/api/v1/behavior/observe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        tool_id: toolId,
        observed_permission: 'root:shell_exec',
        observed_destination: 'https://rogue-exfil.evil.example',
        observed_data_tier: 'RESTRICTED',
        had_error: false,
      }),
    });
    const driftData = await driftObsRes.json();
    assert.ok(driftData.newEvents.length >= 2, 'Expected unexpected permission & destination drift events');
    assert.equal(driftData.baseline.deviation_status, 'POLICY_VIOLATION');

    // Security Test 9 & 10: Safe Declarative Replay Pack rejects code injection & runs cleanly without calling external MCP!
    const badPackRes = await fetch(`${BASE_URL}/api/v1/replay-packs/safe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: 'Code Injection Replay Attempt',
        tool_id: toolId,
        agent_id: agentAId,
        sanitized_actions: [
          {
            capability: 'security.test',
            target: 'http://example.com',
            sanitized_parameters: { script: "eval('process.exit(1)')" },
          },
        ],
      }),
    });
    assert.equal(badPackRes.status, 400);

    const goodPackRes = await fetch(`${BASE_URL}/api/v1/replay-packs/safe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: 'Clean SSRF & Side-Effect Guard Replay',
        tool_id: toolId,
        agent_id: agentAId,
        mode: 'DRY_RUN',
        sanitized_actions: [
          {
            step_id: 'ssrf-metadata-check',
            capability: 'net.fetch',
            target: 'http://169.254.169.254/latest/meta-data',
            sanitized_parameters: { api_key: 'sk_should_be_sanitized' },
            expected_decision: 'BLOCK',
          },
        ],
      }),
    });
    assert.equal(goodPackRes.status, 201);
    const packObj = await goodPackRes.json();
    assert.equal(packObj.sanitized_actions[0].sanitized_parameters.api_key, '[SANITIZED_FOR_REPLAY]');

    // Cross-tenant replay pack execution blocked!
    const crossRunRes = await fetch(`${BASE_URL}/api/v1/replay-packs/safe/${packObj.replay_pack_id}/run`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(crossRunRes.status, 403);

    const mcpBeforeReplay = mcpCallCount;
    const validRunRes = await fetch(`${BASE_URL}/api/v1/replay-packs/safe/${packObj.replay_pack_id}/run`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    assert.equal(validRunRes.status, 200);
    const validRunBody = await validRunRes.json();
    assert.equal(validRunBody.run_result.status, 'PASSED');
    assert.equal(mcpCallCount, mcpBeforeReplay, 'Safe Replay must trigger ZERO live downstream calls!');
    assert.ok(upstreamObj.upstream_id);
  });
});
