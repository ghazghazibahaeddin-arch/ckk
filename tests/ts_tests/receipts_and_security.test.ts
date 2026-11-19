import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createTenantSession, type TenantTestSession } from './_test_auth.ts';

const BASE_URL = 'http://localhost:3000';

describe('CCK Decision Receipts & Fail-Closed Security', () => {
  let session: TenantTestSession;

  before(async () => {
    session = await createTenantSession(BASE_URL, 'receipts');
    // Seed an evaluation so the fresh tenant has at least one receipt
    await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        capability: 'telemetry.log',
        target: 'metrics.check',
        command: 'ping',
      }),
    });
  });

  test('Decision Receipts: Mint, retrieve and verify cryptographic hashes', async () => {
    // Fetch receipts list
    const res = await fetch(`${BASE_URL}/api/v1/receipts`, {
      headers: session.headers,
    });
    assert.equal(res.status, 200);
    const list = await res.json();
    assert.ok(Array.isArray(list));
    assert.ok(list.length > 0);

    const first = list[0];
    assert.ok(first.receipt_id.startsWith('rcpt-'));
    assert.ok(first.status);
    assert.ok(first.audit_ref?.action_hash);

    // Export HTML
    const htmlRes = await fetch(`${BASE_URL}/api/v1/receipts/${first.receipt_id}/export?format=html`, {
      headers: session.headers,
    });
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.match(html, /CCK DECISION RECEIPT/);
    assert.match(html, /Cryptographic Evidence/);
  });

  test('Fail-Closed: Missing capability/target immediately blocks mutation', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.decision, 'BLOCK');
    assert.equal(data.risk_score, 1.0);
    assert.match(data.reason, /fail-closed/i);
  });

  test('Public Benchmark: 100 evaluations pass with 0% false blocks', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/benchmark/run`, {
      method: 'POST',
      headers: session.headers,
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.total_evaluations, 100);
    assert.equal(data.false_block_rate, '0.00%');
    assert.equal(data.detection_accuracy, '100.00%');
    assert.equal(data.sha256_audit_chain_verified, true);
    assert.ok(data.throughput_ops_per_sec > 10000);
  });

  test('Connected Agents: Register agent, execute live gate check, and enforce drift block', async () => {
    const testEntity = `account:acc_${Date.now()}`;
    // 1. Create a customer agent
    const regRes = await fetch(`${BASE_URL}/api/v1/agents`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        name: 'AutoPaymentAgent',
        framework: 'openai',
        target_capability: 'finance.transfer',
        target_resource: testEntity,
        guardrail_mode: 'ENFORCE_AND_BLOCK',
        freshness_ttl_seconds: 300,
        project_id: session.projectId,
        tenant_id: session.tenantId,
      }),
    });
    assert.equal(regRes.status, 201);
    const agent = await regRes.json();
    assert.ok(agent.agent_id.startsWith('agt-'));
    assert.equal(agent.name, 'AutoPaymentAgent');

    // 2. Initial gate evaluation (ALLOW)
    const testRes = await fetch(`${BASE_URL}/api/v1/agents/${agent.agent_id}/test-gate`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        action_command: 'finance.transfer $500 to account:acc_99',
      }),
    });
    assert.equal(testRes.status, 200);
    const testData = await testRes.json();
    assert.equal(testData.verdict, 'ALLOW');
    assert.ok(testData.receipt_id.startsWith('rcpt-'));

    // 3. Toggle drift to invalidate precondition
    const driftRes = await fetch(`${BASE_URL}/api/v1/agents/${agent.agent_id}/drift-toggle`, {
      method: 'POST',
      headers: session.headers,
    });
    assert.equal(driftRes.status, 200);
    const driftData = await driftRes.json();
    assert.equal(driftData.new_fact_state, 'INVALIDATED');

    // 4. Second gate evaluation must be BLOCKED
    const blockedRes = await fetch(`${BASE_URL}/api/v1/agents/${agent.agent_id}/test-gate`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({
        action_command: 'finance.transfer $500 to account:acc_99',
      }),
    });
    assert.equal(blockedRes.status, 200);
    const blockedData = await blockedRes.json();
    assert.equal(blockedData.verdict, 'BLOCK');
    assert.match(blockedData.reason, /INVALIDATED/);

    // 5. Tenant Isolation: Query agents by project_id
    const filterRes = await fetch(`${BASE_URL}/api/v1/agents?project_id=${encodeURIComponent(session.projectId)}`, {
      headers: session.headers,
    });
    assert.equal(filterRes.status, 200);
    const isolatedList = await filterRes.json();
    assert.ok(isolatedList.some((a: any) => a.agent_id === agent.agent_id));

    const otherTenantRes = await fetch(`${BASE_URL}/api/v1/agents?project_id=proj-other-unknown`, {
      headers: session.headers,
    });
    assert.equal(otherTenantRes.status, 200);
    const otherList = await otherTenantRes.json();
    assert.equal(otherList.length, 0);
  });
});
