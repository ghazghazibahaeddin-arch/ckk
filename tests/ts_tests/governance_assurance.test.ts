/**
 * CCK Advanced Agent Governance & Assurance Test Suite
 * Independent verification of:
 * - Phase 1: Multi-Hop Delegation with Non-Expansion & Cascading Revocation
 * - Phase 2: Runtime Budget Guard (Denial-of-Wallet Protection) & Multi-Model Pricing
 * - Phase 3: MCP Server Lifecycle & Sensitive Tool Schema Drift Detection
 * - Phase 4: Skill Trust, Capability Evidence Proofs (4B) & Impact (4C)
 * - Phase 5: Unified Action Gate Pipeline Integration & Fail-Closed Zero-Bypass
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';

const baseUrl = 'http://localhost:3000';

async function makeRequest(method: string, path: string, body?: any) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data: any = null;
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

describe('CCK Advanced Agent Governance Verification Suite', () => {
  before(async () => {
    // Wait for dev server on 3000
    for (let i = 0; i < 15; i++) {
      try {
        const res = await fetch(`${baseUrl}/health`);
        if (res.ok) break;
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }
  });

  describe('Phase 1: Multi-Hop Delegation & Contextual Permission Gateway', () => {
    let rootDelId: string;
    let childDelId: string;
    let grandchildDelId: string;

    test('1.1 Create signed root delegation tied to root agent authority', async () => {
      const res = await makeRequest('POST', '/api/v1/delegations', {
        delegator_agent_id: 'agt-lead-orchestrator',
        delegatee_agent_id: 'agt-finance-specialist',
        tenant_id: 'tenant_enterprise_01',
        allowed_actions: ['payments.process', 'refunds.issue', 'invoices.create'],
        allowed_resources: ['order:*', 'customer:*'],
        allowed_tools: ['stripe_charge', 'stripe_refund'],
        max_depth: 3,
        spending_limit: { max_per_action: 300, total_budget: 3000, currency: 'USD' },
        valid_until: new Date(Date.now() + 86400000 * 30).toISOString(),
      });

      assert.equal(res.status, 201);
      assert.ok(res.data.success);
      assert.ok(res.data.delegation.delegation_id);
      assert.equal(res.data.delegation.parent_delegation_id, null);
      assert.equal(res.data.delegation.scope.current_depth, 0);
      assert.ok(res.data.delegation.signature.length > 20, 'Cryptographic signature must be present');
      rootDelId = res.data.delegation.delegation_id;
    });

    test('1.2 Sub-delegation with equal or narrower scope succeeds monotonically', async () => {
      const res = await makeRequest('POST', `/api/v1/delegations/${rootDelId}/delegate`, {
        delegatee_agent_id: 'agt-refund-worker',
        allowed_actions: ['refunds.issue'], // Strict subset
        allowed_resources: ['order:*'], // Strict subset
        allowed_tools: ['stripe_refund'],
        spending_limit: { max_per_action: 150, total_budget: 1000, currency: 'USD' },
      });

      assert.equal(res.status, 201);
      assert.ok(res.data.success);
      assert.equal(res.data.delegation.parent_delegation_id, rootDelId);
      assert.equal(res.data.delegation.root_delegation_id, rootDelId);
      assert.equal(res.data.delegation.scope.current_depth, 1);
      childDelId = res.data.delegation.delegation_id;
    });

    test('1.3 Non-expansion violation: Sub-delegation requesting wider actions is strictly REJECTED (400)', async () => {
      const res = await makeRequest('POST', `/api/v1/delegations/${childDelId}/delegate`, {
        delegatee_agent_id: 'agt-rogue-sub',
        allowed_actions: ['payments.process', 'database.drop'],
        allowed_resources: ['order:*'],
      });

      assert.equal(res.status, 400);
      assert.match(res.data.error, /Sub-delegation expansion violation/i);
    });

    test('1.4 Non-expansion violation: Sub-delegation requesting higher spending ceiling is strictly REJECTED (400)', async () => {
      const res = await makeRequest('POST', `/api/v1/delegations/${childDelId}/delegate`, {
        delegatee_agent_id: 'agt-greedy-sub',
        allowed_actions: ['refunds.issue'],
        allowed_resources: ['order:*'],
        spending_limit: { max_per_action: 500, total_budget: 5000, currency: 'USD' },
      });

      assert.equal(res.status, 400);
      assert.match(res.data.error, /max_per_action.*cannot exceed parent limit/i);
    });

    test('1.5 Multi-hop grandchild sub-delegation at depth 2 succeeds', async () => {
      const res = await makeRequest('POST', `/api/v1/delegations/${childDelId}/delegate`, {
        delegatee_agent_id: 'agt-micro-refund-bot',
        allowed_actions: ['refunds.issue'],
        allowed_resources: ['order:*'],
        spending_limit: { max_per_action: 50, total_budget: 200, currency: 'USD' },
      });

      assert.equal(res.status, 201);
      assert.equal(res.data.delegation.scope.current_depth, 2);
      grandchildDelId = res.data.delegation.delegation_id;
    });

    test('1.6 Action Gate authorizes compliant action using grandchild delegation', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'refunds.issue',
        target: 'order:1099',
        delegation_id: grandchildDelId,
        parameters: { amount: 45 },
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.decision, 'ALLOW');
    });

    test('1.7 Action Gate BLOCKS action if amount exceeds sub-delegation ceiling', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'refunds.issue',
        target: 'order:1099',
        delegation_id: grandchildDelId,
        parameters: { amount: 90 },
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.decision, 'BLOCK');
      assert.match(res.data.reason, /exceeds spending ceiling/i);
    });

    test('1.8 Cascading Revocation: Revoking root delegation invalidates all descendant hops', async () => {
      const revokeRes = await makeRequest('POST', `/api/v1/delegations/${rootDelId}/revoke`, {
        reason: 'Root agent security credential rotation',
      });

      assert.equal(revokeRes.status, 200);
      assert.ok(revokeRes.data.success);
      assert.ok(revokeRes.data.revoked_count >= 3);
      assert.ok(revokeRes.data.revoked_ids.includes(childDelId));
      assert.ok(revokeRes.data.revoked_ids.includes(grandchildDelId));

      // Immediate check in Action Gate using grandchild delegation must fail closed
      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'refunds.issue',
        target: 'order:1099',
        delegation_id: grandchildDelId,
        parameters: { amount: 20 },
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'BLOCK');
      assert.match(gateRes.data.reason, /is REVOKED/i);
    });
  });

  describe('Phase 2: Runtime Budget Guard — Denial-of-Wallet Protection', () => {
    test('2.1 Multi-model pricing estimation calculates accurate costs across providers', async () => {
      const models = ['gemini-1.5-flash', 'gemini-2.0-flash', 'gpt-4o', 'claude-3-5-sonnet'];

      for (const model of models) {
        const res = await makeRequest('POST', '/api/v1/budgets/estimate', {
          model_id: model,
          estimated_input_tokens: 10000,
          estimated_output_tokens: 2000,
          tool_calls_count: 2,
        });

        assert.equal(res.status, 200);
        assert.ok(res.data.estimate.estimated_cost_usd > 0);
        assert.equal(res.data.estimate.model_id, model);
      }
    });

    test('2.2 Configure task budget with tight ceiling', async () => {
      const res = await makeRequest('POST', '/api/v1/budgets', {
        tenant_id: 'tenant_enterprise_01',
        scope_type: 'TASK',
        scope_id: 'task-batch-scrape-99',
        limits: {
          max_budget_usd: 0.05,
          max_model_calls: 5,
          max_tool_calls: 10,
          max_retries: 2,
          max_delegation_depth: 3,
          max_execution_timeout_ms: 10000,
          max_concurrent_runs: 2,
        },
      });

      assert.ok(res.status === 200 || res.status === 201);
      assert.ok(res.data.budget.budget_id);
    });

    test('2.3 Action Gate BLOCKS dispatch when estimated cost exceeds budget limit (Denial-of-Wallet)', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'scrape.target',
        target: 'customer:profile:99',
        task_id: 'task-batch-scrape-99',
        model_id: 'gpt-4o',
        input_tokens: 25000,
        output_tokens: 5000,
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.decision, 'BLOCK');
      assert.match(res.data.reason, /Denial-of-Wallet Protection/i);
    });

    test('2.4 Action Gate BLOCKS dispatch when model calls limit is hit', async () => {
      const bRes = await makeRequest('POST', '/api/v1/budgets', {
        tenant_id: 'tenant_enterprise_01',
        scope_type: 'AGENT',
        scope_id: 'agt-limited-calls-01',
        limits: {
          max_budget_usd: 10.0,
          max_model_calls: 1,
          max_tool_calls: 5,
          max_retries: 1,
          max_delegation_depth: 2,
          max_execution_timeout_ms: 10000,
          max_concurrent_runs: 2,
        },
      });
      const budgetId = bRes.data.budget.budget_id;

      await makeRequest('POST', '/api/v1/budgets/record-usage', {
        budget_id: budgetId,
        actual_cost_usd: 0.001,
        model_calls: 1,
      });

      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'payments.process',
        target: 'order:2000',
        agent: 'agt-limited-calls-01',
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'BLOCK');
      assert.match(gateRes.data.reason, /Model call.*limit reached/i);
    });
  });

  describe('Phase 3: MCP Server Lifecycle Governance & Tool Drift', () => {
    let mcpServerId: string;

    test('3.1 Register MCP Server with tools and input schemas', async () => {
      const res = await makeRequest('POST', '/api/v1/mcp/servers', {
        name: 'Stripe Payment Processor MCP',
        transport: 'STREAMABLE_HTTP',
        endpoint_url: 'http://localhost:3000/api/v1/mcp/stripe',
        version: '1.0.0',
        exposed_tools: [
          {
            name: 'get_balance',
            description: 'Read current account balance',
            input_schema: { type: 'object' },
            is_sensitive: false,
          },
          {
            name: 'settle_payout',
            description: 'Trigger immediate payout to merchant bank',
            input_schema: { type: 'object', properties: { amount: { type: 'number' } } },
            is_sensitive: true,
            sensitive_reason: 'Direct bank payout mutation',
          },
        ],
      });

      assert.equal(res.status, 201);
      assert.ok(res.data.server.server_id);
      assert.equal(res.data.server.lifecycle_status, 'REVIEW_REQUIRED');
      mcpServerId = res.data.server.server_id;
    });

    test('3.2 Action Gate strictly BLOCKS unapproved sensitive tool execution', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'tool.dispatch',
        target: 'server.mcp',
        mcp_server_id: mcpServerId,
        tool_name: 'settle_payout',
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.decision, 'BLOCK');
      assert.match(res.data.reason, /REVIEW_REQUIRED|requires explicit supervisor production approval/i);
    });

    test('3.3 Supervisor approval gate transitions MCP server to ACTIVE and approves tools', async () => {
      const res = await makeRequest('POST', `/api/v1/mcp/servers/${mcpServerId}/approve`, {
        reviewer: 'supervisor-lead-audit',
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.server.lifecycle_status, 'ACTIVE');
      assert.equal(res.data.server.exposed_tools[1].approved_for_production, true);

      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'tool.dispatch',
        target: 'server.mcp',
        mcp_server_id: mcpServerId,
        tool_name: 'settle_payout',
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'ALLOW');
    });

    test('3.4 Tool schema drift detection flags modified schema and resets status to REVIEW_REQUIRED', async () => {
      const syncRes = await makeRequest('POST', `/api/v1/mcp/servers/${mcpServerId}/tools/sync`, {
        new_tools: [
          {
            name: 'get_balance',
            description: 'Read current account balance',
            input_schema: { type: 'object' },
          },
          {
            name: 'settle_payout',
            description: 'Trigger immediate payout to merchant bank',
            input_schema: { type: 'object', properties: { amount: { type: 'number' }, currency: { type: 'string' } } },
            is_sensitive: true,
          },
        ],
      });

      assert.equal(syncRes.status, 200);
      assert.equal(syncRes.data.drift_detected, true);
      assert.equal(syncRes.data.requires_review, true);
      assert.equal(syncRes.data.server.lifecycle_status, 'REVIEW_REQUIRED');

      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'tool.dispatch',
        target: 'server.mcp',
        mcp_server_id: mcpServerId,
        tool_name: 'settle_payout',
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'BLOCK');
      assert.match(gateRes.data.reason, /REVIEW_REQUIRED/i);
    });

    test('3.5 Suspending or Revoking MCP Server blocks all tool dispatch', async () => {
      const suspendRes = await makeRequest('POST', `/api/v1/mcp/servers/${mcpServerId}/suspend`, {
        reason: 'Scheduled maintenance outage',
      });

      assert.equal(suspendRes.status, 200);
      assert.equal(suspendRes.data.server.lifecycle_status, 'SUSPENDED');

      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'tool.dispatch',
        target: 'server.mcp',
        mcp_server_id: mcpServerId,
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'BLOCK');
      assert.match(gateRes.data.reason, /SUSPENDED/i);
    });
  });

  describe('Phase 4: Skill Trust, Capability Evidence & Impact', () => {
    test('4.1 Mint verifiable CapabilityEvidenceReceipt with tamper-resistant HMAC hash', async () => {
      const res = await makeRequest('POST', '/api/v1/agents/agt-billing-worker/evaluate-capability', {
        skills_used: ['skl-stripe-payments'],
        task_name: 'automated_invoice_settlement',
        model_id: 'gemini-1.5-flash',
        test_count: 50,
      });

      assert.equal(res.status, 201);
      assert.ok(res.data.success);
      const receipt = res.data.capability_evidence_receipt;
      assert.ok(receipt.evidence_receipt_id);
      assert.equal(receipt.results.total_tests, 50);
      assert.equal(receipt.results.success_rate, 1.0);
      assert.ok(receipt.tamper_hash.length >= 32);

      const getRes = await makeRequest('GET', `/api/v1/capability-evidence/${receipt.evidence_receipt_id}`);
      assert.equal(getRes.status, 200);
      assert.equal(getRes.data.tamper_hash, receipt.tamper_hash);
    });

    test('4.2 Action Gate strictly BLOCKS revoked skills fail-closed', async () => {
      const skillRes = await makeRequest('POST', '/api/v1/skills', {
        name: 'Compromised Payment Plugin',
        version: '1.0.0',
        publisher_name: 'Untrusted Vendor',
        cryptographic_hash: 'abc123def456',
        domain: 'financial',
        jurisdiction: 'GLOBAL',
      });
      const skillId = skillRes.data.skill_id;

      await makeRequest('POST', `/api/v1/skills/${skillId}/revoke`, {
        reason: 'Zero-day vulnerability discovered in upstream dependency',
      });

      const gateRes = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'payments.process',
        target: 'order:1099',
        skill_id: skillId,
      });

      assert.equal(gateRes.status, 200);
      assert.equal(gateRes.data.decision, 'BLOCK');
      assert.match(gateRes.data.reason, /REVOKED/i);
    });
  });

  describe('Phase 5: Unified Pipeline Fail-Closed Zero-Bypass', () => {
    test('5.1 Fail-closed: missing capability or target returns 400 BLOCK with receipt', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        agent: 'agt-console',
      });

      assert.equal(res.status, 400);
      assert.equal(res.data.decision, 'BLOCK');
      assert.ok(res.data.receipt_id);
    });

    test('5.2 Zero-bypass: un-gated action fails closed when any governance dimension fails', async () => {
      const res = await makeRequest('POST', '/api/v1/actions/evaluate', {
        capability: 'payments.process',
        target: 'order:1099',
        delegation_id: 'del-forged-fake-id',
      });

      assert.equal(res.status, 200);
      assert.equal(res.data.decision, 'BLOCK');
      assert.match(res.data.reason, /not found/i);
    });
  });
});
