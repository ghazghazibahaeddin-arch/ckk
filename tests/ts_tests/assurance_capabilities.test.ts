import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createTenantSession, type TenantTestSession } from './_test_auth.ts';

const baseUrl = 'http://localhost:3000';

describe('CCK Assurance Capabilities Verification Suite', () => {
  let session: TenantTestSession;
  let contractId = '';
  const isolatedOrder = `order:assurance-${Date.now()}`;

  const apiFetch = (path: string, init: RequestInit = {}) =>
    fetch(`${baseUrl}${path}`, {
      ...init,
      headers: {
        ...(init.headers as Record<string, string> | undefined),
        Authorization: `Bearer ${session.token}`,
      },
    });

  before(async () => {
    session = await createTenantSession(baseUrl, 'assurance');

    // Seed fresh valid evidence fact for isolated assurance suite runs
    await apiFetch('/api/v1/facts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entity_id: isolatedOrder,
        field_name: 'status',
        value: 'paid',
        source: 'stripe_gateway',
      }),
    });
  });

  // --------------------------------------------------------------------------
  // 1. Verified Action Contracts — EFFECT
  // --------------------------------------------------------------------------
  describe('1. Verified Action Contracts (EFFECT)', () => {
    const idempotencyKey = `idemp-${Date.now()}-test1`;
    let executionId = '';

    test('1.1 Create Verified Action Contract with spending ceiling and invariants', async () => {
      const res = await apiFetch(`/api/v1/contracts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: 'agt-console',
          permitted_action: 'payment.charge',
          target_resource: 'api.stripe.com',
          spending_ceiling: 500,
          required_evidence: [`fact:${isolatedOrder}:status`],
          applicable_invariants: ['INV_NEVER_CHARGE_TWICE', 'INV_NEVER_EXCEED_LIMIT'],
          compensation_supported: true,
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.contract_id);
      assert.equal(data.status, 'ACTIVE');
      assert.equal(data.action_capability, 'payment.charge');
      contractId = data.contract_id;
    });

    test('1.2 Execution Lifecycle: PREPARED -> AUTHORIZED -> EXECUTING -> SUCCEEDED', async () => {
      // Step A: Prepare
      const prepRes = await apiFetch(`/api/v1/contracts/${contractId}/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: idempotencyKey,
          parameters: { amount: 150, currency: 'USD', order_id: isolatedOrder, entity_id: isolatedOrder },
        }),
      });
      assert.equal(prepRes.status, 201);
      const prepData = await prepRes.json();
      assert.equal(prepData.execution.state, 'PREPARED');
      executionId = prepData.execution.execution_id;

      // Step B: Authorize
      const authRes = await apiFetch(`/api/v1/contracts/${contractId}/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          execution_id: executionId,
          supervisor_notes: 'Approved for automated processing',
        }),
      });
      assert.equal(authRes.status, 200);
      const authData = await authRes.json();
      assert.equal(authData.execution.state, 'AUTHORIZED');

      // Step C: Execute
      const execRes = await apiFetch(`/api/v1/contracts/${contractId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: idempotencyKey,
          execution_id: executionId,
          parameters: { amount: 150, currency: 'USD', order_id: isolatedOrder, entity_id: isolatedOrder },
        }),
      });
      assert.equal(execRes.status, 200);
      const execData = await execRes.json();
      assert.equal(execData.state, 'SUCCEEDED');
      assert.ok(execData.receipt);
      assert.equal(execData.execution.state, 'SUCCEEDED');
    });

    test('1.3 Idempotency Enforcement: Duplicate execution returns cached result (zero re-execution)', async () => {
      const replayRes = await apiFetch(`/api/v1/contracts/${contractId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: idempotencyKey,
          parameters: { amount: 150, currency: 'USD', order_id: isolatedOrder, entity_id: isolatedOrder },
        }),
      });

      assert.equal(replayRes.status, 200);
      const replayData = await replayRes.json();
      assert.equal(replayData.idempotency_replayed, true);
      assert.equal(replayData.state, 'SUCCEEDED');
    });

    test('1.4 External Status Probe for UNKNOWN state prevents duplicate commits', async () => {
      const unknownKey = `idemp-unknown-${Date.now()}`;
      // Simulate network interruption resulting in UNKNOWN
      const unkRes = await apiFetch(`/api/v1/contracts/${contractId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: unknownKey,
          simulate_unknown: true,
          parameters: { amount: 80, order_id: isolatedOrder, entity_id: isolatedOrder },
        }),
      });
      assert.equal(unkRes.status, 202);
      const unkData = await unkRes.json();
      assert.equal(unkData.state, 'UNKNOWN');
      const unkExecId = unkData.execution_id;

      // Immediate retry must fail closed with 409 Conflict requiring status probe
      const retryRes = await apiFetch(`/api/v1/contracts/${contractId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: unknownKey,
          parameters: { amount: 80, order_id: isolatedOrder, entity_id: isolatedOrder },
        }),
      });
      assert.equal(retryRes.status, 409);

      // Probe external status
      const probeRes = await apiFetch(`/api/v1/contracts/executions/${unkExecId}/probe-external`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ simulated_outcome: 'SUCCEEDED' }),
      });
      assert.equal(probeRes.status, 200);
      const probeData = await probeRes.json();
      assert.equal(probeData.state, 'SUCCEEDED');
      assert.equal(probeData.execution.external_status_verified, true);
    });

    test('1.5 Compensation / Rollback transaction lifecycle', async () => {
      const compRes = await apiFetch(`/api/v1/contracts/executions/${executionId}/compensate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Customer requested cancellation prior to batch clearing' }),
      });
      assert.equal(compRes.status, 200);
      const compData = await compRes.json();
      assert.equal(compData.state, 'COMPENSATED');
      assert.equal(compData.execution.state, 'COMPENSATED');
    });
  });

  // --------------------------------------------------------------------------
  // 2. Evidence Change & Conflict Intelligence — CASCADE + Crossflow
  // --------------------------------------------------------------------------
  describe('2. Evidence Change & Conflict Intelligence (CASCADE + Crossflow)', () => {
    const testEntity = `order:conflict-${Date.now()}`;
    let conflictId = '';

    test('2.1 Initial fact ingestion and version history recording', async () => {
      const res = await apiFetch(`/api/v1/facts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: testEntity,
          field_name: 'status',
          value: 'paid',
          source: 'stripe_payment_gateway',
        }),
      });
      assert.ok(res.status === 200 || res.status === 201);
      const data = await res.json();
      assert.equal(data.version, 1);
      assert.equal(data.state, 'VALID');

      // Verify history
      const histRes = await apiFetch(`/api/v1/facts/${testEntity}/status/history`);
      assert.equal(histRes.status, 200);
      const history = await histRes.json();
      assert.ok(history.length >= 1);
      assert.equal(history[0].change_type, 'INITIAL');
    });

    test('2.2 Contradictory observations across sources trigger CONFLICT without silent overwrite', async () => {
      const conflictRes = await apiFetch(`/api/v1/facts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: testEntity,
          field_name: 'status',
          value: 'refunded',
          source: 'erp_support_desk',
        }),
      });

      assert.equal(conflictRes.status, 409);
      const conflictData = await conflictRes.json();
      assert.ok(conflictData.conflict);
      assert.equal(conflictData.conflict.status, 'ACTIVE_CONFLICT');
      conflictId = conflictData.conflict.conflict_id;

      // Ensure fact state transitioned to CONFLICT
      const getFactRes = await apiFetch(`/api/v1/facts`);
      const allFacts = await getFactRes.json();
      const conflictedFact = allFacts.find((f: any) => f.entity_id === testEntity);
      assert.ok(conflictedFact);
      assert.equal(conflictedFact.state, 'CONFLICT');
    });

    test('2.3 Revalidation Notice automatically issued for dependent decisions', async () => {
      const revRes = await apiFetch(`/api/v1/revalidations`);
      assert.equal(revRes.status, 200);
      const notices = await revRes.json();
      const matched = notices.find((n: any) => n.fact_key === `${testEntity}.status` || n.fact_key === `${testEntity}:status`);
      assert.ok(matched, 'Revalidation notice must be generated upon conflict');
      assert.equal(matched.status, 'PENDING_REVALIDATION');

      // Dismiss notice
      const dismissRes = await apiFetch(`/api/v1/revalidations/${matched.revalidation_id}/dismiss`, {
        method: 'POST',
      });
      assert.equal(dismissRes.status, 200);
    });

    test('2.4 Resolve Conflict with AUTHORITATIVE_SOURCE strategy updates fact and records provenance', async () => {
      const resolveRes = await apiFetch(`/api/v1/conflicts/${conflictId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          strategy: 'AUTHORITATIVE_SOURCE',
          resolver: 'supervisor-lead-01',
          override_value: 'refunded',
          note: 'ERP refund receipt verified against merchant portal',
        }),
      });

      assert.equal(resolveRes.status, 200);
      const resolveData = await resolveRes.json();
      assert.equal(resolveData.conflict.status, 'RESOLVED');
      assert.equal(resolveData.fact.state, 'VALID');
      assert.equal(resolveData.fact.value, 'refunded');
    });
  });

  // --------------------------------------------------------------------------
  // 3. Delegated Authority & Invariant Rules — Mandate OS + INVARIANT
  // --------------------------------------------------------------------------
  describe('3. Delegated Authority & Invariant Rules (Mandate OS + INVARIANT)', () => {
    let mandateId = '';

    test('3.1 Create Delegated Agent Mandate with cryptographic signature', async () => {
      const res = await apiFetch(`/api/v1/mandates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: 'agt-procurement-delegated',
          name: 'Procurement Authority Mandate',
          spending_limits: {
            max_per_action: 300,
            total_budget: 1500,
            current_spent: 0,
            currency: 'USD',
          },
          destination_restrictions: {
            allowed_domains: ['*.stripe.com', 'courier.fedex'],
            allow_external_egress: true,
          },
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.mandate_id);
      assert.ok(data.signature);
      assert.equal(data.status, 'ACTIVE');
      mandateId = data.mandate_id;
    });

    test('3.2 Invariant INV_NEVER_EXCEED_LIMIT: Blocks action exceeding single-action ceiling', async () => {
      const res = await apiFetch(`/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: 'agt-procurement-delegated',
          capability: 'payment.charge',
          target: 'api.stripe.com',
          command: 'charge 750 USD',
          parameters: { amount: 750, currency: 'USD' },
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.decision, 'BLOCK');
      assert.ok(data.reason.includes('exceeds single-action ceiling'));
    });

    test('3.3 Invariant INV_APPROVED_DESTINATION_ONLY: Blocks mutation to unauthorized destination', async () => {
      const res = await apiFetch(`/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: 'agt-procurement-delegated',
          capability: 'payment.charge',
          target: 'api.unauthorized-crypto-mixer.com',
          command: 'transfer 50 USD',
          parameters: { amount: 50 },
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.decision, 'BLOCK');
      assert.ok(data.reason.includes('not an authorized egress destination'));
    });

    test('3.4 Invariant INV_NEVER_CHARGE_TWICE: Prohibits double settlement on same order', async () => {
      const settledOrderId = `order:settled-${Date.now()}`;
      // 1. Establish initial successful settlement
      const initialSettlementRes = await apiFetch(`/api/v1/contracts/${contractId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: `idemp-settle-${Date.now()}`,
          parameters: { entity_id: settledOrderId, order_id: settledOrderId, amount: 100 },
        }),
      });
      assert.ok(initialSettlementRes.ok);

      // 2. Second charge attempt against settled order must be BLOCKED by invariant
      const duplicateRes = await apiFetch(`/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: 'agt-console',
          capability: 'payment.charge',
          target: 'api.stripe.com',
          command: `charge ${settledOrderId} 100 USD`,
          entity_id: settledOrderId,
          parameters: { entity_id: settledOrderId, amount: 100 },
        }),
      });

      assert.equal(duplicateRes.status, 200);
      const data = await duplicateRes.json();
      assert.equal(data.decision, 'BLOCK');
      assert.ok(data.reason.includes('INV_NEVER_CHARGE_TWICE'));
    });
  });

  // --------------------------------------------------------------------------
  // 4. Skill Trust & Lifecycle
  // --------------------------------------------------------------------------
  describe('4. Skill Trust & Lifecycle', () => {
    let unverifiedSkillId = '';

    test('4.1 Register skill: Unverified peer review marks skill as UNVERIFIED', async () => {
      const res = await apiFetch(`/api/v1/skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Community Data Scraper',
          publisher: 'community-dev',
          domain: 'data_ingestion',
          review_info: {
            reviewer_name: 'Peer Reviewer',
            verified_credential: false,
            credential_details: 'Unverified forum post attestation',
          },
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.status, 'UNVERIFIED');
      unverifiedSkillId = data.skill_id;
    });

    test('4.2 Invariant INV_AUTHORIZED_SKILLS_ONLY: Action Gate blocks unverified skill', async () => {
      const res = await apiFetch(`/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: 'agt-console',
          capability: 'scraper.extract',
          target: 'api.acme.com',
          skill_id: unverifiedSkillId,
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.decision, 'BLOCK');
      assert.ok(data.reason.includes('is UNVERIFIED with unverified reviewer attestations'));
    });

    test('4.3 Accredited review verification promotes skill to VALID', async () => {
      const res = await apiFetch(`/api/v1/skills/${unverifiedSkillId}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verified_credential: true,
          reviewer_name: 'Dr. Jane Smith, Certified AI Safety Auditor',
          credential_details: 'ISO-42001 Lead Auditor #AS-2026-88',
          review_notes: 'Formal audit completed: zero arbitrary egress found.',
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.skill.status, 'VALID');
      assert.equal(data.skill.review_info.verified_credential, true);
    });

    test('4.4 Skill Revocation transitions status to REVOKED and blocks execution', async () => {
      const revokeRes = await apiFetch(`/api/v1/skills/${unverifiedSkillId}/revoke`, {
        method: 'POST',
      });
      assert.equal(revokeRes.status, 200);

      const evalRes = await apiFetch(`/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: 'agt-console',
          capability: 'scraper.extract',
          target: 'api.acme.com',
          skill_id: unverifiedSkillId,
        }),
      });
      const evalData = await evalRes.json();
      assert.equal(evalData.decision, 'BLOCK');
      assert.ok(evalData.reason.includes('is REVOKED'));
    });
  });

  // --------------------------------------------------------------------------
  // 5. Skill Impact Evaluation
  // --------------------------------------------------------------------------
  describe('5. Skill Impact Evaluation Harness', () => {
    let receiptId = '';

    test('5.1 Run controlled sandbox evaluation and generate tamper-hashed Impact Receipt', async () => {
      const res = await apiFetch(`/api/v1/skills/skl-stripe-checkout/evaluate-impact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modelId: 'gemini-1.5-pro',
          taskCategory: 'payment-settlement-assurance',
          sampleSize: 50,
        }),
      });

      assert.equal(res.status, 201);
      const receipt = await res.json();
      assert.ok(receipt.impact_receipt_id);
      assert.ok(receipt.tamper_hash);
      assert.equal(receipt.test_method, 'ISOLATED_SANDBOX_REPLAY');
      assert.equal(receipt.privacy_config.external_sharing_enabled, false, 'External sharing must be disabled by default');
      assert.ok(receipt.metrics.relative_improvement > 0);
      receiptId = receipt.impact_receipt_id;
    });

    test('5.2 Privacy Config: External sharing opt-in toggle requires explicit action', async () => {
      const patchRes = await apiFetch(`/api/v1/skills/impact-receipts/${receiptId}/privacy`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          external_sharing_enabled: true,
          opt_in_telemetry: true,
        }),
      });

      assert.equal(patchRes.status, 200);
      const patched = await patchRes.json();
      assert.equal(patched.receipt.privacy_config.external_sharing_enabled, true);
    });
  });

  // --------------------------------------------------------------------------
  // 6. Incident-to-Correction + Replay Packs
  // --------------------------------------------------------------------------
  describe('6. Incident-to-Correction + Replay Packs', () => {
    let incidentId = '';
    let packId = '';
    let replayPackId = '';

    test('6.1 Create real Incident linking affected agent, contract, and entity', async () => {
      const res = await apiFetch(`/api/v1/incidents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: 'Precondition Drift Incident: Unverified Courier Dispatch',
          severity: 'HIGH',
          root_cause_type: 'PRECONDITION_DRIFT',
          description: 'Courier action dispatched without revalidating active refund dispute.',
          affected_agent_id: 'agt-console',
          affected_action: 'logistics.ship',
          affected_entity_id: 'order:9999',
          affected_contract_id: 'ctrc-logistics-standard',
        }),
      });

      assert.equal(res.status, 201);
      const inc = await res.json();
      assert.ok(inc.incident_id);
      assert.equal(inc.status, 'OPEN');
      incidentId = inc.incident_id;
    });

    test('6.2 Create versioned Correction Pack in DRAFT state', async () => {
      const res = await apiFetch(`/api/v1/incidents/${incidentId}/correction`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          version: '1.0.2',
          patch_description: 'Require active payment precondition check <= 30 seconds max age',
          verification_tests: [
            {
              test_id: 'tst-refund-drift-1',
              test_name: 'Drifted status returns BLOCK',
              expected_result: 'BLOCK',
            },
          ],
          requires_human_approval: true,
        }),
      });

      assert.equal(res.status, 201);
      const cpk = await res.json();
      assert.equal(cpk.state, 'DRAFT');
      assert.ok(cpk.pack_id);
      packId = cpk.pack_id;
    });

    test('6.3 Create sanitized Replay Pack and execute isolated replay test harness', async () => {
      // Create Replay Pack
      const createRes = await apiFetch(`/api/v1/incidents/${incidentId}/replay-pack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sanitized_inputs: { order_id: 'order:9999', api_keys_redacted: true },
          expected_baseline_failure: 'Courier dispatch executed despite active refund',
          expected_corrected_success: 'Action Gate intercepts drifted refund and blocks courier dispatch',
        }),
      });
      assert.equal(createRes.status, 201);
      const rpk = await createRes.json();
      replayPackId = rpk.replay_pack_id;

      // Run isolated replay harness
      const runRes = await apiFetch(`/api/v1/incidents/replay-packs/${replayPackId}/run`, {
        method: 'POST',
      });
      assert.equal(runRes.status, 200);
      const runData = await runRes.json();
      assert.equal(runData.harness_result.status, 'VERIFIED_CORRECTED');
      assert.equal(runData.correction_pack.state, 'TESTED');
    });

    test('6.4 Supervisor approval gate promotes correction pack and resolves incident', async () => {
      const approveRes = await apiFetch(`/api/v1/incidents/corrections/${packId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reviewed_by: 'lead-security-officer',
          approval_notes: 'All isolated replay tests verified. Promoted to production policies.',
        }),
      });

      assert.equal(approveRes.status, 200);
      const appData = await approveRes.json();
      assert.equal(appData.correction_pack.state, 'APPROVED');
      assert.equal(appData.incident.status, 'RESOLVED');
      assert.equal(appData.incident.resolved_by_correction_pack_id, packId);
    });
  });
});
