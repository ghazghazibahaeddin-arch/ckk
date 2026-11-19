import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createTenantSession, type TenantTestSession } from './_test_auth.ts';

const BASE_URL = 'http://localhost:3000';

describe('CCK Failure Lab Scenarios', () => {
  let session: TenantTestSession;

  before(async () => {
    session = await createTenantSession(BASE_URL, 'failurelab');
  });

  test('Scenario A: Inventory Drift executes deterministically', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/failure-lab/run`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({ scenario_id: 'scenario_a_inventory' }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.scenario_id, 'scenario_a_inventory');
    assert.equal(data.before_drift.verdict, 'ALLOW');
    assert.equal(data.before_drift.fact_value, 5);
    assert.equal(data.after_drift.verdict, 'BLOCK');
    assert.equal(data.after_drift.fact_value, 0);
    assert.ok(data.before_drift.receipt.receipt_id);
    assert.ok(data.after_drift.receipt.receipt_id);
  });

  test('Scenario B: Permission Revocation executes deterministically', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/failure-lab/run`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({ scenario_id: 'scenario_b_permission' }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.scenario_id, 'scenario_b_permission');
    assert.equal(data.before_drift.verdict, 'ALLOW');
    assert.equal(data.before_drift.fact_value, 'active');
    assert.equal(data.after_drift.verdict, 'BLOCK');
    assert.equal(data.after_drift.fact_value, 'revoked');
  });

  test('Scenario C: Refund Dispute executes deterministically', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/failure-lab/run`, {
      method: 'POST',
      headers: session.headers,
      body: JSON.stringify({ scenario_id: 'scenario_c_refund' }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.scenario_id, 'scenario_c_refund');
    assert.equal(data.before_drift.verdict, 'ALLOW');
    assert.equal(data.before_drift.fact_value, 'eligible_for_refund');
    assert.equal(data.after_drift.verdict, 'BLOCK');
    assert.equal(data.after_drift.fact_value, 'disputed');
  });
});
