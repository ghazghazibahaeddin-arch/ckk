import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

const BASE_URL = 'http://localhost:3000';

describe('CCK Action Gate & Precondition Verification', () => {
  test('ALLOW: Action succeeds when prerequisite fact is VALID', async () => {
    // Ensure order:test-gate-01 is valid
    await fetch(`${BASE_URL}/api/v1/facts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entity_id: 'order:test-gate-01',
        field_name: 'status',
        value: 'paid',
        source: 'test_fixture',
      }),
    });

    await fetch(`${BASE_URL}/api/v1/dependencies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj-prod-ecommerce',
        action_capability: 'logistics.ship',
        required_fact_entity: 'order:test-gate-01',
        required_fact_field: 'status',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        capability: 'logistics.ship',
        target: 'courier.fedex',
        command: 'dispatch_parcel(order_id="test-gate-01")',
        entity_id: 'order:test-gate-01',
        severity: 'MUTATION',
      }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision, 'ALLOW');
    assert.ok(data.risk_score <= 0.2);
    assert.ok(data.receipt_id);
  });

  test('BLOCK: Action blocked when prerequisite fact drifts to invalidated state', async () => {
    // Invalidate order:test-gate-01
    await fetch(`${BASE_URL}/api/v1/facts/invalidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entity_id: 'order:test-gate-01',
        field_name: 'status',
        new_value: 'refunded',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        capability: 'logistics.ship',
        target: 'courier.fedex',
        command: 'dispatch_parcel(order_id="test-gate-01")',
        entity_id: 'order:test-gate-01',
        severity: 'MUTATION',
      }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision, 'BLOCK');
    assert.ok(data.risk_score >= 0.9);
    assert.match(data.reason, /Precondition drift detected/);
  });

  test('BLOCK: Destructive root command (rm -rf /) is unconditionally blocked', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        capability: 'bash.execute',
        target: 'server.root',
        command: 'rm -rf / --no-preserve-root',
        severity: 'DESTRUCTIVE',
      }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision, 'BLOCK');
    assert.equal(data.risk_score, 1.0);
    assert.match(data.reason, /destructive root command detected/i);
  });

  test('REQUIRE_APPROVAL: System mutations trigger human supervisor queue', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        capability: 'bash.execute',
        target: 'systemd.service',
        command: 'systemctl stop nginx',
        severity: 'MUTATION',
      }),
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision, 'REQUIRE_APPROVAL');
    assert.ok(data.risk_score >= 0.7);
  });
});
