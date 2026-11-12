/**
 * CCK Full Security Red Team & Penetration Test Suite
 *
 * Verifies defensive remediation against:
 * 1. Webhook Signature Bypass ('test_bypass' exploit attempt)
 * 2. Webhook Replay Attacks (Timestamp window enforcement)
 * 3. API Key Hash Disclosure (Offline cracking prevention)
 * 4. Cross-Project Key Revocation (Unauthorized project tampering)
 * 5. Cross-Tenant Project Deletion (Tenant isolation enforcement)
 * 6. Action Gate Invalid / Forged Bearer Token Rejection
 * 7. Action Gate Revoked API Key Rejection
 * 8. Malicious Command Injections (:(){ :|:& };:, cat /etc/shadow, dd if=/dev/zero)
 * 9. Unauthorized Human Approval Resolution (RBAC enforcement)
 * 10. Security Response Headers (X-Content-Type-Options, X-Frame-Options, CSP)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

const BASE_URL = 'http://127.0.0.1:3000';

describe('CCK Red Team Security & Penetration Verification Suite', () => {
  let createdProjectId: string;
  let testKeyId: string;
  let testPlaintextToken: string;
  let foreignProjectId: string;

  before(async () => {
    // 1. Create a primary project in tenant-alpha
    const p1 = await fetch(`${BASE_URL}/api/v1/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': 'tenant-alpha' },
      body: JSON.stringify({ name: 'Alpha Secure Project', tenant_id: 'tenant-alpha' }),
    });
    const p1Data = await p1.json();
    createdProjectId = p1Data.project_id;

    // 2. Mint an API key for Alpha project
    const k1 = await fetch(`${BASE_URL}/api/v1/projects/${createdProjectId}/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alpha Agent Key' }),
    });
    const k1Data = await k1.json();
    testKeyId = k1Data.key_id;
    testPlaintextToken = k1Data.token;

    // 3. Create a foreign project in tenant-bravo
    const p2 = await fetch(`${BASE_URL}/api/v1/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': 'tenant-bravo' },
      body: JSON.stringify({ name: 'Bravo Foreign Project', tenant_id: 'tenant-bravo' }),
    });
    const p2Data = await p2.json();
    foreignProjectId = p2Data.project_id;
  });

  test('RED-01: Exploit Attempt: Webhook signature bypass using "test_bypass" header is REJECTED', async () => {
    const payload = {
      entity_id: 'order:exploit_wh',
      field_name: 'payment_status',
      value: 'paid',
      attack_attempt: 'bypass_with_hardcoded_string',
    };

    const res = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-cck-signature': 'test_bypass',
      },
      body: JSON.stringify(payload),
    });

    // Must be rejected with 401 Unauthorized!
    assert.equal(res.status, 401, 'Backdoor header test_bypass must be rejected with 401');
    const data = await res.json();
    assert.equal(data.error, 'INVALID_SIGNATURE');
  });

  test('RED-02: Exploit Attempt: Webhook replay attack with expired timestamp is REJECTED', async () => {
    const secret = 'cck_whsec_live_default';
    const payload = { entity_id: 'order:replay_01', field_name: 'status', value: 'refunded' };
    const rawStr = JSON.stringify(payload);
    const validSig = crypto.createHmac('sha256', secret).update(rawStr).digest('hex');

    // Send with timestamp 10 minutes (600s) in the past
    const expiredTimestamp = Math.floor(Date.now() / 1000) - 600;

    const res = await fetch(`${BASE_URL}/api/v1/webhooks/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-cck-signature': `sha256=${validSig}`,
        'x-cck-timestamp': String(expiredTimestamp),
      },
      body: rawStr,
    });

    assert.equal(res.status, 401, 'Webhook with expired timestamp must be rejected');
    const data = await res.json();
    assert.equal(data.error, 'EXPIRED_TIMESTAMP');
  });

  test('RED-03: Secret Disclosure Defense: GET /api/v1/projects/:id/keys NEVER exposes key_hash', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/projects/${createdProjectId}/keys`);
    assert.equal(res.status, 200);
    const keys = await res.json();
    assert.ok(Array.isArray(keys) && keys.length > 0);

    for (const key of keys) {
      assert.equal(key.key_hash, undefined, 'CRITICAL: key_hash must never be returned in API response');
      assert.ok(key.key_id);
      assert.ok(key.key_prefix);
      assert.ok(key.name);
    }
  });

  test('RED-04: Cross-Project Key Revocation Defense: Cannot revoke Key of Project A via Project B URL', async () => {
    // Attempt to revoke testKeyId (belongs to createdProjectId) through foreignProjectId URL
    const res = await fetch(`${BASE_URL}/api/v1/projects/${foreignProjectId}/keys/${testKeyId}`, {
      method: 'DELETE',
    });

    assert.equal(res.status, 403, 'Cross-project key revocation must be rejected with 403 Forbidden');
    const data = await res.json();
    assert.equal(data.error, 'FORBIDDEN');
  });

  test('RED-05: Cross-Tenant Project Deletion Defense: Tenant Bravo cannot delete Tenant Alpha project', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/projects/${createdProjectId}`, {
      method: 'DELETE',
      headers: { 'x-tenant-id': 'tenant-bravo' },
    });

    assert.equal(res.status, 403, 'Cross-tenant project deletion must be rejected with 403 Forbidden');
    const data = await res.json();
    assert.equal(data.error, 'FORBIDDEN');
  });

  test('RED-06: Action Gate Authentication: Forged / Invalid Bearer token is REJECTED', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer cck_live_forged_fake_token_1234567890',
      },
      body: JSON.stringify({
        capability: 'logistics.ship',
        target: 'courier.fedex',
        command: 'ship_order(101)',
      }),
    });

    assert.equal(res.status, 401, 'Invalid agent token must be rejected with 401 Unauthorized');
    const data = await res.json();
    assert.equal(data.error, 'INVALID_CREDENTIALS');
  });

  test('RED-07: Action Gate Authentication: Revoked API Key is strictly BLOCKED with 403', async () => {
    // Revoke the key legitimately first
    const revokeRes = await fetch(`${BASE_URL}/api/v1/projects/${createdProjectId}/keys/${testKeyId}`, {
      method: 'DELETE',
    });
    assert.equal(revokeRes.status, 200);

    // Attempt action evaluation using the revoked token
    const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${testPlaintextToken}`,
      },
      body: JSON.stringify({
        capability: 'database.query',
        target: 'customers_db',
        command: 'SELECT * FROM users',
      }),
    });

    assert.equal(res.status, 403, 'Revoked agent token must be blocked with 403 Forbidden');
    const data = await res.json();
    assert.equal(data.error, 'REVOKED');
  });

  test('RED-08: Malicious Command Injections (:(){ :|:& };:, cat /etc/shadow, dd if=/dev/zero) fail closed', async () => {
    const attackCommands = [
      ':(){ :|:& };:',
      'cat /etc/shadow',
      'dd if=/dev/zero of=/dev/sda',
      'format c: /q',
      'truncate -s 0 /etc/passwd',
    ];

    for (const cmd of attackCommands) {
      const res = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          capability: 'bash.execute',
          target: 'server.root',
          command: cmd,
          severity: 'DESTRUCTIVE',
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.decision, 'BLOCK', `Command "${cmd}" must be BLOCKED`);
      assert.equal(data.risk_score, 1.0, `Command "${cmd}" must have risk score 1.0`);
      assert.ok(data.reason.includes('POL-SEC-001'), 'Must match security policy POL-SEC-001');
    }
  });

  test('RED-09: RBAC Enforcement: Standard operator cannot resolve human approvals', async () => {
    // 1. Submit an action requiring human approval
    const evalRes = await fetch(`${BASE_URL}/api/v1/actions/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        capability: 'system.service',
        target: 'systemctl',
        command: 'systemctl stop nginx',
        severity: 'MUTATION',
      }),
    });
    assert.equal(evalRes.status, 200);
    const evalData = await evalRes.json();
    assert.equal(evalData.decision, 'REQUIRE_APPROVAL');

    // Retrieve pending approvals
    const listRes = await fetch(`${BASE_URL}/api/v1/approvals`);
    const approvals = await listRes.json();
    assert.ok(approvals.length > 0);
    const approvalId = approvals[0].approval_id;

    // 2. Attempt unauthorized resolution as operator
    const unauthorizedRes = await fetch(`${BASE_URL}/api/v1/approvals/${approvalId}/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-user-role': 'operator',
      },
      body: JSON.stringify({ approved: true, notes: 'Malicious operator auto-approval' }),
    });

    assert.equal(unauthorizedRes.status, 403, 'Operator role must be forbidden from resolving approvals');
    const unauthData = await unauthorizedRes.json();
    assert.equal(unauthData.error, 'FORBIDDEN');

    // 3. Authorized resolution as supervisor
    const supervisorRes = await fetch(`${BASE_URL}/api/v1/approvals/${approvalId}/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-user-role': 'supervisor',
      },
      body: JSON.stringify({ approved: true, notes: 'Authorized supervisor signature' }),
    });
    assert.equal(supervisorRes.status, 200, 'Supervisor role must be allowed to resolve approvals');
  });

  test('RED-10: Security Headers: X-Content-Type-Options, X-Frame-Options, CSP are present', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/health`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
    assert.ok(res.headers.get('content-security-policy'));
    assert.ok(res.headers.get('strict-transport-security'));
  });
});
