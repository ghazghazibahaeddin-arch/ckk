import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { CCKClient } from '../../src/sdk/client.ts';
import type { ConnectorManifest } from '../../src/intelligence/types.ts';

const execFileAsync = promisify(execFile);
const BASE_URL = 'http://localhost:3000';

describe('CCK Batch 3: Public Source Health, Connector SDK & 12-Test Harness, CLI Scanner, GitHub PR Guardian & Signed Trust Registry E2E', () => {
  const ts = Date.now();
  const userA = {
    username: `batch3_a_${ts}`,
    email: `batch3_a_${ts}@example.com`,
    password: 'StrongPassword!Batch3A',
    display_name: 'Batch3 Publisher Alpha',
  };
  const userB = {
    username: `batch3_b_${ts}`,
    email: `batch3_b_${ts}@example.com`,
    password: 'StrongPassword!Batch3B',
    display_name: 'Batch3 Challenger Beta',
  };

  let tenantA = '';
  let tokenA = '';
  let tenantB = '';
  let tokenB = '';
  let tempScanDir = '';

  before(async () => {
    for (let i = 0; i < 20; i++) {
      try {
        const res = await fetch(`${BASE_URL}/health`);
        if (res.ok) break;
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }

    const regA = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userA),
    });
    assert.equal(regA.status, 201);
    const dataA = await regA.json();
    tenantA = dataA.user.tenant_id;
    tokenA = dataA.token;

    const regB = await fetch(`${BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userB),
    });
    assert.equal(regB.status, 201);
    const dataB = await regB.json();
    tenantB = dataB.user.tenant_id;
    tokenB = dataB.token;

    // Prepare isolated local directory for CLI cck scan test (contains dangerous config + ignored .env/.pem)
    tempScanDir = fs.mkdtempSync(path.join(os.tmpdir(), `cck-scan-e2e-${ts}-`));
    fs.writeFileSync(
      path.join(tempScanDir, '.env'),
      'STRIPE_API_KEY=sk_live_must_be_ignored_by_scanner_12345678\n',
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tempScanDir, 'cert.pem'),
      '-----BEGIN PRIVATE KEY-----\nIGNORED_PEM_CONTENT\n-----END PRIVATE KEY-----\n',
      'utf-8'
    );
    fs.writeFileSync(
      path.join(tempScanDir, 'mcp.json'),
      JSON.stringify(
        {
          mcpServers: {
            'dangerous-admin-tool': {
              command: 'node',
              args: ['server.js'],
              url: 'http://169.254.169.254/latest/meta-data/',
              env: {
                API_TOKEN: 'sk_live_exposed_in_mcp_config_9999999999',
              },
              capabilities: ['*', 'shell:exec', 'secrets:read'],
            },
          },
        },
        null,
        2
      ),
      'utf-8'
    );
  });

  after(() => {
    if (tempScanDir && fs.existsSync(tempScanDir)) {
      fs.rmSync(tempScanDir, { recursive: true, force: true });
    }
  });

  test('1. Feature 7 — Public Source Health Profile: Insufficient Data Withholds SLA, Real Telemetry Computes Reproducible Metrics, Outage Degrades Health, Privacy Consent Enforced', async () => {
    // 1. Register a real Change Radar source for Tenant A
    const srcRes = await fetch(`${BASE_URL}/api/v1/radar/sources`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        name: `Batch3-ERP-Source-${ts}`,
        source_type: 'API_POLL',
        poll_interval_seconds: 30,
        schema_version: '2.0',
      }),
    });
    assert.equal(srcRes.status, 201);
    const source = await srcRes.json();

    // 2. Poll only 2 items (< minSampleThreshold=5) -> must withhold SLA & return INSUFFICIENT_DATA
    const pollSmall = await fetch(`${BASE_URL}/api/v1/radar/sources/${source.source_id}/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        inline_items: [
          { entity_id: `ent:b3:${ts}:1`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 3000).toISOString() },
          { entity_id: `ent:b3:${ts}:2`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 2000).toISOString() },
        ],
      }),
    });
    assert.equal(pollSmall.status, 200);

    const clientA = new CCKClient({ baseUrl: BASE_URL, sessionToken: tokenA });
    const insufficient = (await clientA.computeSourceHealth(source.source_id, { min_sample_threshold: 5 })) as any;
    assert.equal(insufficient.sufficiency_status, 'INSUFFICIENT_DATA');
    assert.equal(insufficient.is_public, false, 'Source Health Profile must be private by default');
    assert.equal(insufficient.metrics.median_freshness.value, null);
    assert.equal(insufficient.metrics.verification_success_rate.value, null);
    assert.equal(insufficient.metrics.verification_success_rate.display, 'Insufficient Data');

    // Public access while private -> 403 PRIVATE_PROFILE
    const deniedPub = await fetch(`${BASE_URL}/api/v1/public/sources/${source.source_id}/health`);
    assert.equal(deniedPub.status, 403);

    // Enabling public visibility without explicit_consent: true -> 400 CONSENT_REQUIRED
    const noConsent = await fetch(`${BASE_URL}/api/v1/sources/${source.source_id}/health/visibility`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ is_public: true }),
    });
    assert.equal(noConsent.status, 400);

    // 3. Ingest 5 more samples -> now >= 5 total samples -> reproducible telemetry + methodology
    const pollMore = await fetch(`${BASE_URL}/api/v1/radar/sources/${source.source_id}/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        inline_items: [
          { entity_id: `ent:b3:${ts}:3`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 5000).toISOString() },
          { entity_id: `ent:b3:${ts}:4`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 4000).toISOString() },
          { entity_id: `ent:b3:${ts}:5`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 3000).toISOString() },
          { entity_id: `ent:b3:${ts}:6`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 2000).toISOString() },
          { entity_id: `ent:b3:${ts}:7`, field_name: 'status', value: 'READY', event_timestamp: new Date(Date.now() - 1000).toISOString() },
        ],
      }),
    });
    assert.equal(pollMore.status, 200);

    const healthyProfile = (await clientA.computeSourceHealth(source.source_id, {
      is_public: true,
      min_sample_threshold: 5,
    })) as any;
    assert.equal(healthyProfile.sufficiency_status, 'SUFFICIENT_DATA');
    assert.equal(healthyProfile.is_public, true);
    assert.equal(typeof healthyProfile.metrics.median_freshness.value, 'number');
    assert.ok(healthyProfile.metrics.median_freshness.calculation_method.length > 10);
    assert.ok(healthyProfile.metrics.verification_success_rate.scope_excluded.includes('Action Gate BLOCK'));

    // Public read succeeds and strictly omits tenant_id & private consent fields
    const pubRes = await fetch(`${BASE_URL}/api/v1/public/sources/${source.source_id}/health`);
    assert.equal(pubRes.status, 200);
    const pubJson = await pubRes.json();
    assert.equal((pubJson as any).tenant_id, undefined);
    assert.equal(pubJson.visibility, 'PUBLIC');

    // 4. Simulate 3 consecutive upstream poll outages -> failure count & error rate update
    for (let i = 0; i < 3; i++) {
      await fetch(`${BASE_URL}/api/v1/radar/sources/${source.source_id}/poll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
        body: JSON.stringify({ simulate_error: 'HTTP 503 Upstream Timeout' }),
      });
    }
    const degradedProfile = (await clientA.computeSourceHealth(source.source_id)) as any;
    assert.ok(degradedProfile.failure_count >= 3);
    assert.ok(degradedProfile.metrics.error_rate.value > 0);
  });

  test('2. Feature 8 — Connector SDK & 12-Test Harness: Declared vs Verified Capabilities, Secret Non-Leakage, Bad Manifest Rejected & Unified Core Ingestion', async () => {
    const clientA = new CCKClient({ baseUrl: BASE_URL, sessionToken: tokenA });

    const validManifest: ConnectorManifest = {
      connector_id: `conn-b3-${ts}`,
      name: 'Batch3 Inventory Connector',
      version: '1.2.0',
      publisher: 'acme-connectors',
      supported_source_types: ['API_POLL'],
      required_permissions: ['facts:write', 'evidence:write'],
      required_secrets_refs: ['ERP_API_TOKEN'],
      declared_capabilities: ['READ', 'VERIFY_SOURCE', 'HEALTH_CHECK', 'RATE_LIMIT_BACKOFF', 'CONDITIONAL_WRITE'],
      network_requirements: {
        allowed_hosts: ['erp.example.com'],
        protocols: ['https'],
        requires_tls: true,
      },
      compatibility_range: {
        min_cck_version: '0.1.0',
        max_cck_version: '0.9.9',
      },
    };

    // Run 12-test automated harness
    const harness = (await clientA.runConnectorHarness(
      validManifest as unknown as Record<string, unknown>,
      [{ entity_id: `entity:conn:${ts}`, field_name: 'status', value: { ok: true }, version: 1 }]
    )) as any;
    assert.equal(harness.passed, true);
    assert.equal(harness.total_tests, 12);
    assert.equal(harness.passed_tests, 12);
    assert.equal(harness.credentials_leaked, false);
    assert.ok(harness.verified_capabilities.includes('READ'));
    assert.ok(!harness.verified_capabilities.includes('COMPENSATION'));

    // Submit package backed by harness report
    const subRes = await fetch(`${BASE_URL}/api/v1/connectors/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        manifest: validManifest,
        harness_report_id: harness.report_id,
        submitted_by: userA.username,
      }),
    });
    assert.equal(subRes.status, 201);
    const sub = await subRes.json();
    assert.equal(sub.review_status, 'APPROVED_FOR_SANDBOX');
    assert.equal(sub.harness_passed, true);
    assert.notEqual(sub.verified_capabilities.length, 0);

    // Unified core ingestion directly feeds Facts, Evidence, Change Radar & Source Health without parallel storage
    const ingestRes = await fetch(`${BASE_URL}/api/v1/connectors/submissions/${sub.submission_id}/consume-ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        items: [
          {
            entity_id: `entity:conn:${ts}`,
            field_name: 'settlement_status',
            value: { settled: true, amount: 250 },
            version: 1,
          },
        ],
      }),
    });
    assert.equal(ingestRes.status, 200);
    const ingestJson = await ingestRes.json();
    assert.equal(ingestJson.ingested_facts, 1);
    assert.equal(ingestJson.ingested_evidence, 1);
    assert.ok(ingestJson.source_health_profile_id);

    // Manifest with literal secret inside required_secrets_refs MUST be rejected
    const badManifest: ConnectorManifest = {
      ...validManifest,
      connector_id: `conn-bad-${ts}`,
      required_secrets_refs: ['sk_live_literal_secret_leak_123456'],
    };
    const badSubRes = await fetch(`${BASE_URL}/api/v1/connectors/submissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        manifest: badManifest,
        harness_report_id: harness.report_id,
      }),
    });
    assert.equal(badSubRes.status, 400);
    const badErr = await badSubRes.json();
    assert.equal(badErr.error, 'INVALID_MANIFEST');
  });

  test('3. Feature 18 — One-Command CCK CLI Scanner (`cck scan`): Local-Only Zero-Auth Execution, Ignores .env/.pem, SARIF v2.1.0 + JSON Repeatability, No False "Safe" Claims', async () => {
    let stdout = '';
    let exitCode = 0;
    const tsxBin = path.join(process.cwd(), 'node_modules', '.bin', 'tsx');
    try {
      const res = await execFileAsync(
        tsxBin,
        ['src/cli/cck.ts', 'scan', tempScanDir, '--format', 'sarif'],
        { cwd: process.cwd(), env: { ...process.env, NO_COLOR: '1' } }
      );
      stdout = res.stdout;
    } catch (err: any) {
      stdout = err.stdout || '';
      exitCode = typeof err.code === 'number' ? err.code : 1;
    }

    assert.equal(exitCode, 2, 'CRITICAL findings must yield non-zero exit code 2');
    const sarif = JSON.parse(stdout);
    assert.equal(sarif.version, '2.1.0');
    const results = sarif.runs?.[0]?.results || [];
    assert.ok(results.length >= 2, 'Scanner should find CRITICAL secret and wildcard capability / metadata URL findings in mcp.json');

    const joined = JSON.stringify(sarif);
    assert.ok(!joined.includes('must_be_ignored_by_scanner'), '.env files must be excluded from scan');
    assert.ok(!joined.includes('IGNORED_PEM_CONTENT'), '.pem files must be excluded from scan');
    assert.ok(!joined.includes('sk_live_exposed_in_mcp_config_9999999999'), 'Detected secrets must be redacted in scanner output');

    // Run JSON format twice to verify repeatable digest and absence of "Safe" marketing claim
    let jsonOut1 = '';
    let jsonOut2 = '';
    try {
      await execFileAsync(tsxBin, ['src/cli/cck.ts', 'scan', tempScanDir, '--format', 'json'], { cwd: process.cwd() });
    } catch (err: any) {
      jsonOut1 = err.stdout || '';
    }
    try {
      await execFileAsync(tsxBin, ['src/cli/cck.ts', 'scan', tempScanDir, '--format', 'json'], { cwd: process.cwd() });
    } catch (err: any) {
      jsonOut2 = err.stdout || '';
    }

    const parsed1 = JSON.parse(jsonOut1);
    const parsed2 = JSON.parse(jsonOut2);
    assert.equal(parsed1.mode, 'LOCAL');
    assert.equal(parsed1.uploaded_to_cloud, false);
    assert.equal(parsed1.report_digest_sha256, parsed2.report_digest_sha256, 'Canonical digest must be deterministic across identical scans');
    assert.ok(parsed1.findings.some((f: any) => f.certainty === 'CONFIRMED'));
    assert.ok(!/\b(100%\s*safe|fully\s*secure|zero\s*risk)\b/i.test(jsonOut1));

    // Verify opt-in upload enforcement on backend (fails closed if consent_upload !== true)
    const deniedUpload = await fetch(`${BASE_URL}/api/v1/scanner/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ report: parsed1, consent_upload: false }),
    });
    assert.equal(deniedUpload.status, 400);
  });

  test('4. Feature 19 — GitHub PR Guardian: Verdicts (PASS / WARNING / BLOCKING_FINDING / INSUFFICIENT_COVERAGE) & Least-Privilege Workflow Check', async () => {
    const clientA = new CCKClient({ baseUrl: BASE_URL, sessionToken: tokenA });

    // A) Safe PR (no tool modifications) -> PASS
    const passRep = (await clientA.evaluatePrGuardian({
      repository: 'acme/agent-tools',
      pr_number: 101,
      base_sha: '111111111111',
      head_sha: '222222222222',
      changed_files: ['README.md'],
      base_tools: [],
      head_tools: [],
      coverage_available: true,
    })) as any;
    assert.equal(passRep.verdict, 'PASS');
    assert.equal(passRep.merge_blocked, false);

    // B) Escalated permissions + unapproved private metadata IP -> BLOCKING_FINDING
    const blockRep = (await clientA.evaluatePrGuardian({
      repository: 'acme/agent-tools',
      pr_number: 102,
      base_sha: 'aaaa1111',
      head_sha: 'bbbb2222',
      changed_files: ['mcp.json'],
      base_tools: [
        {
          tool_id: 'orders-tool',
          name: 'Orders Tool',
          permissions: ['orders:read'],
          endpoints: ['https://api.example.com/v1/orders'],
        },
      ],
      head_tools: [
        {
          tool_id: 'orders-tool',
          name: 'Orders Tool',
          permissions: ['orders:read', 'admin:write'],
          endpoints: ['https://api.example.com/v1/orders', 'http://169.254.169.254/latest/meta-data/'],
        },
      ],
      coverage_available: true,
    })) as any;
    assert.equal(blockRep.verdict, 'BLOCKING_FINDING');
    assert.equal(blockRep.merge_blocked, true);

    // C) Missing / broken diff coverage -> INSUFFICIENT_COVERAGE (never false PASS)
    const missingCov = (await clientA.evaluatePrGuardian({
      repository: 'acme/agent-tools',
      pr_number: 103,
      changed_files: ['mcp.json'],
      base_tools: [],
      head_tools: [],
      coverage_available: false,
    })) as any;
    assert.equal(missingCov.verdict, 'INSUFFICIENT_COVERAGE');

    // D) Inspect GitHub Workflow & Action for least-privilege configuration (no write-all, no pull_request_target)
    const wfContent = fs.readFileSync(path.join(process.cwd(), '.github/workflows/cck-pr-guardian.yml'), 'utf-8');
    assert.ok(wfContent.includes('contents: read'));
    assert.ok(wfContent.includes('security-events: write'));
    assert.ok(!wfContent.includes('write-all'));
    assert.ok(!wfContent.includes('pull_request_target'));
  });

  test('5. Feature 20 & Security Red Team — Organic Loop, Signed Trust Profile (Ed25519), DLP Blocking, Tamper Detection, Supersede/Expire/Revoke, Anti-Spam & Ownership Isolation', async () => {
    const clientA = new CCKClient({ baseUrl: BASE_URL, sessionToken: tokenA });
    const artifactId = `mcp:refund-guard-${ts}`;

    // A) DLP Guard blocks public Trust Profile containing secret, tenant_id, or private metadata IP
    const leakRes = await fetch(`${BASE_URL}/api/v1/trust/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        visibility: 'PUBLIC',
        artifact_identity: `mcp:leaky-${ts}`,
        artifact_type: 'MCP_TOOL',
        name: 'Leaky Tool',
        publisher_name: 'acme',
        version: '1.0.0',
        fingerprint: 'a'.repeat(64),
        assessment_statement: `Evaluated with ${tenantA} token sk_live_abc1234567890`,
      }),
    });
    assert.equal(leakRes.status, 400);
    const leakJson = await leakRes.json();
    assert.equal(leakJson.error_code, 'PUBLIC_DATA_LEAKAGE_BLOCKED');

    // B) Reject absolute safety claims ("100% Safe" / "Fully Secure")
    const absClaimRes = await fetch(`${BASE_URL}/api/v1/trust/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        visibility: 'PUBLIC',
        artifact_identity: `mcp:hype-${ts}`,
        artifact_type: 'MCP_TOOL',
        name: 'Hype Tool',
        publisher_name: 'acme',
        version: '1.0.0',
        fingerprint: 'b'.repeat(64),
        assessment_statement: 'This tool is 100% safe and fully secure forever.',
      }),
    });
    assert.equal(absClaimRes.status, 400);
    const absJson = await absClaimRes.json();
    assert.equal(absJson.error_code, 'FORBIDDEN_ABSOLUTE_SECURITY_CLAIM');

    // C) Obtain Publisher Challenge & publish signed v1.0.0 profile (VERIFIED_PUBLISHER)
    const chalRes = await fetch(`${BASE_URL}/api/v1/trust/publisher-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ artifact_identity: artifactId, publisher_name: 'acme-platform' }),
    });
    assert.equal(chalRes.status, 200);
    const chal = await chalRes.json();

    const v1 = (await clientA.createTrustProfile({
      visibility: 'PUBLIC',
      artifact_identity: artifactId,
      artifact_type: 'MCP_TOOL',
      name: 'Refund Guard Tool',
      publisher_name: 'acme-platform',
      claimed_identity: 'acme-platform',
      ownership_proof_token: chal.ownership_proof_token,
      version: '1.0.0',
      fingerprint: '1'.repeat(64),
      passed_checks: ['tool_identity_fingerprint', 'least_privilege_static'],
      failed_checks: [],
      unsupported_checks: ['live_production_traffic'],
    })) as any;
    assert.equal(v1.publisher_verification, 'VERIFIED_PUBLISHER');
    assert.equal(v1.status, 'VERIFIED_FOR_A_DEFINED_SCOPE');
    assert.equal(v1.signature.algorithm, 'Ed25519');

    // D) Tenant B attempts to hijack Tenant A's artifact_identity -> 403 PUBLISHER_OWNERSHIP_CONFLICT
    const hijackRes = await fetch(`${BASE_URL}/api/v1/trust/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenB}` },
      body: JSON.stringify({
        visibility: 'PUBLIC',
        artifact_identity: artifactId,
        artifact_type: 'MCP_TOOL',
        name: 'Refund Guard Tool Hijack',
        publisher_name: 'acme-platform',
        version: '9.9.9',
        fingerprint: '9'.repeat(64),
      }),
    });
    assert.equal(hijackRes.status, 403);

    // E) Public verification & search + SVG badge check (Zero Login Required)
    const searchItems = (await clientA.searchTrustRegistry(`refund-guard-${ts}`)) as any[];
    assert.ok(searchItems.some((item) => item.profile_id === v1.profile_id));
    assert.equal((searchItems[0] as any).owner_tenant_id, undefined, 'Public registry must strip owner_tenant_id');

    const pubVerify = (await clientA.verifyPublicTrustProfile(v1.profile_id)) as any;
    assert.equal(pubVerify.verification.integrity_valid, true);
    assert.equal(pubVerify.verification.signature_valid, true);

    const badgeV1 = await fetch(`${BASE_URL}/api/v1/trust/profiles/${v1.profile_id}/badge.svg`);
    assert.equal(badgeV1.status, 200);
    const svgV1 = await badgeV1.text();
    assert.ok(svgV1.includes('v1.0.0'));

    // F) Tamper Probe: alter assessment_statement -> Ed25519 verification fails cleanly!
    const tamperRes = await fetch(`${BASE_URL}/api/v1/public/trust/profiles/${v1.profile_id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tamper_probe: { assessment_statement: 'Tampered outside scope' } }),
    });
    const tamperJson = await tamperRes.json();
    assert.equal(tamperJson.integrity_valid, false);
    assert.equal(tamperJson.signature_valid, false);

    // G) Duplicate artifact + version + fingerprint -> 409 DUPLICATE_ARTIFACT_VERSION
    const dupRes = await fetch(`${BASE_URL}/api/v1/trust/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        visibility: 'PUBLIC',
        artifact_identity: artifactId,
        artifact_type: 'MCP_TOOL',
        name: 'Refund Guard Tool',
        publisher_name: 'acme-platform',
        version: '1.0.0',
        fingerprint: '1'.repeat(64),
      }),
    });
    assert.equal(dupRes.status, 409);

    // H) Publish v2.0.0 -> v1.0.0 automatically SUPERSEDED + outdated notice + SVG badge reflects SUPERSEDED
    const v2 = (await clientA.createTrustProfile({
      visibility: 'PUBLIC',
      artifact_identity: artifactId,
      artifact_type: 'MCP_TOOL',
      name: 'Refund Guard Tool',
      publisher_name: 'acme-platform',
      ownership_proof_token: chal.ownership_proof_token,
      version: '2.0.0',
      fingerprint: '2'.repeat(64),
      passed_checks: ['tool_identity_fingerprint', 'least_privilege_static'],
    })) as any;
    assert.equal(v2.version, '2.0.0');

    const pubV1After = (await clientA.verifyPublicTrustProfile(v1.profile_id)) as any;
    assert.equal(pubV1After.profile.status, 'SUPERSEDED');
    assert.ok(pubV1After.outdated_notice.includes('v2.0.0') || pubV1After.outdated_notice.includes(v2.profile_id));

    const badgeSuperseded = await (await fetch(`${BASE_URL}/api/v1/trust/profiles/${v1.profile_id}/badge.svg`)).text();
    assert.ok(badgeSuperseded.includes('SUPERSEDED'));

    // I) Revoke v2.0.0 -> badge immediately shows REVOKED
    const revRes = await fetch(`${BASE_URL}/api/v1/trust/profiles/${v2.profile_id}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ reason: 'Security advisory revoked v2.0.0' }),
    });
    assert.equal(revRes.status, 200);
    const badgeRevoked = await (await fetch(`${BASE_URL}/api/v1/trust/profiles/${v2.profile_id}/badge.svg`)).text();
    assert.ok(badgeRevoked.includes('REVOKED'));

    // J) Expired profile (`ttl_days: -1`) -> EXPIRED status & badge
    const expProfile = (await clientA.createTrustProfile({
      visibility: 'PUBLIC',
      artifact_identity: `mcp:expired-check-${ts}`,
      artifact_type: 'MCP_TOOL',
      name: 'Expiring Check Tool',
      publisher_name: 'acme-platform',
      version: '0.9.0',
      fingerprint: 'e'.repeat(64),
      ttl_days: -1,
      passed_checks: ['static_scan'],
    })) as any;
    const badgeExp = await (await fetch(`${BASE_URL}/api/v1/trust/profiles/${expProfile.profile_id}/badge.svg`)).text();
    assert.ok(badgeExp.includes('EXPIRED'));

    // K) Private profile cannot be accessed via public verification endpoint -> 403
    const privProfile = (await clientA.createTrustProfile({
      visibility: 'PRIVATE',
      artifact_identity: `mcp:private-only-${ts}`,
      artifact_type: 'AGENT_PACK',
      name: 'Private Agent Pack',
      publisher_name: 'acme-platform',
      version: '1.0.0',
      fingerprint: 'f'.repeat(64),
      passed_checks: ['static_scan'],
    })) as any;
    const privDenied = await fetch(`${BASE_URL}/api/v1/public/trust/profiles/${privProfile.profile_id}`);
    assert.equal(privDenied.status, 403);

    // L) Anti-Spam rate limit enforcement (429 when exceeding tenant per-minute budget)
    let hitRateLimit = false;
    for (let i = 0; i < 6; i++) {
      const rlRes = await fetch(`${BASE_URL}/api/v1/trust/profiles`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenB}`,
          'x-cck-test-rate-limit': '2',
        },
        body: JSON.stringify({
          visibility: 'PRIVATE',
          artifact_identity: `mcp:rl-${ts}-${i}`,
          artifact_type: 'MCP_TOOL',
          name: `RL Tool ${i}`,
          publisher_name: 'beta',
          version: '1.0.0',
          fingerprint: String(i).repeat(64),
        }),
      });
      if (rlRes.status === 429) {
        hitRateLimit = true;
        break;
      }
    }
    assert.equal(hitRateLimit, true, 'Anti-spam rate limiting must return HTTP 429 when tenant quota is exceeded');

    // M) Privacy-Respecting Analytics + Explicit Opt-Out stops counter increments
    await fetch(`${BASE_URL}/api/v1/analytics/privacy-settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ analytics_enabled: false }),
    });
    const beforeOptOut = await (await fetch(`${BASE_URL}/api/v1/analytics/adoption`)).json();
    await fetch(`${BASE_URL}/api/v1/analytics/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ event_type: 'CLI_SCAN' }),
    });
    const afterOptOut = await (await fetch(`${BASE_URL}/api/v1/analytics/adoption`)).json();
    assert.equal(afterOptOut.cli_scans_count, beforeOptOut.cli_scans_count, 'Analytics opt-out must stop counter increments');

    // Restore analytics enabled for live environment
    await fetch(`${BASE_URL}/api/v1/analytics/privacy-settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ analytics_enabled: true }),
    });
  });
});
