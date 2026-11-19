/**
 * Feature 13: Ephemeral Secret Broker
 *
 * Manages tenant-isolated registered secrets via an encrypted vault envelope
 * (AES-256-GCM at rest) and mints short-lived, scope-bound, session-bound
 * ephemeral lease handles (`seclease_*`).
 *
 * Security & Honesty Guarantees:
 * - Raw secrets NEVER appear in API responses after registration, decision receipts,
 *   audit logs, error strings, or UI payloads.
 * - Uses an in-process Broker & Encrypted Store Adapter; does NOT claim external
 *   cloud IdP OIDC token exchange unless explicitly bridged by an upstream adapter.
 * - Fail-closed on missing, expired, revoked, cross-tenant, or out-of-scope requests.
 */

import crypto from 'crypto';
import type {
  EphemeralSecretLease,
  RegisteredSecretRecord,
  SecretAccessAuditRecord,
} from './types.ts';

// Runtime broker wrapping key derived once per process (or from CCK_BROKER_MASTER_KEY)
const PROCESS_BROKER_KEY = crypto
  .createHash('sha256')
  .update(process.env.CCK_BROKER_MASTER_KEY || process.env.CCK_SIGNING_SECRET || 'cck-ephemeral-broker-key-v1-local')
  .digest();

function encryptSecretValue(plaintext: string): RegisteredSecretRecord['encrypted_envelope'] {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', PROCESS_BROKER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext_b64: encrypted.toString('base64'),
    iv_b64: iv.toString('base64'),
    auth_tag_b64: authTag.toString('base64'),
    alg: 'aes-256-gcm',
  };
}

function decryptSecretValue(env: RegisteredSecretRecord['encrypted_envelope']): string {
  const iv = Buffer.from(env.iv_b64, 'base64');
  const authTag = Buffer.from(env.auth_tag_b64, 'base64');
  const ciphertext = Buffer.from(env.ciphertext_b64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', PROCESS_BROKER_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function matchesScopePattern(pattern: string, target: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return target.startsWith(pattern.slice(0, -1));
  return pattern === target;
}

export function sanitizeSecretSummary(record: RegisteredSecretRecord): Omit<RegisteredSecretRecord, 'encrypted_envelope'> & { vault_encrypted: true } {
  const { encrypted_envelope: _hidden, ...safe } = record;
  return { ...safe, vault_encrypted: true };
}

export function registerVaultSecret(params: {
  secrets: RegisteredSecretRecord[];
  accessLogs: SecretAccessAuditRecord[];
  tenantId: string;
  principalId: string;
  provider: string;
  rawSecretValue: string;
  secretRef?: string;
  allowedTools: string[];
  allowedScopes: string[];
  allowedResources?: string[];
  expiresAt?: string;
}): RegisteredSecretRecord {
  if (!params.rawSecretValue || typeof params.rawSecretValue !== 'string') {
    throw new Error('Secret registration requires a non-empty secret value.');
  }
  const now = new Date().toISOString();
  const ref = params.secretRef || `sec_${crypto.randomUUID().slice(0, 10)}`;
  const prefix = `${params.rawSecretValue.slice(0, Math.min(4, params.rawSecretValue.length))}***`;
  const envelope = encryptSecretValue(params.rawSecretValue);

  const existing = params.secrets.find((s) => s.tenant_id === params.tenantId && s.secret_ref === ref);
  if (existing) {
    existing.encrypted_envelope = envelope;
    existing.fingerprint_prefix = prefix;
    existing.version += 1;
    existing.allowed_tools = params.allowedTools.length ? params.allowedTools : existing.allowed_tools;
    existing.allowed_scopes = params.allowedScopes.length ? params.allowedScopes : existing.allowed_scopes;
    existing.allowed_resources = params.allowedResources?.length ? params.allowedResources : existing.allowed_resources;
    existing.expires_at = params.expiresAt ?? existing.expires_at;
    existing.revoked = false;
    existing.revoked_at = undefined;
    existing.updated_at = now;

    params.accessLogs.unshift({
      access_id: `secaud-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      secret_ref: ref,
      principal_id: params.principalId,
      agent_id: 'system',
      tool_id: '*',
      session_id: 'rotation',
      purpose: 'secret_rotation',
      outcome: 'ROTATED',
      reason: `Rotated secret ${ref} to v${existing.version}.`,
      timestamp: now,
    });
    return existing;
  }

  const record: RegisteredSecretRecord = {
    secret_ref: ref,
    tenant_id: params.tenantId,
    principal_id: params.principalId,
    provider: params.provider || 'generic-oauth-token',
    allowed_tools: params.allowedTools,
    allowed_scopes: params.allowedScopes,
    allowed_resources: params.allowedResources && params.allowedResources.length > 0 ? params.allowedResources : ['*'],
    encrypted_envelope: envelope,
    fingerprint_prefix: prefix,
    version: 1,
    revoked: false,
    expires_at: params.expiresAt,
    created_at: now,
    updated_at: now,
  };
  params.secrets.unshift(record);
  return record;
}

export function issueEphemeralSecretLease(params: {
  secrets: RegisteredSecretRecord[];
  leases: EphemeralSecretLease[];
  accessLogs: SecretAccessAuditRecord[];
  tenantId: string;
  principalId: string;
  agentId: string;
  toolId: string;
  secretRef: string;
  sessionId: string;
  invocationId?: string;
  requestedScope: string;
  resourceScope?: string;
  purpose: string;
  ttlSeconds?: number;
}): { ok: true; lease: EphemeralSecretLease } | { ok: false; outcome: SecretAccessAuditRecord['outcome']; reason: string } {
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const resourceScope = params.resourceScope || '*';

  const recordAudit = (outcome: SecretAccessAuditRecord['outcome'], reason: string, leaseId?: string) => {
    params.accessLogs.unshift({
      access_id: `secaud-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      secret_ref: params.secretRef,
      lease_id: leaseId,
      principal_id: params.principalId,
      agent_id: params.agentId,
      tool_id: params.toolId,
      session_id: params.sessionId,
      purpose: params.purpose,
      outcome,
      reason,
      timestamp: nowIso,
    });
    if (params.accessLogs.length > 400) params.accessLogs.pop();
  };

  const secret = params.secrets.find((s) => s.secret_ref === params.secretRef);
  if (!secret) {
    const reason = `Secret Broker DENY: secret_ref "${params.secretRef}" does not exist.`;
    recordAudit('DENIED_MISSING', reason);
    return { ok: false, outcome: 'DENIED_MISSING', reason };
  }

  if (secret.tenant_id !== params.tenantId) {
    const reason = `Secret Broker DENY: Cross-tenant access to secret_ref "${params.secretRef}" prohibited.`;
    recordAudit('DENIED_TENANT', reason);
    return { ok: false, outcome: 'DENIED_TENANT', reason };
  }

  if (secret.revoked) {
    const reason = `Secret Broker DENY: secret_ref "${params.secretRef}" has been revoked.`;
    recordAudit('DENIED_REVOKED', reason);
    return { ok: false, outcome: 'DENIED_REVOKED', reason };
  }

  if (secret.expires_at && new Date(secret.expires_at).getTime() <= nowMs) {
    const reason = `Secret Broker DENY: secret_ref "${params.secretRef}" expired at ${secret.expires_at}.`;
    recordAudit('DENIED_EXPIRED', reason);
    return { ok: false, outcome: 'DENIED_EXPIRED', reason };
  }

  const toolPermitted = secret.allowed_tools.some((t) => matchesScopePattern(t, params.toolId));
  if (!toolPermitted) {
    const reason = `Secret Broker DENY: Tool "${params.toolId}" is not authorized to lease "${params.secretRef}".`;
    recordAudit('DENIED_SCOPE', reason);
    return { ok: false, outcome: 'DENIED_SCOPE', reason };
  }

  const scopePermitted = secret.allowed_scopes.some((sc) => matchesScopePattern(sc, params.requestedScope));
  if (!scopePermitted) {
    const reason = `Secret Broker DENY: Scope "${params.requestedScope}" exceeds allowed scopes [${secret.allowed_scopes.join(', ')}] on "${params.secretRef}".`;
    recordAudit('DENIED_SCOPE', reason);
    return { ok: false, outcome: 'DENIED_SCOPE', reason };
  }

  const resourcePermitted = secret.allowed_resources.some((rs) => matchesScopePattern(rs, resourceScope));
  if (!resourcePermitted) {
    const reason = `Secret Broker DENY: Resource "${resourceScope}" not in allowed resources [${secret.allowed_resources.join(', ')}].`;
    recordAudit('DENIED_SCOPE', reason);
    return { ok: false, outcome: 'DENIED_SCOPE', reason };
  }

  const ttl = Math.max(5, Math.min(300, params.ttlSeconds ?? 60));
  const lease: EphemeralSecretLease = {
    lease_id: `seclease_${crypto.randomUUID().slice(0, 12)}`,
    secret_ref: secret.secret_ref,
    tenant_id: params.tenantId,
    principal_id: params.principalId,
    agent_id: params.agentId,
    tool_id: params.toolId,
    session_id: params.sessionId,
    invocation_id: params.invocationId,
    requested_scope: params.requestedScope,
    resource_scope: resourceScope,
    purpose: params.purpose,
    issued_at: nowIso,
    expires_at: new Date(nowMs + ttl * 1000).toISOString(),
    revoked: false,
    used_count: 0,
  };

  params.leases.unshift(lease);
  if (params.leases.length > 400) params.leases.pop();
  recordAudit('GRANTED', `Issued ephemeral lease (${ttl}s) for tool ${params.toolId} scope ${params.requestedScope}.`, lease.lease_id);
  return { ok: true, lease };
}

/**
 * Resolves an ephemeral lease to raw credentials strictly for in-memory tool transport injection.
 * Fails closed if the lease or underlying secret is expired, revoked, cross-tenant, or cross-tool.
 */
export function resolveEphemeralLeaseForExecution(params: {
  secrets: RegisteredSecretRecord[];
  leases: EphemeralSecretLease[];
  leaseId: string;
  tenantId: string;
  toolId: string;
  invocationId?: string;
}): { ok: true; secretValue: string; secretRef: string } | { ok: false; reason: string } {
  const nowMs = Date.now();
  const lease = params.leases.find((l) => l.lease_id === params.leaseId);
  if (!lease) {
    return { ok: false, reason: `Ephemeral lease "${params.leaseId}" not found.` };
  }
  if (lease.tenant_id !== params.tenantId) {
    return { ok: false, reason: `Cross-tenant lease resolution denied.` };
  }
  if (lease.tool_id !== params.toolId) {
    return { ok: false, reason: `Lease bound to tool "${lease.tool_id}", rejected for "${params.toolId}".` };
  }
  if (lease.invocation_id && params.invocationId && lease.invocation_id !== params.invocationId) {
    return { ok: false, reason: `Lease bound to invocation "${lease.invocation_id}", rejected for "${params.invocationId}".` };
  }
  if (lease.revoked) {
    return { ok: false, reason: `Ephemeral lease "${params.leaseId}" has been revoked (${lease.revoke_reason || 'revoked'}).` };
  }
  if (new Date(lease.expires_at).getTime() <= nowMs) {
    lease.revoked = true;
    lease.revoked_at = new Date(nowMs).toISOString();
    lease.revoke_reason = 'TTL_EXPIRED';
    return { ok: false, reason: `Ephemeral lease "${params.leaseId}" has expired.` };
  }

  const secret = params.secrets.find((s) => s.secret_ref === lease.secret_ref && s.tenant_id === params.tenantId);
  if (!secret || secret.revoked || (secret.expires_at && new Date(secret.expires_at).getTime() <= nowMs)) {
    return { ok: false, reason: `Underlying secret "${lease.secret_ref}" is missing, expired, or revoked.` };
  }

  try {
    const raw = decryptSecretValue(secret.encrypted_envelope);
    lease.used_count += 1;
    return { ok: true, secretValue: raw, secretRef: secret.secret_ref };
  } catch {
    return { ok: false, reason: `Failed to decrypt secret envelope for "${secret.secret_ref}" (fail-closed).` };
  }
}

export function revokeSecretOrLease(params: {
  secrets: RegisteredSecretRecord[];
  leases: EphemeralSecretLease[];
  accessLogs: SecretAccessAuditRecord[];
  tenantId: string;
  secretRef?: string;
  leaseId?: string;
  reason?: string;
}): { ok: boolean; revokedLeases: number; error?: string } {
  const now = new Date().toISOString();
  let revokedCount = 0;

  if (params.leaseId) {
    const lease = params.leases.find((l) => l.lease_id === params.leaseId);
    if (!lease) return { ok: false, revokedLeases: 0, error: 'Lease not found.' };
    if (lease.tenant_id !== params.tenantId) return { ok: false, revokedLeases: 0, error: 'Cross-tenant revocation forbidden.' };
    lease.revoked = true;
    lease.revoked_at = now;
    lease.revoke_reason = params.reason || 'manual_revocation';
    revokedCount += 1;
    params.accessLogs.unshift({
      access_id: `secaud-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      secret_ref: lease.secret_ref,
      lease_id: lease.lease_id,
      principal_id: lease.principal_id,
      agent_id: lease.agent_id,
      tool_id: lease.tool_id,
      session_id: lease.session_id,
      purpose: 'lease_revocation',
      outcome: 'LEASE_REVOKED',
      reason: params.reason || 'Ephemeral lease revoked.',
      timestamp: now,
    });
    return { ok: true, revokedLeases: revokedCount };
  }

  if (params.secretRef) {
    const secret = params.secrets.find((s) => s.secret_ref === params.secretRef);
    if (!secret) return { ok: false, revokedLeases: 0, error: 'Secret reference not found.' };
    if (secret.tenant_id !== params.tenantId) return { ok: false, revokedLeases: 0, error: 'Cross-tenant revocation forbidden.' };
    secret.revoked = true;
    secret.revoked_at = now;
    secret.updated_at = now;
    for (const l of params.leases) {
      if (l.secret_ref === secret.secret_ref && l.tenant_id === params.tenantId && !l.revoked) {
        l.revoked = true;
        l.revoked_at = now;
        l.revoke_reason = 'parent_secret_revoked';
        revokedCount += 1;
      }
    }
    params.accessLogs.unshift({
      access_id: `secaud-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      secret_ref: secret.secret_ref,
      principal_id: secret.principal_id,
      agent_id: 'system',
      tool_id: '*',
      session_id: 'revocation',
      purpose: 'secret_revocation',
      outcome: 'DENIED_REVOKED',
      reason: params.reason || `Secret ${secret.secret_ref} revoked (${revokedCount} active leases invalidated).`,
      timestamp: now,
    });
    return { ok: true, revokedLeases: revokedCount };
  }

  return { ok: false, revokedLeases: 0, error: 'secret_ref or lease_id required.' };
}
