/**
 * Feature 14: Per-Call Isolation
 *
 * Creates a fresh, strictly scoped InvocationContext per MCP Gateway tool call
 * with timeout/abort controls, payload size limits, scratch state isolation,
 * and deterministic teardown (revoking ephemeral secret leases and clearing
 * volatile handles on completion, error, or timeout).
 *
 * Security Boundary Note:
 * This provides Application-Level Per-Call Invocation Context Isolation inside
 * the Node.js runtime (with per-call AbortController, clean context maps,
 * secret lease revocation on teardown, and payload limits), NOT OS/container/VM sandboxing.
 */

import crypto from 'crypto';
import type {
  DataSensitivityTier,
  EphemeralSecretLease,
  InvocationContextSnapshot,
  RegisteredSecretRecord,
  SecretAccessAuditRecord,
} from './types.ts';
import { revokeSecretOrLease } from './secret_broker.ts';

export interface ActiveInvocationHandle {
  invocationId: string;
  snapshot: InvocationContextSnapshot;
  abortController: AbortController;
  volatileScratch: Map<string, unknown>;
  resolvedSecretsBuffer: Map<string, string>;
  teardown: (outcome: 'COMPLETED_CLEANED' | 'FAILED_CLEANED' | 'TIMED_OUT_CLEANED') => void;
}

export function createIsolatedInvocationContext(params: {
  invocationsLedger: InvocationContextSnapshot[];
  leases: EphemeralSecretLease[];
  secrets: RegisteredSecretRecord[];
  accessLogs: SecretAccessAuditRecord[];
  tenantId: string;
  agentId: string;
  toolId: string;
  traceId: string;
  effectiveScopes: string[];
  matchedGrants: string[];
  classifications: string[];
  maxTier: DataSensitivityTier;
  secretLeaseIds?: string[];
  timeoutMs?: number;
  maxPayloadBytes?: number;
  payloadObject?: unknown;
}): { ok: true; handle: ActiveInvocationHandle } | { ok: false; error: string } {
  const maxBytes = Math.max(1024, Math.min(2_000_000, params.maxPayloadBytes ?? 256_000));
  const payloadSize = Buffer.byteLength(JSON.stringify(params.payloadObject ?? {}), 'utf8');
  if (payloadSize > maxBytes) {
    return {
      ok: false,
      error: `Per-Call Isolation BLOCKED: Input payload (${payloadSize} bytes) exceeds invocation ceiling (${maxBytes} bytes).`,
    };
  }

  const invocationId = `icall-${crypto.randomUUID().slice(0, 10)}`;
  const timeoutMs = Math.max(200, Math.min(30000, params.timeoutMs ?? 4000));
  const abortController = new AbortController();
  const volatileScratch = new Map<string, unknown>();
  const resolvedSecretsBuffer = new Map<string, string>();
  const leaseIds = Array.isArray(params.secretLeaseIds) ? [...params.secretLeaseIds] : [];

  const snapshot: InvocationContextSnapshot = {
    invocation_id: invocationId,
    tenant_id: params.tenantId,
    agent_id: params.agentId,
    tool_id: params.toolId,
    trace_id: params.traceId,
    permission_context: {
      effective_scopes: [...params.effectiveScopes],
      matched_grants: [...params.matchedGrants],
    },
    data_classification_context: {
      classifications: [...params.classifications],
      max_tier: params.maxTier,
    },
    secret_lease_ids: leaseIds,
    timeout_ms: timeoutMs,
    max_payload_bytes: maxBytes,
    status: 'ACTIVE',
    leases_revoked_count: 0,
    isolation_boundary_note:
      'Application-level per-call InvocationContext with AbortController, isolated scratch state, payload bounds, and automatic lease teardown (non-OS sandbox).',
    created_at: new Date().toISOString(),
  };

  params.invocationsLedger.unshift(snapshot);
  if (params.invocationsLedger.length > 250) params.invocationsLedger.pop();

  let tornDown = false;
  const timer = setTimeout(() => {
    abortController.abort(new Error(`Invocation ${invocationId} timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  const teardown = (outcome: 'COMPLETED_CLEANED' | 'FAILED_CLEANED' | 'TIMED_OUT_CLEANED') => {
    if (tornDown) return;
    tornDown = true;
    clearTimeout(timer);

    // Clear all volatile memory buffers
    volatileScratch.clear();
    resolvedSecretsBuffer.clear();

    // Deterministically revoke all ephemeral secret leases bound to this invocation
    let revokedCount = 0;
    for (const lid of leaseIds) {
      const res = revokeSecretOrLease({
        secrets: params.secrets,
        leases: params.leases,
        accessLogs: params.accessLogs,
        tenantId: params.tenantId,
        leaseId: lid,
        reason: `invocation_teardown:${invocationId}:${outcome}`,
      });
      if (res.ok) revokedCount += res.revokedLeases;
    }

    snapshot.leases_revoked_count = revokedCount;
    snapshot.status = outcome;
    snapshot.cleaned_at = new Date().toISOString();
  };

  return {
    ok: true,
    handle: {
      invocationId,
      snapshot,
      abortController,
      volatileScratch,
      resolvedSecretsBuffer,
      teardown,
    },
  };
}
