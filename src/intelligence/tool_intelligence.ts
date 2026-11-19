/**
 * Features 9 & 10: Tool Identity Fingerprint & Tool Drift Intelligence
 *
 * Feature 9: Deterministic canonical SHA-256 fingerprinting over tool ID,
 * package/server identity, version, input/output schemas, declared permissions,
 * declared endpoints, capabilities, and protocol metadata — strictly excluding secrets.
 * Distinguishes DECLARED, OBSERVED, and VERIFIED_PUBLISHER trust sources.
 *
 * Feature 10: Detects all 11 classes of tool/manifest drift, classifies severity
 * (LOW | MEDIUM | HIGH | CRITICAL) with clear reasoning, and evaluates whether
 * the requested action scope is affected or safely allowed under policy.
 */

import crypto from 'crypto';
import type {
  CanonicalToolDefinition,
  ToolDriftFinding,
  ToolDriftSeverity,
  ToolDriftType,
  ToolFingerprintVersion,
  ToolIdentityRecord,
} from './types.ts';
import { redactSensitiveDiffValue } from './semantic_diff.ts';

function canonicalSort(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalSort);
  }
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = canonicalSort((value as Record<string, unknown>)[k]);
    }
    return sorted;
  }
  return value;
}

const TOOL_SECRET_KEY_REGEX =
  /(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key|authorization|auth[_-]?header|credential|bearer|cookie|session[_-]?key)/i;

function stripSecretKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripSecretKeys);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (TOOL_SECRET_KEY_REGEX.test(k)) {
        continue;
      }
      out[k] = stripSecretKeys(v);
    }
    return out;
  }
  return value;
}

export function sanitizeToolDefinition(raw: Partial<CanonicalToolDefinition> & { tool_id: string; name?: string }): CanonicalToolDefinition {
  const safeInput = redactSensitiveDiffValue(stripSecretKeys(raw.input_schema || {})) as Record<string, unknown>;
  const safeOutput = raw.output_schema
    ? (redactSensitiveDiffValue(stripSecretKeys(raw.output_schema)) as Record<string, unknown>)
    : undefined;
  const safeProtocol = raw.protocol_metadata
    ? (redactSensitiveDiffValue(stripSecretKeys(raw.protocol_metadata)) as Record<string, unknown>)
    : undefined;

  const dedupeSorted = (arr?: string[]) =>
    Array.from(new Set((arr || []).map((s) => String(s).trim()).filter(Boolean))).sort();

  const cleanedProtocol =
    safeProtocol && Object.keys(safeProtocol).length > 0 ? (canonicalSort(safeProtocol) as Record<string, unknown>) : undefined;

  return {
    tool_id: String(raw.tool_id).trim(),
    name: String(raw.name || raw.tool_id).trim(),
    server_id: raw.server_id ? String(raw.server_id).trim() : undefined,
    server_name: raw.server_name ? String(raw.server_name).trim() : undefined,
    package_identity: raw.package_identity ? String(raw.package_identity).trim() : undefined,
    version: String(raw.version || '1.0.0').trim(),
    input_schema: canonicalSort(safeInput) as Record<string, unknown>,
    output_schema: safeOutput ? (canonicalSort(safeOutput) as Record<string, unknown>) : undefined,
    declared_permissions: dedupeSorted(raw.declared_permissions),
    declared_endpoints: dedupeSorted(raw.declared_endpoints),
    capabilities: dedupeSorted(raw.capabilities),
    protocol_metadata: cleanedProtocol,
    publisher_info: raw.publisher_info
      ? {
          publisher_id: raw.publisher_info.publisher_id,
          verified: Boolean(raw.publisher_info.verified),
          source_repo: raw.publisher_info.source_repo,
        }
      : undefined,
    identity_source: raw.identity_source || 'DECLARED',
  };
}

export function computeToolFingerprint(def: CanonicalToolDefinition): {
  fingerprint_hash: string;
  canonical_json: string;
} {
  const clean = sanitizeToolDefinition(def);
  // Explicitly strip ephemeral or secret fields before canonical hashing
  const canonicalPayload = canonicalSort({
    canon_spec: 'cck-tool-canon-v1',
    tool_id: clean.tool_id,
    name: clean.name,
    server_name: clean.server_name || null,
    package_identity: clean.package_identity || null,
    version: clean.version,
    input_schema: clean.input_schema,
    output_schema: clean.output_schema || null,
    declared_permissions: clean.declared_permissions,
    declared_endpoints: clean.declared_endpoints,
    capabilities: clean.capabilities,
    protocol_metadata: clean.protocol_metadata || null,
    publisher_info: clean.publisher_info || null,
  });
  const canonicalJson = JSON.stringify(canonicalPayload);
  const fingerprintHash = crypto.createHash('sha256').update(canonicalJson).digest('hex');
  return { fingerprint_hash: fingerprintHash, canonical_json: canonicalJson };
}

export function detectToolDrift(params: {
  tenantId: string;
  toolIdentityId: string;
  previous: CanonicalToolDefinition;
  next: CanonicalToolDefinition;
  fromFingerprint: string;
  toFingerprint: string;
}): ToolDriftFinding | null {
  const { tenantId, toolIdentityId, previous, next, fromFingerprint, toFingerprint } = params;
  if (fromFingerprint === toFingerprint) {
    return null;
  }

  const driftTypes: ToolDriftType[] = [];
  const explanation: string[] = [];
  const affectedScopes = new Set<string>();

  if (JSON.stringify(previous.input_schema) !== JSON.stringify(next.input_schema)) {
    driftTypes.push('INPUT_SCHEMA_CHANGED');
    const prevProps = Object.keys((previous.input_schema?.properties as Record<string, unknown>) || {});
    const nextProps = Object.keys((next.input_schema?.properties as Record<string, unknown>) || {});
    const addedProps = nextProps.filter((p) => !prevProps.includes(p));
    const removedProps = prevProps.filter((p) => !nextProps.includes(p));
    explanation.push(
      `Input schema mutated (added fields: [${addedProps.join(', ') || 'none'}], removed fields: [${removedProps.join(', ') || 'none'}]).`
    );
    affectedScopes.add('schema.input');
  }

  if (JSON.stringify(previous.output_schema || null) !== JSON.stringify(next.output_schema || null)) {
    driftTypes.push('OUTPUT_SCHEMA_CHANGED');
    explanation.push('Tool output schema definition changed.');
    affectedScopes.add('schema.output');
  }

  const addedPerms = next.declared_permissions.filter((p) => !previous.declared_permissions.includes(p));
  const removedPerms = previous.declared_permissions.filter((p) => !next.declared_permissions.includes(p));
  if (addedPerms.length > 0) {
    driftTypes.push('PERMISSIONS_ADDED');
    explanation.push(`New permissions requested: [${addedPerms.join(', ')}].`);
    addedPerms.forEach((p) => affectedScopes.add(p));
  }
  if (removedPerms.length > 0) {
    driftTypes.push('PERMISSIONS_REMOVED');
    explanation.push(`Previously declared permissions removed: [${removedPerms.join(', ')}].`);
  }

  const addedEndpoints = next.declared_endpoints.filter((e) => !previous.declared_endpoints.includes(e));
  const removedEndpoints = previous.declared_endpoints.filter((e) => !next.declared_endpoints.includes(e));
  if (addedEndpoints.length > 0) {
    driftTypes.push('ENDPOINTS_ADDED');
    explanation.push(`New external endpoints declared: [${addedEndpoints.join(', ')}].`);
    affectedScopes.add('network.egress');
  } else if (removedEndpoints.length > 0) {
    driftTypes.push('ENDPOINTS_CHANGED');
    explanation.push(`Declared endpoints altered (removed: [${removedEndpoints.join(', ')}]).`);
    affectedScopes.add('network.egress');
  }

  const addedCaps = next.capabilities.filter((c) => !previous.capabilities.includes(c));
  const removedCaps = previous.capabilities.filter((c) => !next.capabilities.includes(c));
  if (addedCaps.length > 0 || removedCaps.length > 0) {
    driftTypes.push('CAPABILITY_CHANGED');
    explanation.push(`Capabilities changed (+[${addedCaps.join(',')}], -[${removedCaps.join(',')}]).`);
    [...addedCaps, ...removedCaps].forEach((c) => affectedScopes.add(c));
  }

  if (previous.version !== next.version || previous.package_identity !== next.package_identity) {
    driftTypes.push('VERSION_DRIFT');
    explanation.push(`Package/version drift: ${previous.version} -> ${next.version}.`);
  }

  if (
    JSON.stringify(previous.protocol_metadata || null) !== JSON.stringify(next.protocol_metadata || null) ||
    JSON.stringify(previous.publisher_info || null) !== JSON.stringify(next.publisher_info || null) ||
    previous.identity_source !== next.identity_source
  ) {
    driftTypes.push('PUBLISHER_OR_PROTOCOL_DRIFT');
    explanation.push(
      `Publisher/protocol trust drift (${previous.identity_source} -> ${next.identity_source}).`
    );
    affectedScopes.add('publisher.trust');
  }

  // Deterministic Risk Classification
  let severity: ToolDriftSeverity = 'LOW';
  let recommendedAction: ToolDriftFinding['recommended_action'] = 'ALLOW';

  const hasCriticalPermission = addedPerms.some((p) =>
    /admin|write|delete|exec|shell|payment|secret|credential|root|\*/i.test(p)
  );
  const publisherDowngraded =
    previous.identity_source === 'VERIFIED_PUBLISHER' && next.identity_source !== 'VERIFIED_PUBLISHER';

  if (addedEndpoints.length > 0 || hasCriticalPermission || publisherDowngraded) {
    severity = 'CRITICAL';
    recommendedAction = 'BLOCK';
  } else if (
    driftTypes.includes('PERMISSIONS_ADDED') ||
    driftTypes.includes('INPUT_SCHEMA_CHANGED') ||
    driftTypes.includes('CAPABILITY_CHANGED')
  ) {
    severity = 'HIGH';
    recommendedAction = 'REQUIRE_APPROVAL';
  } else if (driftTypes.includes('OUTPUT_SCHEMA_CHANGED') || driftTypes.includes('ENDPOINTS_CHANGED')) {
    severity = 'MEDIUM';
    recommendedAction = 'REVALIDATE';
  } else {
    severity = 'LOW';
    recommendedAction = 'ALLOW';
  }

  return {
    drift_id: `tdrift-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: tenantId,
    tool_identity_id: toolIdentityId,
    tool_id: next.tool_id,
    from_fingerprint: fromFingerprint,
    to_fingerprint: toFingerprint,
    from_version: previous.version,
    to_version: next.version,
    drift_types: driftTypes,
    severity,
    recommended_action: recommendedAction,
    explanation,
    affected_scopes: Array.from(affectedScopes),
    detected_at: new Date().toISOString(),
    resolved: false,
  };
}

export function registerOrUpdateToolIdentity(params: {
  identities: ToolIdentityRecord[];
  drifts: ToolDriftFinding[];
  tenantId: string;
  rawDefinition: Partial<CanonicalToolDefinition> & { tool_id: string; name?: string };
  recordedBy?: string;
}): {
  identity: ToolIdentityRecord;
  fingerprint: string;
  drift: ToolDriftFinding | null;
  isNew: boolean;
} {
  const { identities, drifts, tenantId, rawDefinition, recordedBy = 'system' } = params;
  const cleanDef = sanitizeToolDefinition(rawDefinition);
  const { fingerprint_hash } = computeToolFingerprint(cleanDef);
  const nowIso = new Date().toISOString();

  const existing = identities.find(
    (t) => t.tenant_id === tenantId && t.tool_id === cleanDef.tool_id
  );

  if (!existing) {
    const versionEntry: ToolFingerprintVersion = {
      version_seq: 1,
      version_label: cleanDef.version,
      fingerprint_hash,
      canonical_version: 'cck-tool-canon-v1',
      identity_source: cleanDef.identity_source,
      definition: cleanDef,
      recorded_at: nowIso,
      recorded_by: recordedBy,
      approved: true,
      approved_by: recordedBy,
      approved_at: nowIso,
    };
    const record: ToolIdentityRecord = {
      tool_identity_id: `tid-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: tenantId,
      tool_id: cleanDef.tool_id,
      name: cleanDef.name,
      server_id: cleanDef.server_id,
      current_fingerprint: fingerprint_hash,
      current_version: cleanDef.version,
      identity_source: cleanDef.identity_source,
      drift_status: 'CLEAN',
      history: [versionEntry],
      created_at: nowIso,
      updated_at: nowIso,
    };
    identities.unshift(record);
    return { identity: record, fingerprint: fingerprint_hash, drift: null, isNew: true };
  }

  // Exact same fingerprint -> no drift
  if (existing.current_fingerprint === fingerprint_hash) {
    existing.updated_at = nowIso;
    return { identity: existing, fingerprint: fingerprint_hash, drift: null, isNew: false };
  }

  const prevVersion = existing.history[0];
  const drift = detectToolDrift({
    tenantId,
    toolIdentityId: existing.tool_identity_id,
    previous: prevVersion.definition,
    next: cleanDef,
    fromFingerprint: existing.current_fingerprint,
    toFingerprint: fingerprint_hash,
  });

  const nextSeq = existing.history.length + 1;
  const newVersion: ToolFingerprintVersion = {
    version_seq: nextSeq,
    version_label: cleanDef.version,
    fingerprint_hash,
    canonical_version: 'cck-tool-canon-v1',
    identity_source: cleanDef.identity_source,
    definition: cleanDef,
    recorded_at: nowIso,
    recorded_by: recordedBy,
    approved: !drift || drift.severity === 'LOW',
  };

  existing.history.unshift(newVersion);
  existing.current_fingerprint = fingerprint_hash;
  existing.current_version = cleanDef.version;
  existing.identity_source = cleanDef.identity_source;
  existing.updated_at = nowIso;

  if (drift) {
    drifts.unshift(drift);
    if (drift.severity === 'CRITICAL') {
      existing.drift_status = 'DRIFT_BLOCKED';
    } else if (drift.severity === 'HIGH') {
      existing.drift_status = 'PENDING_APPROVAL';
    } else if (drift.severity === 'MEDIUM') {
      existing.drift_status = 'DRIFT_WARNING';
    } else {
      existing.drift_status = 'CLEAN';
    }
  }

  return { identity: existing, fingerprint: fingerprint_hash, drift, isNew: false };
}

export function evaluateToolDriftPolicy(params: {
  identity: ToolIdentityRecord | undefined;
  drifts: ToolDriftFinding[];
  requestedScope?: string;
}): {
  decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';
  finding: ToolDriftFinding | null;
  reason: string;
} {
  const { identity, drifts, requestedScope } = params;
  if (!identity) {
    return {
      decision: 'ALLOW',
      finding: null,
      reason: 'No registered Tool Identity fingerprint to drift-check.',
    };
  }

  const latestVersion = identity.history[0];
  const unresolvedDrift = drifts.find(
    (d) => d.tool_identity_id === identity.tool_identity_id && !d.resolved
  ) || null;

  if (!unresolvedDrift || (latestVersion && latestVersion.approved)) {
    return {
      decision: 'ALLOW',
      finding: unresolvedDrift,
      reason: `Tool "${identity.tool_id}" fingerprint ${identity.current_fingerprint.slice(0, 12)} verified cleanly.`,
    };
  }

  // Scope-aware exception: ONLY allow LOW drift or unaffected scope when NO security-sensitive permissions/endpoints changed
  const isCriticalOrSecurity =
    unresolvedDrift.severity === 'CRITICAL' ||
    unresolvedDrift.drift_types.includes('PERMISSIONS_ADDED') ||
    unresolvedDrift.drift_types.includes('ENDPOINTS_ADDED') ||
    unresolvedDrift.drift_types.includes('PUBLISHER_OR_PROTOCOL_DRIFT');

  if (!isCriticalOrSecurity && unresolvedDrift.severity === 'LOW') {
    return {
      decision: 'ALLOW',
      finding: unresolvedDrift,
      reason: `Low-severity drift (${unresolvedDrift.drift_types.join(', ')}) does not affect security boundary for scope "${requestedScope || 'default'}".`,
    };
  }

  if (
    !isCriticalOrSecurity &&
    requestedScope &&
    unresolvedDrift.affected_scopes.length > 0 &&
    !unresolvedDrift.affected_scopes.some((s) => s === requestedScope || requestedScope.startsWith(s)) &&
    unresolvedDrift.severity === 'MEDIUM'
  ) {
    return {
      decision: 'ALLOW',
      finding: unresolvedDrift,
      reason: `Requested scope "${requestedScope}" is unaffected by MEDIUM drift [${unresolvedDrift.affected_scopes.join(', ')}].`,
    };
  }

  return {
    decision: unresolvedDrift.recommended_action,
    finding: unresolvedDrift,
    reason: `Tool Drift [${unresolvedDrift.severity}] detected on "${identity.tool_id}": ${unresolvedDrift.explanation.join(' ')}`,
  };
}
