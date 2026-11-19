/**
 * Feature 3: Semantic Change Detection
 *
 * Deterministic JSON field-level and schema-aware comparison engine.
 * Classifies changes into:
 * - MATERIAL_CHANGE
 * - NON_MATERIAL_CHANGE
 * - STRUCTURAL_CHANGE
 * - SECURITY_SENSITIVE_CHANGE
 * - UNKNOWN_CHANGE
 *
 * Strictly redacts secrets, API keys, tokens, and PII-like credentials so they
 * never leak into stored diffs, logs, or UI responses.
 */

import crypto from 'crypto';
import type {
  SemanticChangeClass,
  SemanticDiffResult,
  SemanticFieldDiff,
} from './types.ts';

const SECRET_KEY_REGEX =
  /(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key|authorization|auth[_-]?header|credential|bearer|cookie|session[_-]?key|credit[_-]?card|ssn)/i;

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /Bearer\s+[A-Za-z0-9_\-.=]+/gi,
  /cck_live_[A-Za-z0-9_\-]+/gi,
  /cck_whsec_[A-Za-z0-9_\-]+/gi,
  /sk_(?:live|test)_[A-Za-z0-9_\-]+/gi,
  /ghp_[A-Za-z0-9_\-]+/gi,
  /AIza[0-9A-Za-z\-_]{20,}/g,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
];

const DEFAULT_NON_MATERIAL_KEYS = new Set([
  'note',
  'notes',
  'comment',
  'comments',
  'description',
  'display_name',
  'display_label',
  'ui_hint',
  'etag',
  'last_checked_at',
  'checked_at',
  'updated_display',
  'formatting',
  'cosmetic_tag',
]);

const SECURITY_SENSITIVE_KEYS = new Set([
  'permissions',
  'scopes',
  'scope',
  'roles',
  'role',
  'endpoint',
  'endpoints',
  'endpoint_url',
  'target_url',
  'webhook_url',
  'declared_permissions',
  'declared_endpoints',
  'required_permissions',
  'auth_method',
  'trust_tier',
  'identity_source',
  'approved_for_production',
  'is_sensitive',
  'allow_exec',
  'allow_network',
  'allow_filesystem',
  'signer',
  'signature',
  'capabilities',
]);

const CONSTRAINT_KEYS = new Set([
  'required',
  'minimum',
  'maximum',
  'minlength',
  'maxlength',
  'pattern',
  'enum',
  'format',
  'max_amount',
  'max_amount_usd',
  'max_depth',
  'ttl_seconds',
  'additionalproperties',
]);

export function redactSensitiveDiffValue(value: unknown, keyName?: string): unknown {
  if (keyName && SECRET_KEY_REGEX.test(keyName)) {
    return '[REDACTED_SECRET]';
  }
  if (typeof value === 'string') {
    let cleaned = value;
    for (const pattern of SECRET_VALUE_PATTERNS) {
      cleaned = cleaned.replace(pattern, '[REDACTED_SECRET]');
    }
    return cleaned;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveDiffValue(item));
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactSensitiveDiffValue(v, k);
    }
    return out;
  }
  return value;
}

function getJsonType(val: unknown): string {
  if (val === null) return 'null';
  if (Array.isArray(val)) return 'array';
  return typeof val;
}

function lastSegment(path: string): string {
  const parts = path.split('.');
  return (parts[parts.length - 1] || '').replace(/\[\d+\]$/, '').toLowerCase();
}

function canonicalStringEqual(a: unknown, b: unknown): boolean {
  if (typeof a === 'string' && typeof b === 'string') {
    // Normalize purely cosmetic whitespace around tokens
    return a.trim() === b.trim();
  }
  return JSON.stringify(a) === JSON.stringify(b);
}

function isSecurityPath(path: string): boolean {
  const parts = path.toLowerCase().split(/[.[\]]+/).filter(Boolean);
  return parts.some((p) => SECURITY_SENSITIVE_KEYS.has(p));
}

function isEndpointPath(path: string): boolean {
  const seg = lastSegment(path);
  return seg.includes('endpoint') || seg === 'url' || seg === 'target_url' || seg === 'base_url';
}

function isPermissionPath(path: string): boolean {
  const seg = lastSegment(path);
  return seg.includes('permission') || seg.includes('scope') || seg === 'roles' || seg === 'role';
}

function isConstraintPath(path: string): boolean {
  return CONSTRAINT_KEYS.has(lastSegment(path));
}

function isNonMaterialPath(path: string, extraIgnoredKeys: Set<string>): boolean {
  const seg = lastSegment(path);
  return DEFAULT_NON_MATERIAL_KEYS.has(seg) || extraIgnoredKeys.has(seg);
}

export function computeSemanticDiff(params: {
  tenant_id: string;
  subject_id: string;
  before: unknown;
  after: unknown;
  ignored_fields?: string[];
  material_fields?: string[];
}): SemanticDiffResult {
  const { tenant_id, subject_id, before, after, ignored_fields = [], material_fields = [] } = params;
  const extraIgnored = new Set(ignored_fields.map((s) => s.toLowerCase()));
  const explicitMaterial = new Set(material_fields.map((s) => s.toLowerCase()));

  // Redact inputs upfront so secrets NEVER appear in diff outputs
  const safeBefore = redactSensitiveDiffValue(before);
  const safeAfter = redactSensitiveDiffValue(after);

  const diffs: SemanticFieldDiff[] = [];
  const addedFields: string[] = [];
  const removedFields: string[] = [];
  const modifiedFields: string[] = [];
  const typeChanges: string[] = [];
  const permissionChanges: string[] = [];
  const endpointChanges: string[] = [];
  const constraintChanges: string[] = [];

  let indeterminate = false;

  const walk = (a: unknown, b: unknown, path: string, depth: number) => {
    if (depth > 16) {
      indeterminate = true;
      return;
    }

    const typeA = getJsonType(a);
    const typeB = getJsonType(b);
    const seg = lastSegment(path);
    const forceMaterial = explicitMaterial.has(seg) || explicitMaterial.has(path.toLowerCase());
    const secSensitive = isSecurityPath(path) || isPermissionPath(path) || isEndpointPath(path);
    const ignored = !forceMaterial && !secSensitive && isNonMaterialPath(path, extraIgnored);

    if (a === undefined && b !== undefined) {
      addedFields.push(path);
      if (isPermissionPath(path)) permissionChanges.push(path);
      if (isEndpointPath(path)) endpointChanges.push(path);
      if (isConstraintPath(path)) constraintChanges.push(path);
      diffs.push({
        path,
        change_kind: isPermissionPath(path)
          ? 'PERMISSION_CHANGED'
          : isEndpointPath(path)
          ? 'ENDPOINT_CHANGED'
          : isConstraintPath(path)
          ? 'CONSTRAINT_CHANGED'
          : 'ADDED',
        before_value: undefined,
        after_value: b,
        after_type: typeB,
        is_material: !ignored,
        is_security_sensitive: secSensitive,
        reason: ignored ? `Added non-material field "${path}"` : `Added field "${path}"`,
      });
      return;
    }

    if (a !== undefined && b === undefined) {
      removedFields.push(path);
      if (isPermissionPath(path)) permissionChanges.push(path);
      if (isEndpointPath(path)) endpointChanges.push(path);
      if (isConstraintPath(path)) constraintChanges.push(path);
      diffs.push({
        path,
        change_kind: isPermissionPath(path)
          ? 'PERMISSION_CHANGED'
          : isEndpointPath(path)
          ? 'ENDPOINT_CHANGED'
          : isConstraintPath(path)
          ? 'CONSTRAINT_CHANGED'
          : 'REMOVED',
        before_value: a,
        after_value: undefined,
        before_type: typeA,
        is_material: !ignored,
        is_security_sensitive: secSensitive,
        reason: ignored ? `Removed non-material field "${path}"` : `Removed field "${path}"`,
      });
      return;
    }

    if (typeA !== typeB) {
      typeChanges.push(path);
      modifiedFields.push(path);
      diffs.push({
        path,
        change_kind: 'TYPE_CHANGED',
        before_value: a,
        after_value: b,
        before_type: typeA,
        after_type: typeB,
        is_material: true,
        is_security_sensitive: secSensitive,
        reason: `Type changed at "${path}": ${typeA} -> ${typeB}`,
      });
      return;
    }

    if (typeA === 'object' && a !== null && b !== null) {
      const objA = a as Record<string, unknown>;
      const objB = b as Record<string, unknown>;
      const keys = Array.from(new Set([...Object.keys(objA), ...Object.keys(objB)])).sort();
      for (const k of keys) {
        const nextPath = path === '$' ? k : `${path}.${k}`;
        walk(objA[k], objB[k], nextPath, depth + 1);
      }
      return;
    }

    if (typeA === 'array') {
      const arrA = a as unknown[];
      const arrB = b as unknown[];
      const eq = JSON.stringify(arrA) === JSON.stringify(arrB);
      if (!eq) {
        modifiedFields.push(path);
        if (isPermissionPath(path)) permissionChanges.push(path);
        if (isEndpointPath(path)) endpointChanges.push(path);
        if (isConstraintPath(path)) constraintChanges.push(path);
        diffs.push({
          path,
          change_kind: isPermissionPath(path)
            ? 'PERMISSION_CHANGED'
            : isEndpointPath(path)
            ? 'ENDPOINT_CHANGED'
            : isConstraintPath(path)
            ? 'CONSTRAINT_CHANGED'
            : 'MODIFIED',
          before_value: arrA,
          after_value: arrB,
          before_type: 'array',
          after_type: 'array',
          is_material: !ignored,
          is_security_sensitive: secSensitive,
          reason: `${secSensitive ? 'Security-sensitive array' : 'Array'} changed at "${path}" (${arrA.length} -> ${arrB.length} items)`,
        });
      }
      return;
    }

    // Primitive leaf comparison
    if (!canonicalStringEqual(a, b)) {
      modifiedFields.push(path);
      if (isPermissionPath(path)) permissionChanges.push(path);
      if (isEndpointPath(path)) endpointChanges.push(path);
      if (isConstraintPath(path)) constraintChanges.push(path);
      diffs.push({
        path,
        change_kind: isPermissionPath(path)
          ? 'PERMISSION_CHANGED'
          : isEndpointPath(path)
          ? 'ENDPOINT_CHANGED'
          : isConstraintPath(path)
          ? 'CONSTRAINT_CHANGED'
          : 'MODIFIED',
        before_value: a,
        after_value: b,
        before_type: typeA,
        after_type: typeB,
        is_material: !ignored,
        is_security_sensitive: secSensitive,
        reason: ignored
          ? `Non-material cosmetic change at "${path}"`
          : `Value changed at "${path}": ${JSON.stringify(a)} -> ${JSON.stringify(b)}`,
      });
    }
  };

  if (safeBefore === undefined && safeAfter === undefined) {
    indeterminate = true;
  } else {
    walk(safeBefore, safeAfter, '$', 0);
  }

  let classification: SemanticChangeClass = 'NON_MATERIAL_CHANGE';
  if (indeterminate) {
    classification = 'UNKNOWN_CHANGE';
  } else if (diffs.length === 0) {
    classification = 'NON_MATERIAL_CHANGE';
  } else if (
    diffs.some((d) => d.is_security_sensitive) ||
    permissionChanges.length > 0 ||
    endpointChanges.length > 0
  ) {
    classification = 'SECURITY_SENSITIVE_CHANGE';
  } else if (
    typeChanges.length > 0 ||
    constraintChanges.length > 0 ||
    diffs.some((d) => (d.change_kind === 'ADDED' || d.change_kind === 'REMOVED') && d.is_material)
  ) {
    classification = 'STRUCTURAL_CHANGE';
  } else if (diffs.some((d) => d.is_material)) {
    classification = 'MATERIAL_CHANGE';
  } else {
    classification = 'NON_MATERIAL_CHANGE';
  }

  const requiresInvalidation =
    classification === 'SECURITY_SENSITIVE_CHANGE' ||
    classification === 'STRUCTURAL_CHANGE' ||
    classification === 'MATERIAL_CHANGE' ||
    classification === 'UNKNOWN_CHANGE';

  const summary =
    diffs.length === 0
      ? `No semantic differences detected for ${subject_id}.`
      : `${classification}: ${diffs.length} change(s) on ${subject_id} (added=${addedFields.length}, removed=${removedFields.length}, modified=${modifiedFields.length}, security=${permissionChanges.length + endpointChanges.length}).`;

  return {
    diff_id: `sdiff-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id,
    subject_id,
    classification,
    has_changes: diffs.length > 0,
    requires_invalidation: diffs.length > 0 ? requiresInvalidation : false,
    added_fields: addedFields,
    removed_fields: removedFields,
    modified_fields: modifiedFields,
    type_changes: typeChanges,
    permission_changes: permissionChanges,
    endpoint_changes: endpointChanges,
    constraint_changes: constraintChanges,
    diffs,
    summary,
    redacted: true,
    computed_at: new Date().toISOString(),
  };
}
