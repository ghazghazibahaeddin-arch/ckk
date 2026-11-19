/**
 * Feature 15: Data Flow & Leakage Guard
 *
 * Inspects structured tool arguments and data payloads using BOTH:
 * 1) Tenant-customizable schema classifications & field-path policies (PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED)
 * 2) Structural sensitive field & token/credential detection (PII, PHI, PCI, Credentials)
 *
 * Applies Data Minimization, policy-based Redaction (MASK | DROP | HASH),
 * and Fail-Closed blocking for unauthorized or unclassified restricted destinations.
 * Never logs raw sensitive values into receipts or audit entries.
 */

import crypto from 'crypto';
import type {
  DataClassificationRule,
  DataFlowEvaluationResult,
  DataFlowPolicyRecord,
  DataSensitivityTier,
} from './types.ts';

const TIER_RANK: Record<DataSensitivityTier, number> = {
  PUBLIC: 1,
  INTERNAL: 2,
  CONFIDENTIAL: 3,
  RESTRICTED: 4,
};

function matchesDestinationPattern(pattern: string, destination: string): boolean {
  const p = pattern.trim().toLowerCase();
  const d = destination.trim().toLowerCase();
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // '.domain.com'
    return d.endsWith(suffix) || d === p.slice(2) || d.includes(p.slice(2));
  }
  if (p.endsWith('*')) return d.startsWith(p.slice(0, -1));
  return d === p || d.includes(p);
}

const DEFAULT_SENSITIVE_KEY_CATEGORIES: Array<{ keys: string[]; category: 'PII' | 'PHI' | 'PCI' | 'CREDENTIAL' | 'TOKEN'; tier: DataSensitivityTier; label: string }> = [
  { keys: ['password', 'secret', 'api_key', 'apikey', 'private_key', 'client_secret', 'raw_secret'], category: 'CREDENTIAL', tier: 'RESTRICTED', label: 'RAW_CREDENTIAL' },
  { keys: ['access_token', 'refresh_token', 'bearer', 'jwt', 'authorization', 'auth_token'], category: 'TOKEN', tier: 'RESTRICTED', label: 'AUTH_TOKEN' },
  { keys: ['ssn', 'social_security', 'national_id', 'passport', 'tax_id'], category: 'PII', tier: 'RESTRICTED', label: 'GOVERNMENT_PII' },
  { keys: ['card_number', 'cvv', 'cvc', 'pan', 'bank_account', 'iban', 'routing_number'], category: 'PCI', tier: 'RESTRICTED', label: 'FINANCIAL_PCI' },
  { keys: ['diagnosis', 'medical_record', 'patient_id', 'phi', 'health_plan'], category: 'PHI', tier: 'RESTRICTED', label: 'MEDICAL_PHI' },
  { keys: ['email', 'phone', 'address', 'dob', 'date_of_birth', 'customer_name'], category: 'PII', tier: 'CONFIDENTIAL', label: 'CONTACT_PII' },
];

const CREDENTIAL_VALUE_PATTERNS: RegExp[] = [
  /^sk[-_][a-zA-Z0-9_-]{12,}$/,
  /^cck_[a-zA-Z0-9_-]{8,}$/,
  /^ghp_[a-zA-Z0-9]{16,}$/,
  /^AKIA[0-9A-Z]{16}$/,
  /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/,
];

export function createDataClassificationRule(input: {
  tenant_id: string;
  label: string;
  tier: DataSensitivityTier;
  field_paths: string[];
  value_categories?: Array<'PII' | 'PHI' | 'PCI' | 'CREDENTIAL' | 'TOKEN' | 'CUSTOM'>;
  description?: string;
}): DataClassificationRule {
  return {
    rule_id: `dcls-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id || 'tenant_default',
    label: input.label,
    tier: input.tier,
    field_paths: Array.isArray(input.field_paths) ? input.field_paths : [],
    value_categories: Array.isArray(input.value_categories) && input.value_categories.length > 0 ? input.value_categories : ['CUSTOM'],
    description: input.description || `Tenant data classification rule for ${input.label}`,
    created_at: new Date().toISOString(),
  };
}

export function createDataFlowPolicy(input: {
  tenant_id: string;
  name: string;
  source_scope?: string;
  allowed_destinations?: string[];
  blocked_destinations?: string[];
  max_allowed_tier?: DataSensitivityTier;
  redaction_mode?: 'MASK' | 'DROP' | 'HASH' | 'BLOCK';
  block_unclassified_sensitive?: boolean;
}): DataFlowPolicyRecord {
  return {
    flow_policy_id: `dfpol-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id || 'tenant_default',
    name: input.name,
    source_scope: input.source_scope || '*',
    allowed_destinations: Array.isArray(input.allowed_destinations) ? input.allowed_destinations : ['*'],
    blocked_destinations: Array.isArray(input.blocked_destinations) ? input.blocked_destinations : [],
    max_allowed_tier: input.max_allowed_tier || 'CONFIDENTIAL',
    redaction_mode: input.redaction_mode || 'MASK',
    block_unclassified_sensitive: input.block_unclassified_sensitive !== false,
    is_active: true,
    created_at: new Date().toISOString(),
  };
}

export function evaluateDataFlowGuard(params: {
  tenantId: string;
  destination: string;
  payload: Record<string, unknown>;
  classifications: DataClassificationRule[];
  policies: DataFlowPolicyRecord[];
  explicitSensitivityLabels?: string[];
}): DataFlowEvaluationResult {
  const nowIso = new Date().toISOString();
  const dest = (params.destination || 'unknown').trim();
  const tenantClassifications = params.classifications.filter((c) => c.tenant_id === params.tenantId);
  const activePolicies = params.policies.filter((p) => p.is_active && p.tenant_id === params.tenantId);

  const detectedFields: DataFlowEvaluationResult['detected_fields'] = [];
  const labelSet = new Set<string>(params.explicitSensitivityLabels || []);
  let highestTier: DataSensitivityTier = 'PUBLIC';

  const upgradeTier = (t: DataSensitivityTier) => {
    if (TIER_RANK[t] > TIER_RANK[highestTier]) highestTier = t;
  };

  // Match active flow policies targeting this destination
  const blockedPolicy = activePolicies.find((p) => p.blocked_destinations.some((bd) => matchesDestinationPattern(bd, dest)));
  const applicablePolicies = activePolicies.filter(
    (p) => p.blocked_destinations.some((bd) => matchesDestinationPattern(bd, dest)) || p.allowed_destinations.some((ad) => matchesDestinationPattern(ad, dest))
  );

  // Strictest policy wins when evaluating max_allowed_tier and redaction
  let effectivePolicy: DataFlowPolicyRecord | undefined = blockedPolicy;
  if (!effectivePolicy && applicablePolicies.length > 0) {
    effectivePolicy = [...applicablePolicies].sort((a, b) => TIER_RANK[a.max_allowed_tier] - TIER_RANK[b.max_allowed_tier])[0];
  } else if (!effectivePolicy && activePolicies.length > 0) {
    // If tenant has active flow policies with allowlists and destination isn't in ANY allowlist, treat as RESTRICTED violation!
    effectivePolicy = {
      flow_policy_id: 'implicit-deny-unlisted-dest',
      tenant_id: params.tenantId,
      name: 'Unlisted Destination Guard',
      source_scope: '*',
      allowed_destinations: [],
      blocked_destinations: [dest],
      max_allowed_tier: 'PUBLIC',
      redaction_mode: 'BLOCK',
      block_unclassified_sensitive: true,
      is_active: true,
      created_at: nowIso,
    };
  }

  const maxAllowedTier: DataSensitivityTier = effectivePolicy ? effectivePolicy.max_allowed_tier : 'CONFIDENTIAL';
  const redactionMode = effectivePolicy ? effectivePolicy.redaction_mode : 'MASK';

  let hardBlock = Boolean(blockedPolicy && blockedPolicy.redaction_mode === 'BLOCK');
  let blockReason = blockedPolicy ? `Destination "${dest}" is explicitly blocked by Data Flow Policy "${blockedPolicy.name}".` : '';

  const inspectAndTransform = (node: unknown, currentPath: string): unknown => {
    if (node === null || node === undefined) return node;
    if (Array.isArray(node)) {
      return node.map((item, idx) => inspectAndTransform(item, `${currentPath}[${idx}]`));
    }
    if (typeof node === 'object') {
      const srcObj = node as Record<string, unknown>;
      const outObj: Record<string, unknown> = {};
      for (const key of Object.keys(srcObj)) {
        const path = currentPath ? `${currentPath}.${key}` : key;
        const val = srcObj[key];
        const keyLower = key.toLowerCase();

        // 1. Check tenant-defined schema classification rules
        const customRule = tenantClassifications.find((r) =>
          r.field_paths.some((fp) => {
            const norm = fp.toLowerCase();
            return norm === path.toLowerCase() || norm === keyLower || (norm.endsWith('*') && path.toLowerCase().startsWith(norm.slice(0, -1)));
          })
        );

        // 2. Check built-in schema key heuristics
        const builtinRule = DEFAULT_SENSITIVE_KEY_CATEGORIES.find((cat) =>
          cat.keys.some((k) => keyLower === k || keyLower.includes(k))
        );

        // 3. Check raw credential value shapes (API keys / JWT)
        const valLooksLikeCredential =
          typeof val === 'string' && CREDENTIAL_VALUE_PATTERNS.some((rx) => rx.test(val.trim()));

        if (customRule || builtinRule || valLooksLikeCredential) {
          const tier: DataSensitivityTier = customRule
            ? customRule.tier
            : valLooksLikeCredential
            ? 'RESTRICTED'
            : builtinRule!.tier;
          const label = customRule
            ? customRule.label
            : valLooksLikeCredential
            ? 'SECRET_VALUE_DETECTED'
            : builtinRule!.label;
          const category = customRule
            ? customRule.value_categories[0]
            : valLooksLikeCredential
            ? 'CREDENTIAL'
            : builtinRule!.category;

          upgradeTier(tier);
          labelSet.add(label);

          // Unclassified credential / RESTRICTED field check
          const exceedsPolicyTier = TIER_RANK[tier] > TIER_RANK[maxAllowedTier];
          const isUnclassifiedSecret = valLooksLikeCredential && (!effectivePolicy || effectivePolicy.block_unclassified_sensitive);

          if (exceedsPolicyTier || isUnclassifiedSecret) {
            const shouldBlockRestricted =
              tier === 'RESTRICTED' &&
              TIER_RANK[maxAllowedTier] < TIER_RANK.RESTRICTED &&
              (!effectivePolicy || effectivePolicy.block_unclassified_sensitive || effectivePolicy.redaction_mode === 'BLOCK');
            if (redactionMode === 'BLOCK' || shouldBlockRestricted) {
              hardBlock = true;
              blockReason = blockReason || `Data Flow BLOCKED: ${tier} field "${path}" (${label}) cannot flow to destination "${dest}".`;
              detectedFields.push({ path, label, tier, category, action: 'BLOCKED' });
              outObj[key] = '[BLOCKED]';
              continue;
            }
            if (redactionMode === 'DROP') {
              detectedFields.push({ path, label, tier, category, action: 'DROPPED' });
              continue; // data minimization: field omitted
            }
            if (redactionMode === 'HASH') {
              const hashed = crypto.createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
              detectedFields.push({ path, label, tier, category, action: 'REDACTED' });
              outObj[key] = `sha256:${hashed}`;
              continue;
            }
            // MASK
            detectedFields.push({ path, label, tier, category, action: 'REDACTED' });
            outObj[key] = `[REDACTED:${label}]`;
            continue;
          }

          detectedFields.push({ path, label, tier, category, action: 'KEPT' });
        }

        outObj[key] = inspectAndTransform(val, path);
      }
      return outObj;
    }
    return node;
  };

  const sanitizedPayload = (inspectAndTransform(params.payload || {}, '') || {}) as Record<string, unknown>;

  if (hardBlock) {
    return {
      evaluation_id: `dfeval-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      destination: dest,
      decision: 'BLOCK',
      highest_tier: highestTier,
      detected_labels: Array.from(labelSet),
      detected_fields: detectedFields,
      sanitized_payload: sanitizedPayload,
      reason: blockReason || `Blocked sensitive data flow (${highestTier}) to "${dest}".`,
      evaluated_at: nowIso,
    };
  }

  const wasRedacted = detectedFields.some((f) => f.action === 'REDACTED' || f.action === 'DROPPED');
  return {
    evaluation_id: `dfeval-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    destination: dest,
    decision: wasRedacted ? 'ALLOW_REDACTED' : 'ALLOW',
    highest_tier: highestTier,
    detected_labels: Array.from(labelSet),
    detected_fields: detectedFields,
    sanitized_payload: sanitizedPayload,
    reason: wasRedacted
      ? `Data Flow Guard sanitized ${detectedFields.filter((f) => f.action !== 'KEPT').length} sensitive field(s) before dispatch to "${dest}".`
      : `Data Flow Guard verified payload safety (${highestTier}) for destination "${dest}".`,
    evaluated_at: nowIso,
  };
}
