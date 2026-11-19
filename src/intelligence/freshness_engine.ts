/**
 * Feature 1: Adaptive Freshness Engine
 *
 * Evaluates temporal & causal validity of facts using bounded adaptive TTL
 * driven by policy rules (source, fact type, entity pattern, risk class) and
 * historical stability/volatility. Fails closed on INVALIDATED/REVOKED/CONFLICT
 * and enforces strict ceiling bounds on CRITICAL / HIGH risk facts.
 */

import crypto from 'crypto';
import type {
  FactRiskClass,
  FreshnessEvaluationResult,
  FreshnessPolicyRecord,
  FreshnessStatus,
} from './types.ts';

export interface FreshnessFactInput {
  entity_id: string;
  field_name: string;
  value: unknown;
  source: string;
  observed_at: string;
  state: 'VALID' | 'INVALIDATED' | 'STALE' | 'UNKNOWN' | 'CONFLICT' | 'REVOKED';
  ttl_seconds: number;
  risk_class?: FactRiskClass;
  change_timestamps?: string[];
  stability_score?: number;
}

const RISK_TTL_HARD_CEILING_SECONDS: Record<FactRiskClass, number> = {
  CRITICAL: 120,
  HIGH: 600,
  MEDIUM: 3600,
  LOW: 86400,
};

const RISK_DEFAULT_TTL_SECONDS: Record<FactRiskClass, number> = {
  CRITICAL: 60,
  HIGH: 300,
  MEDIUM: 900,
  LOW: 3600,
};

function matchesPattern(pattern: string | undefined, value: string): boolean {
  if (!pattern || pattern === '*') return true;
  if (pattern.endsWith('*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}

export function inferFactRiskClass(entityId: string, fieldName: string): FactRiskClass {
  const combined = `${entityId}.${fieldName}`.toLowerCase();
  if (
    combined.includes('payment') ||
    combined.includes('balance') ||
    combined.includes('auth') ||
    combined.includes('permission') ||
    combined.includes('fraud') ||
    combined.includes('kyc') ||
    combined.includes('settlement')
  ) {
    return 'CRITICAL';
  }
  if (
    combined.includes('status') ||
    combined.includes('inventory') ||
    combined.includes('stock') ||
    combined.includes('price') ||
    combined.includes('order') ||
    combined.includes('contract')
  ) {
    return 'HIGH';
  }
  if (combined.includes('profile') || combined.includes('address') || combined.includes('metadata')) {
    return 'LOW';
  }
  return 'MEDIUM';
}

export function selectFreshnessPolicy(params: {
  policies: FreshnessPolicyRecord[];
  tenantId: string;
  entityId: string;
  fieldName: string;
  source: string;
  explicitRiskClass?: FactRiskClass;
}): FreshnessPolicyRecord {
  const { policies, tenantId, entityId, fieldName, source, explicitRiskClass } = params;
  const riskClass = explicitRiskClass || inferFactRiskClass(entityId, fieldName);

  const candidates = policies
    .filter((p) => p.is_active && (p.tenant_id === tenantId || p.tenant_id === 'tenant_default' || p.tenant_id === '*'))
    .filter((p) => matchesPattern(p.source_id, source))
    .filter((p) => matchesPattern(p.fact_type, fieldName))
    .filter((p) => matchesPattern(p.entity_pattern, entityId));

  // Rank specificity: exact matches score higher than wildcard '*'
  candidates.sort((a, b) => {
    const score = (p: FreshnessPolicyRecord) =>
      (p.tenant_id === tenantId ? 8 : 0) +
      (p.entity_pattern && p.entity_pattern !== '*' ? 4 : 0) +
      (p.fact_type && p.fact_type !== '*' ? 2 : 0) +
      (p.source_id && p.source_id !== '*' ? 1 : 0);
    return score(b) - score(a);
  });

  if (candidates.length > 0) {
    return candidates[0];
  }

  const ceiling = RISK_TTL_HARD_CEILING_SECONDS[riskClass];
  const def = Math.min(RISK_DEFAULT_TTL_SECONDS[riskClass], ceiling);
  return {
    policy_id: `pol-fresh-default-${riskClass.toLowerCase()}`,
    tenant_id: tenantId,
    source_id: '*',
    fact_type: '*',
    entity_pattern: '*',
    risk_class: riskClass,
    min_ttl_seconds: Math.min(10, def),
    default_ttl_seconds: def,
    max_ttl_seconds: ceiling,
    stale_grace_seconds: riskClass === 'CRITICAL' ? 0 : Math.min(30, Math.floor(def * 0.25)),
    fail_mode: riskClass === 'CRITICAL' ? 'BLOCK_ON_EXPIRED' : 'REVALIDATE_ON_STALE',
    policy_version: 1,
    is_active: true,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
  };
}

/**
 * Computes bounded adaptive TTL deterministically:
 * - High volatility (recent changes or low stability_score) shrinks TTL toward min_ttl_seconds.
 * - High stability gently expands toward max_ttl_seconds, never exceeding policy max or risk ceiling.
 */
export function calculateAdaptiveTtlSeconds(params: {
  policy: FreshnessPolicyRecord;
  factTtlSeconds?: number;
  stabilityScore?: number;
  changeTimestamps?: string[];
  nowMs?: number;
}): { effective_ttl_seconds: number; base_ttl_seconds: number; adaptive_factor: number } {
  const { policy, factTtlSeconds, stabilityScore, changeTimestamps, nowMs = Date.now() } = params;
  const riskCeiling = RISK_TTL_HARD_CEILING_SECONDS[policy.risk_class];
  const minBound = Math.max(1, Math.min(policy.min_ttl_seconds, riskCeiling));
  const maxBound = Math.max(minBound, Math.min(policy.max_ttl_seconds, riskCeiling));

  // If the fact explicitly specifies a tighter TTL, respect the tighter bound
  const baseRaw =
    typeof factTtlSeconds === 'number' && factTtlSeconds > 0
      ? Math.min(factTtlSeconds, policy.default_ttl_seconds)
      : policy.default_ttl_seconds;
  const base = Math.max(minBound, Math.min(baseRaw, maxBound));

  // Volatility factor from recent changes within the last hour
  const recentWindowMs = 3600 * 1000;
  const recentChanges = (changeTimestamps || []).filter((ts) => {
    const t = new Date(ts).getTime();
    return !Number.isNaN(t) && nowMs - t <= recentWindowMs && nowMs - t >= 0;
  }).length;

  let factor = 1.0;
  if (typeof stabilityScore === 'number' && !Number.isNaN(stabilityScore)) {
    // stabilityScore in [0, 1]: 0 => 0.4x (volatile), 1 => 1.35x (stable)
    const clampedScore = Math.max(0, Math.min(1, stabilityScore));
    factor = 0.4 + clampedScore * 0.95;
  }
  if (recentChanges >= 3) {
    factor = Math.min(factor, 0.35);
  } else if (recentChanges === 2) {
    factor = Math.min(factor, 0.55);
  } else if (recentChanges === 1) {
    factor = Math.min(factor, 0.8);
  }

  // CRITICAL facts are strictly non-expanding beyond default TTL
  if (policy.risk_class === 'CRITICAL') {
    factor = Math.min(factor, 1.0);
  }

  const computed = Math.round(base * factor);
  const bounded = Math.max(minBound, Math.min(computed, maxBound));

  return {
    effective_ttl_seconds: bounded,
    base_ttl_seconds: base,
    adaptive_factor: Number((bounded / Math.max(1, base)).toFixed(3)),
  };
}

export function evaluateFactFreshness(params: {
  fact: FreshnessFactInput | null | undefined;
  entityId: string;
  fieldName: string;
  tenantId: string;
  policies: FreshnessPolicyRecord[];
  nowMs?: number;
}): FreshnessEvaluationResult {
  const { fact, entityId, fieldName, tenantId, policies, nowMs = Date.now() } = params;

  if (!fact) {
    const fallbackPolicy = selectFreshnessPolicy({
      policies,
      tenantId,
      entityId,
      fieldName,
      source: '*',
    });
    return {
      entity_id: entityId,
      field_name: fieldName,
      freshness_status: 'UNKNOWN',
      recommended_action: fallbackPolicy.risk_class === 'CRITICAL' ? 'BLOCK' : 'REVALIDATE',
      risk_class: fallbackPolicy.risk_class,
      age_seconds: -1,
      base_ttl_seconds: fallbackPolicy.default_ttl_seconds,
      effective_ttl_seconds: fallbackPolicy.default_ttl_seconds,
      adaptive_factor: 1,
      expires_at: null,
      policy_id: fallbackPolicy.policy_id,
      policy_version: fallbackPolicy.policy_version,
      explanation: `No verified fact observation exists for ${entityId}.${fieldName}. Revalidation required before execution.`,
    };
  }

  const policy = selectFreshnessPolicy({
    policies,
    tenantId,
    entityId: fact.entity_id,
    fieldName: fact.field_name,
    source: fact.source,
    explicitRiskClass: fact.risk_class,
  });

  const { effective_ttl_seconds, base_ttl_seconds, adaptive_factor } = calculateAdaptiveTtlSeconds({
    policy,
    factTtlSeconds: fact.ttl_seconds,
    stabilityScore: fact.stability_score,
    changeTimestamps: fact.change_timestamps,
    nowMs,
  });

  const observedMs = new Date(fact.observed_at).getTime();
  const ageSeconds = Number.isNaN(observedMs)
    ? Number.MAX_SAFE_INTEGER
    : Math.max(0, Math.floor((nowMs - observedMs) / 1000));
  const expiresAtIso = Number.isNaN(observedMs)
    ? null
    : new Date(observedMs + effective_ttl_seconds * 1000).toISOString();

  // Invariant: Never consider invalidated, revoked, or conflicted facts valid!
  if (fact.state === 'INVALIDATED' || fact.state === 'REVOKED' || fact.state === 'CONFLICT') {
    return {
      entity_id: fact.entity_id,
      field_name: fact.field_name,
      freshness_status: 'INVALIDATED',
      recommended_action: 'BLOCK',
      risk_class: policy.risk_class,
      age_seconds: ageSeconds,
      base_ttl_seconds,
      effective_ttl_seconds,
      adaptive_factor,
      expires_at: expiresAtIso,
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      explanation: `Fact ${fact.entity_id}.${fact.field_name} is in ${fact.state} state. Fail-closed BLOCK enforced regardless of age (${ageSeconds}s).`,
    };
  }

  if (fact.state === 'UNKNOWN' || Number.isNaN(observedMs)) {
    return {
      entity_id: fact.entity_id,
      field_name: fact.field_name,
      freshness_status: 'UNKNOWN',
      recommended_action: policy.risk_class === 'CRITICAL' ? 'BLOCK' : 'REVALIDATE',
      risk_class: policy.risk_class,
      age_seconds: ageSeconds,
      base_ttl_seconds,
      effective_ttl_seconds,
      adaptive_factor,
      expires_at: expiresAtIso,
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      explanation: `Fact ${fact.entity_id}.${fact.field_name} has UNKNOWN state or unparseable timestamp.`,
    };
  }

  let status: FreshnessStatus = 'FRESH';
  if (fact.state === 'STALE') {
    status = ageSeconds > effective_ttl_seconds + policy.stale_grace_seconds ? 'EXPIRED' : 'STALE';
  } else if (ageSeconds > effective_ttl_seconds + policy.stale_grace_seconds) {
    status = 'EXPIRED';
  } else if (ageSeconds > effective_ttl_seconds) {
    status = 'STALE';
  }

  if (status === 'FRESH') {
    return {
      entity_id: fact.entity_id,
      field_name: fact.field_name,
      freshness_status: 'FRESH',
      recommended_action: 'ALLOW',
      risk_class: policy.risk_class,
      age_seconds: ageSeconds,
      base_ttl_seconds,
      effective_ttl_seconds,
      adaptive_factor,
      expires_at: expiresAtIso,
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      explanation: `Fact ${fact.entity_id}.${fact.field_name} is FRESH (age ${ageSeconds}s <= adaptive TTL ${effective_ttl_seconds}s, risk ${policy.risk_class}).`,
    };
  }

  // Non-fresh evaluation (STALE or EXPIRED)
  const shouldBlock =
    (status === 'EXPIRED' && policy.fail_mode === 'BLOCK_ON_EXPIRED') ||
    (policy.fail_mode === 'BLOCK_ON_STALE');

  return {
    entity_id: fact.entity_id,
    field_name: fact.field_name,
    freshness_status: status,
    recommended_action: shouldBlock ? 'BLOCK' : 'REVALIDATE',
    risk_class: policy.risk_class,
    age_seconds: ageSeconds,
    base_ttl_seconds,
    effective_ttl_seconds,
    adaptive_factor,
    expires_at: expiresAtIso,
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    explanation: `Fact ${fact.entity_id}.${fact.field_name} is ${status} (age ${ageSeconds}s > adaptive TTL ${effective_ttl_seconds}s, policy fail_mode=${policy.fail_mode}).`,
  };
}

export function createFreshnessPolicy(input: {
  tenant_id: string;
  source_id?: string;
  fact_type?: string;
  entity_pattern?: string;
  risk_class: FactRiskClass;
  min_ttl_seconds?: number;
  default_ttl_seconds?: number;
  max_ttl_seconds?: number;
  stale_grace_seconds?: number;
  fail_mode?: FreshnessPolicyRecord['fail_mode'];
}): FreshnessPolicyRecord {
  const now = new Date().toISOString();
  const ceiling = RISK_TTL_HARD_CEILING_SECONDS[input.risk_class];
  const defaultTtl = Math.max(
    1,
    Math.min(input.default_ttl_seconds ?? RISK_DEFAULT_TTL_SECONDS[input.risk_class], ceiling)
  );
  const minTtl = Math.max(1, Math.min(input.min_ttl_seconds ?? Math.min(10, defaultTtl), defaultTtl));
  const maxTtl = Math.max(defaultTtl, Math.min(input.max_ttl_seconds ?? ceiling, ceiling));

  return {
    policy_id: `fpol-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id,
    source_id: input.source_id || '*',
    fact_type: input.fact_type || '*',
    entity_pattern: input.entity_pattern || '*',
    risk_class: input.risk_class,
    min_ttl_seconds: minTtl,
    default_ttl_seconds: defaultTtl,
    max_ttl_seconds: maxTtl,
    stale_grace_seconds: Math.max(0, Math.min(input.stale_grace_seconds ?? (input.risk_class === 'CRITICAL' ? 0 : 15), 300)),
    fail_mode: input.fail_mode || (input.risk_class === 'CRITICAL' ? 'BLOCK_ON_EXPIRED' : 'REVALIDATE_ON_STALE'),
    policy_version: 1,
    is_active: true,
    created_at: now,
    updated_at: now,
  };
}
