/**
 * Feature 5: Multi-Source Conflict Resolver
 *
 * Manages multi-source fact observations with full provenance and evaluates
 * configurable conflict resolution policies without silently overwriting
 * contradictory values or performing invalid mathematical averaging.
 */

import crypto from 'crypto';
import type {
  ConflictResolutionPolicy,
  ConflictResolutionStatus,
  ConflictResolutionStrategy,
  DecisionOutcome,
  FactSourceObservation,
  MultiSourceConflictEvaluation,
  SourceAuthorityTier,
} from './types.ts';

function wildcardMatch(pattern: string | undefined, value: string): boolean {
  if (!pattern || pattern === '*') return true;
  if (pattern.endsWith('*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}

const AUTHORITY_RANK: Record<SourceAuthorityTier, number> = {
  OFFICIAL: 5,
  CONTRACTED: 4,
  TRUSTED: 3,
  THIRD_PARTY: 2,
  UNVERIFIED: 1,
};

export function createConflictResolutionPolicy(input: {
  tenant_id: string;
  entity_pattern?: string;
  field_pattern?: string;
  strategy_order?: ConflictResolutionStrategy[];
  trusted_source_order?: string[];
  explicit_source_rules?: Array<{ preferred_source_id: string; min_quality?: number }>;
  min_evidence_quality?: number;
  on_unresolved_decision?: DecisionOutcome;
}): ConflictResolutionPolicy {
  const now = new Date().toISOString();
  return {
    policy_id: `crpol-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id || 'tenant_default',
    entity_pattern: input.entity_pattern || '*',
    field_pattern: input.field_pattern || '*',
    strategy_order:
      input.strategy_order && input.strategy_order.length > 0
        ? input.strategy_order
        : ['OFFICIAL_SOURCE_PRIORITY', 'CONTRACTED_SOURCE_PRIORITY', 'TRUSTED_SOURCE_PRIORITY', 'RECENCY', 'EVIDENCE_COMPLETENESS'],
    trusted_source_order: Array.isArray(input.trusted_source_order) ? input.trusted_source_order : [],
    explicit_source_rules: input.explicit_source_rules,
    min_evidence_quality: typeof input.min_evidence_quality === 'number' ? Math.max(0, Math.min(1, input.min_evidence_quality)) : 0.4,
    allow_mathematical_averaging: false,
    on_unresolved_decision: input.on_unresolved_decision || 'REQUIRE_APPROVAL',
    is_active: true,
    created_at: now,
    updated_at: now,
  };
}

export function selectConflictPolicy(params: {
  policies: ConflictResolutionPolicy[];
  tenantId: string;
  entityId: string;
  fieldName: string;
}): ConflictResolutionPolicy {
  const { policies, tenantId, entityId, fieldName } = params;
  const active = policies.filter((p) => p.is_active && (p.tenant_id === tenantId || p.tenant_id === 'tenant_default' || p.tenant_id === '*'));
  const scored = active
    .filter((p) => wildcardMatch(p.entity_pattern, entityId) && wildcardMatch(p.field_pattern, fieldName))
    .map((p) => {
      let score = 0;
      if (p.tenant_id === tenantId) score += 20;
      if (p.entity_pattern !== '*') score += 10;
      if (p.field_pattern !== '*') score += 8;
      return { policy: p, score };
    })
    .sort((a, b) => b.score - a.score);

  if (scored.length > 0) return scored[0].policy;

  return createConflictResolutionPolicy({
    tenant_id: tenantId,
    strategy_order: ['OFFICIAL_SOURCE_PRIORITY', 'CONTRACTED_SOURCE_PRIORITY', 'TRUSTED_SOURCE_PRIORITY', 'EVIDENCE_COMPLETENESS', 'RECENCY'],
  });
}

export function recordMultiSourceObservation(params: {
  observations: FactSourceObservation[];
  tenantId: string;
  entityId: string;
  fieldName: string;
  value: unknown;
  sourceId: string;
  sourceAuthority?: SourceAuthorityTier;
  sourceVersion?: string;
  verifiedAt?: string;
  observedAt?: string;
  expiry?: string;
  provenance?: Record<string, unknown>;
  evidenceRef?: string;
  dataQuality?: number;
  sourceAvailable?: boolean;
}): FactSourceObservation {
  const now = new Date().toISOString();
  const existingIdx = params.observations.findIndex(
    (o) => o.tenant_id === params.tenantId && o.entity_id === params.entityId && o.field_name === params.fieldName && o.source_id === params.sourceId
  );

  const record: FactSourceObservation = {
    observation_id: existingIdx >= 0 ? params.observations[existingIdx].observation_id : `obs-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    entity_id: params.entityId,
    field_name: params.fieldName,
    value: params.value,
    source_id: params.sourceId,
    source_authority: params.sourceAuthority || 'THIRD_PARTY',
    source_version: params.sourceVersion || '1.0',
    verified_at: params.verifiedAt,
    observed_at: params.observedAt || now,
    expiry: params.expiry,
    provenance: params.provenance || { system: params.sourceId },
    evidence_ref: params.evidenceRef,
    data_quality: typeof params.dataQuality === 'number' ? Math.max(0, Math.min(1, params.dataQuality)) : 0.85,
    source_available: params.sourceAvailable !== false,
    created_at: existingIdx >= 0 ? params.observations[existingIdx].created_at : now,
  };

  if (existingIdx >= 0) {
    params.observations[existingIdx] = record;
  } else {
    params.observations.unshift(record);
  }
  return record;
}

function stableValueKey(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableValueKey).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableValueKey(obj[k])}`).join(',')}}`;
}

function isObservationExpired(obs: FactSourceObservation, nowMs: number): boolean {
  if (!obs.expiry) return false;
  const expMs = new Date(obs.expiry).getTime();
  return !Number.isNaN(expMs) && expMs <= nowMs;
}

export function evaluateMultiSourceConflict(params: {
  observations: FactSourceObservation[];
  policies: ConflictResolutionPolicy[];
  tenantId: string;
  entityId: string;
  fieldName: string;
  nowMs?: number;
  manualWinnerObservationId?: string;
}): MultiSourceConflictEvaluation {
  const nowMs = params.nowMs ?? Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const policy = selectConflictPolicy({
    policies: params.policies,
    tenantId: params.tenantId,
    entityId: params.entityId,
    fieldName: params.fieldName,
  });

  // Strict tenant isolation
  const scoped = params.observations.filter(
    (o) => o.tenant_id === params.tenantId && o.entity_id === params.entityId && o.field_name === params.fieldName
  );

  const historyTrail: Array<{ step: string; detail: string; at: string }> = [
    {
      step: 'COLLECT_OBSERVATIONS',
      detail: `Collected ${scoped.length} source observations for ${params.entityId}.${params.fieldName} in tenant ${params.tenantId}.`,
      at: nowIso,
    },
  ];

  if (scoped.length === 0) {
    return {
      evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      entity_id: params.entityId,
      field_name: params.fieldName,
      status: 'INSUFFICIENT_EVIDENCE',
      recommended_action: 'REVALIDATE',
      retained_non_winning: [],
      policy_id: policy.policy_id,
      explanation: `No multi-source observations found for ${params.entityId}.${params.fieldName}; fail-closed REVALIDATE required.`,
      history_trail: historyTrail,
      evaluated_at: nowIso,
    };
  }

  const available = scoped.filter((o) => o.source_available && !isObservationExpired(o, nowMs));
  if (available.length === 0) {
    historyTrail.push({
      step: 'AVAILABILITY_CHECK',
      detail: 'All recorded sources are currently unavailable or expired.',
      at: nowIso,
    });
    return {
      evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      entity_id: params.entityId,
      field_name: params.fieldName,
      status: 'SOURCE_UNAVAILABLE',
      recommended_action: 'REVALIDATE',
      retained_non_winning: scoped,
      policy_id: policy.policy_id,
      explanation: `All ${scoped.length} observations are unavailable or expired; mathematical averaging is forbidden.`,
      history_trail: historyTrail,
      evaluated_at: nowIso,
    };
  }

  const highQuality = available.filter((o) => o.data_quality >= policy.min_evidence_quality);
  if (highQuality.length === 0) {
    historyTrail.push({
      step: 'EVIDENCE_QUALITY_CHECK',
      detail: `None of the ${available.length} available sources meet min_evidence_quality=${policy.min_evidence_quality}.`,
      at: nowIso,
    });
    return {
      evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      entity_id: params.entityId,
      field_name: params.fieldName,
      status: 'INSUFFICIENT_EVIDENCE',
      recommended_action: 'REVALIDATE',
      retained_non_winning: scoped,
      policy_id: policy.policy_id,
      explanation: `Insufficient evidence quality (all sources below ${policy.min_evidence_quality}); action cannot rely on unverified claims.`,
      history_trail: historyTrail,
      evaluated_at: nowIso,
    };
  }

  // Group distinct semantic values
  const distinctValues = new Set(highQuality.map((o) => stableValueKey(o.value)));
  if (distinctValues.size === 1) {
    const winner = [...highQuality].sort((a, b) => AUTHORITY_RANK[b.source_authority] - AUTHORITY_RANK[a.source_authority])[0];
    const nonWinning = scoped.filter((o) => o.observation_id !== winner.observation_id);
    historyTrail.push({
      step: 'CONSENSUS',
      detail: `All ${highQuality.length} qualified sources agree on value=${JSON.stringify(winner.value)}.`,
      at: nowIso,
    });
    return {
      evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      entity_id: params.entityId,
      field_name: params.fieldName,
      status: 'NO_CONFLICT',
      recommended_action: 'ALLOW',
      winning_observation: winner,
      retained_non_winning: nonWinning,
      policy_id: policy.policy_id,
      explanation: `Consistent multi-source consensus across ${highQuality.length} qualified source(s).`,
      history_trail: historyTrail,
      evaluated_at: nowIso,
    };
  }

  // Conflict detected — check manual resolution first if provided
  if (params.manualWinnerObservationId) {
    const manualWinner = highQuality.find((o) => o.observation_id === params.manualWinnerObservationId);
    if (manualWinner) {
      historyTrail.push({
        step: 'MANUAL_RESOLUTION',
        detail: `Supervisor selected observation ${manualWinner.observation_id} (${manualWinner.source_id}).`,
        at: nowIso,
      });
      return {
        evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
        tenant_id: params.tenantId,
        entity_id: params.entityId,
        field_name: params.fieldName,
        status: 'RESOLVED',
        recommended_action: 'ALLOW',
        winning_observation: manualWinner,
        retained_non_winning: scoped.filter((o) => o.observation_id !== manualWinner.observation_id),
        policy_id: policy.policy_id,
        strategy_applied: 'MANUAL_RESOLUTION',
        explanation: `Conflict resolved via explicit supervisor adjudication favoring source ${manualWinner.source_id}.`,
        history_trail: historyTrail,
        evaluated_at: nowIso,
      };
    }
  }

  // Walk policy strategies cleanly without mathematical averaging
  let candidates = [...highQuality];
  let strategyApplied: ConflictResolutionStrategy | undefined;

  for (const strategy of policy.strategy_order) {
    if (strategy === 'MANUAL_RESOLUTION') {
      // Explicit rule requires human approval when conflict reached
      historyTrail.push({
        step: 'MANUAL_RESOLUTION_REQUIRED',
        detail: `Policy requires MANUAL_RESOLUTION across ${candidates.length} conflicting sources.`,
        at: nowIso,
      });
      return {
        evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
        tenant_id: params.tenantId,
        entity_id: params.entityId,
        field_name: params.fieldName,
        status: 'UNRESOLVED',
        recommended_action: policy.on_unresolved_decision,
        retained_non_winning: scoped,
        policy_id: policy.policy_id,
        strategy_applied: 'MANUAL_RESOLUTION',
        explanation: `Contradictory values remain unresolved (${candidates.map((c) => `${c.source_id}=${JSON.stringify(c.value)}`).join(' vs ')}); manual adjudication required.`,
        history_trail: historyTrail,
        evaluated_at: nowIso,
      };
    }

    let nextCandidates: FactSourceObservation[] = candidates;
    if (strategy === 'EXPLICIT_SOURCE_RULES' && policy.explicit_source_rules?.length) {
      const matched = policy.explicit_source_rules.find((r) =>
        candidates.some((c) => c.source_id === r.preferred_source_id && c.data_quality >= (r.min_quality ?? 0))
      );
      if (matched) {
        nextCandidates = candidates.filter((c) => c.source_id === matched.preferred_source_id);
      }
    } else if (strategy === 'OFFICIAL_SOURCE_PRIORITY') {
      const official = candidates.filter((c) => c.source_authority === 'OFFICIAL');
      if (official.length > 0) nextCandidates = official;
    } else if (strategy === 'CONTRACTED_SOURCE_PRIORITY') {
      const contracted = candidates.filter((c) => c.source_authority === 'OFFICIAL' || c.source_authority === 'CONTRACTED');
      if (contracted.length > 0) nextCandidates = contracted;
    } else if (strategy === 'TRUSTED_SOURCE_PRIORITY') {
      if (policy.trusted_source_order.length > 0) {
        let bestRank = Number.MAX_SAFE_INTEGER;
        for (const c of candidates) {
          const idx = policy.trusted_source_order.indexOf(c.source_id);
          if (idx >= 0 && idx < bestRank) bestRank = idx;
        }
        if (bestRank < Number.MAX_SAFE_INTEGER) {
          const topSourceId = policy.trusted_source_order[bestRank];
          nextCandidates = candidates.filter((c) => c.source_id === topSourceId);
        }
      } else {
        const maxAuth = Math.max(...candidates.map((c) => AUTHORITY_RANK[c.source_authority]));
        nextCandidates = candidates.filter((c) => AUTHORITY_RANK[c.source_authority] === maxAuth);
      }
    } else if (strategy === 'EVIDENCE_COMPLETENESS') {
      const scoreEvidence = (o: FactSourceObservation): number =>
        (o.evidence_ref ? 0.5 : 0) + (o.verified_at ? 0.3 : 0) + o.data_quality * 0.2;
      const maxScore = Math.max(...candidates.map(scoreEvidence));
      nextCandidates = candidates.filter((c) => Math.abs(scoreEvidence(c) - maxScore) < 0.0001);
    } else if (strategy === 'RECENCY') {
      const maxTs = Math.max(...candidates.map((c) => new Date(c.observed_at).getTime()));
      nextCandidates = candidates.filter((c) => new Date(c.observed_at).getTime() === maxTs);
    }

    candidates = nextCandidates;
    const distinctAfter = new Set(candidates.map((c) => stableValueKey(c.value)));
    historyTrail.push({
      step: strategy,
      detail: `Applied ${strategy}: narrowed to ${candidates.length} candidate(s) with ${distinctAfter.size} distinct value(s).`,
      at: nowIso,
    });

    if (distinctAfter.size === 1) {
      strategyApplied = strategy;
      const winner = candidates[0];
      const nonWinning = scoped.filter((o) => o.observation_id !== winner.observation_id);
      return {
        evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
        tenant_id: params.tenantId,
        entity_id: params.entityId,
        field_name: params.fieldName,
        status: 'RESOLVED' as ConflictResolutionStatus,
        recommended_action: 'ALLOW',
        winning_observation: winner,
        retained_non_winning: nonWinning,
        policy_id: policy.policy_id,
        strategy_applied: strategyApplied,
        explanation: `Conflict resolved via ${strategyApplied}: selected source "${winner.source_id}" (${winner.source_authority}, value=${JSON.stringify(winner.value)}). Retained ${nonWinning.length} non-winning record(s).`,
        history_trail: historyTrail,
        evaluated_at: nowIso,
      };
    }
  }

  // Tie still unresolved -> Fail-Closed
  const failDecision: DecisionOutcome = policy.on_unresolved_decision || 'REVALIDATE';
  return {
    evaluation_id: `ceval-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    entity_id: params.entityId,
    field_name: params.fieldName,
    status: 'UNRESOLVED',
    recommended_action: failDecision,
    retained_non_winning: scoped,
    policy_id: policy.policy_id,
    explanation: `Unresolved multi-source conflict across ${candidates.length} tied sources (${candidates.map((c) => `${c.source_id}=${JSON.stringify(c.value)}`).join(' vs ')}). Mathematical averaging prohibited; fail-closed ${failDecision}.`,
    history_trail: historyTrail,
    evaluated_at: nowIso,
  };
}
