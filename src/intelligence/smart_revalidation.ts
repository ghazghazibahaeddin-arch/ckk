/**
 * Feature 6: Smart Revalidation & Delta Refresh
 *
 * Uses Dependency Graph & Invalidation Cascade + Adaptive Freshness Engine
 * to compute the minimal affected subset of facts/evidence, run selective
 * Delta or Full refresh against sources under rate/budget/timeout controls,
 * and NEVER marks stale facts FRESH when an external source fails.
 */

import crypto from 'crypto';
import type {
  ChangeSourceRecord,
  ConflictResolutionPolicy,
  DependencyEdgeRecord,
  DependencyNodeRecord,
  FactSourceObservation,
  FreshnessPolicyRecord,
  MultiSourceConflictEvaluation,
  RefreshMode,
  RevalidationPlanRecord,
} from './types.ts';
import { evaluateFactFreshness } from './freshness_engine.ts';
import { checkRadarRateLimit, pollExternalRadarSource } from './change_radar.ts';
import { evaluateMultiSourceConflict, recordMultiSourceObservation } from './conflict_resolver.ts';

export interface RevalidationFactRef {
  entity_id: string;
  field_name: string;
  value: unknown;
  source: string;
  observed_at: string;
  version: number;
  state: 'VALID' | 'INVALIDATED' | 'CONFLICT' | 'REVOKED' | 'STALE' | 'UNKNOWN';
  ttl_seconds: number;
  tenant_id?: string;
  expires_at?: string;
  stability_score?: number;
  change_timestamps?: string[];
}

export async function planAndExecuteSmartRevalidation(params: {
  tenantId: string;
  triggerReason: string;
  mode?: RefreshMode;
  entityId?: string;
  fieldName?: string;
  sourceId?: string;
  refreshBudget?: number;
  maxRetries?: number;
  timeoutMs?: number;
  allowLoopbackForTest?: boolean;
  inlineUpdates?: Array<{ entity_id: string; field_name: string; value: unknown; source_id?: string; changed_fields?: string[] }>;
  simulateSourceFailure?: string;
  facts: RevalidationFactRef[];
  freshnessPolicies: FreshnessPolicyRecord[];
  dependencyNodes: DependencyNodeRecord[];
  dependencyEdges: DependencyEdgeRecord[];
  changeSources: ChangeSourceRecord[];
  observations: FactSourceObservation[];
  conflictPolicies: ConflictResolutionPolicy[];
}): Promise<{
  plan: RevalidationPlanRecord;
  conflict_evaluations: MultiSourceConflictEvaluation[];
}> {
  const mode: RefreshMode = params.mode === 'FULL' ? 'FULL' : 'DELTA';
  const budget = Math.max(1, Math.min(50, params.refreshBudget ?? 10));
  const maxRetries = Math.max(0, Math.min(3, params.maxRetries ?? 1));
  const timeoutMs = Math.max(200, Math.min(15000, params.timeoutMs ?? 4000));

  // 1. Identify minimal affected facts via Freshness + Dependency Graph
  const tenantFacts = params.facts.filter((f) => !f.tenant_id || f.tenant_id === params.tenantId || f.tenant_id === 'tenant_default');
  const candidateFacts: Array<{ fact: RevalidationFactRef; reason: string }> = [];

  for (const f of tenantFacts) {
    if (params.entityId && f.entity_id !== params.entityId) continue;
    if (params.fieldName && f.field_name !== params.fieldName) continue;

    const fresh = evaluateFactFreshness({
      fact: f,
      entityId: f.entity_id,
      fieldName: f.field_name,
      tenantId: params.tenantId,
      policies: params.freshnessPolicies,
    });

    const nodeRef = `${f.entity_id}:${f.field_name}`;
    const depNode = params.dependencyNodes.find(
      (n) => n.tenant_id === params.tenantId && n.node_type === 'FACT' && n.ref_id === nodeRef
    );
    const isCascadeAffected = depNode && (depNode.state === 'INVALIDATED' || depNode.state === 'REVALIDATE_REQUIRED' || depNode.state === 'STALE');

    if (mode === 'FULL' || fresh.freshness_status !== 'FRESH' || isCascadeAffected || f.state !== 'VALID' || (params.entityId && params.fieldName)) {
      const expReason =
        fresh.freshness_status !== 'FRESH'
          ? `freshness=${fresh.freshness_status}`
          : isCascadeAffected
          ? `cascade_state=${depNode?.state}`
          : f.state !== 'VALID'
          ? `fact_state=${f.state}`
          : 'explicit_target_or_full_refresh';
      candidateFacts.push({ fact: f, reason: expReason });
    }
  }

  // Respect refresh budget (smallest minimal subset up to budget)
  const boundedTargets = candidateFacts.slice(0, budget);

  // Also collect affected dependency node IDs downstream
  const targetNodeIds = new Set<string>();
  for (const item of boundedTargets) {
    const factNode = params.dependencyNodes.find(
      (n) => n.tenant_id === params.tenantId && n.node_type === 'FACT' && n.ref_id === `${item.fact.entity_id}:${item.fact.field_name}`
    );
    if (factNode) {
      targetNodeIds.add(factNode.node_id);
      const outEdges = params.dependencyEdges.filter((e) => e.tenant_id === params.tenantId && e.from_node_id === factNode.node_id);
      for (const edge of outEdges) targetNodeIds.add(edge.to_node_id);
    }
  }

  const plan: RevalidationPlanRecord = {
    plan_id: `revalplan-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    trigger_reason: params.triggerReason || 'smart_revalidation',
    mode,
    target_facts: boundedTargets.map((b) => ({
      entity_id: b.fact.entity_id,
      field_name: b.fact.field_name,
      source_id: params.sourceId || b.fact.source,
      expiration_reason: b.reason,
    })),
    dependency_node_ids: Array.from(targetNodeIds),
    refresh_budget: budget,
    max_retries: maxRetries,
    timeout_ms: timeoutMs,
    status: 'RUNNING',
    refreshed_facts: [],
    failed_facts: [],
    attempts: 0,
    conflict_rechecks: 0,
    explanation: '',
    created_at: new Date().toISOString(),
  };

  const conflictEvaluations: MultiSourceConflictEvaluation[] = [];

  if (boundedTargets.length === 0) {
    plan.status = 'SUCCEEDED';
    plan.completed_at = new Date().toISOString();
    plan.explanation = 'No stale, expired, or cascade-invalidated facts detected within scope; 0 external calls made.';
    return { plan, conflict_evaluations: conflictEvaluations };
  }

  // Rate limit check if sourceId matches a registered ChangeSource
  const matchedSource = params.sourceId
    ? params.changeSources.find((s) => s.tenant_id === params.tenantId && (s.source_id === params.sourceId || s.name === params.sourceId))
    : undefined;

  if (matchedSource) {
    const rate = checkRadarRateLimit({
      tenantId: params.tenantId,
      sourceId: matchedSource.source_id,
      maxPerMinute: matchedSource.rate_limit_per_minute,
    });
    if (!rate.allowed) {
      plan.status = 'RATE_LIMITED';
      plan.completed_at = new Date().toISOString();
      plan.failed_facts = boundedTargets.map((b) => ({
        entity_id: b.fact.entity_id,
        field_name: b.fact.field_name,
        error: `Rate limit exceeded for source ${matchedSource.source_id}; retry after ${rate.retryAfterSeconds}s`,
        kept_stale: true,
      }));
      plan.explanation = `Rate-limited on source ${matchedSource.source_id}; stale/invalidated facts remain fail-closed.`;
      return { plan, conflict_evaluations: conflictEvaluations };
    }
  }

  // Gather refreshed payloads from either ChangeSource poller or inlineUpdates
  let fetchedItems: Array<{ entity_id: string; field_name: string; value: unknown; source_id?: string; changed_fields?: string[] }> = [];
  let sourceError: string | undefined = params.simulateSourceFailure;

  if (!sourceError && Array.isArray(params.inlineUpdates) && params.inlineUpdates.length > 0) {
    fetchedItems = params.inlineUpdates;
  } else if (!sourceError && matchedSource) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      plan.attempts += 1;
      const pollRes = await pollExternalRadarSource({
        source: matchedSource,
        allowLoopbackForTest: params.allowLoopbackForTest,
        timeoutMs,
      });
      if (pollRes.ok) {
        fetchedItems = pollRes.items.map((it) => ({
          entity_id: it.entity_id,
          field_name: it.field_name,
          value: it.value,
          source_id: matchedSource.name || matchedSource.source_id,
          changed_fields: it.value && typeof it.value === 'object' && !Array.isArray(it.value) ? Object.keys(it.value as Record<string, unknown>) : [it.field_name],
        }));
        sourceError = undefined;
        break;
      } else {
        sourceError = pollRes.error || 'Upstream source refresh failed';
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, Math.min(250, 40 * (attempt + 1))));
        }
      }
    }
  } else if (!sourceError) {
    sourceError = 'No reachable live source connector or update payload available for refresh.';
  }

  // Fail-Closed guarantee: if source failed, NEVER mark stale facts FRESH
  if (sourceError) {
    plan.status = 'FAILED_FAIL_CLOSED';
    plan.completed_at = new Date().toISOString();
    plan.failed_facts = boundedTargets.map((b) => ({
      entity_id: b.fact.entity_id,
      field_name: b.fact.field_name,
      error: sourceError!,
      kept_stale: true,
    }));
    plan.explanation = `Smart revalidation failed (${sourceError}). All ${boundedTargets.length} target facts preserved as non-FRESH (fail-closed).`;
    return { plan, conflict_evaluations: conflictEvaluations };
  }

  const nowIso = new Date().toISOString();
  for (const target of boundedTargets) {
    const f = target.fact;
    const match = fetchedItems.find((it) => it.entity_id === f.entity_id && it.field_name === f.field_name);
    if (!match) {
      // Partial / missing item in delta -> keep existing stale state untouched
      plan.failed_facts.push({
        entity_id: f.entity_id,
        field_name: f.field_name,
        error: 'Delta response omitted this fact; preserved current state without false-freshness.',
        kept_stale: true,
      });
      continue;
    }

    const srcName = match.source_id || params.sourceId || f.source || 'smart_revalidation';
    // Record observation & run Conflict Resolver before setting VALID
    recordMultiSourceObservation({
      observations: params.observations,
      tenantId: params.tenantId,
      entityId: f.entity_id,
      fieldName: f.field_name,
      value: match.value,
      sourceId: srcName,
      sourceAuthority: 'TRUSTED',
      observedAt: nowIso,
      dataQuality: 0.9,
      evidenceRef: `reval:${plan.plan_id}`,
    });

    const confEval = evaluateMultiSourceConflict({
      observations: params.observations,
      policies: params.conflictPolicies,
      tenantId: params.tenantId,
      entityId: f.entity_id,
      fieldName: f.field_name,
    });
    conflictEvaluations.push(confEval);
    plan.conflict_rechecks += 1;

    if (confEval.status === 'UNRESOLVED' || confEval.status === 'INSUFFICIENT_EVIDENCE' || confEval.status === 'SOURCE_UNAVAILABLE') {
      f.state = 'CONFLICT';
      plan.failed_facts.push({
        entity_id: f.entity_id,
        field_name: f.field_name,
        error: `Post-refresh conflict status=${confEval.status}: ${confEval.explanation}`,
        kept_stale: true,
      });
      continue;
    }

    // Selective delta merge when object & delta mode
    let updatedFields: string[] = [f.field_name];
    if (mode === 'DELTA' && f.value && typeof f.value === 'object' && !Array.isArray(f.value) && match.value && typeof match.value === 'object' && !Array.isArray(match.value)) {
      const merged = { ...(f.value as Record<string, unknown>), ...(match.value as Record<string, unknown>) };
      updatedFields = Object.keys(match.value as Record<string, unknown>);
      f.value = merged;
    } else {
      f.value = confEval.winning_observation ? confEval.winning_observation.value : match.value;
    }

    f.version += 1;
    f.source = srcName;
    f.observed_at = nowIso;
    f.state = 'VALID';
    f.change_timestamps = [nowIso, ...(f.change_timestamps || [])].slice(0, 20);
    f.expires_at = new Date(Date.now() + (f.ttl_seconds || 300) * 1000).toISOString();

    // Update FACT dependency node if present
    const factNode = params.dependencyNodes.find(
      (n) => n.tenant_id === params.tenantId && n.node_type === 'FACT' && n.ref_id === `${f.entity_id}:${f.field_name}`
    );
    if (factNode) {
      factNode.state = 'VALID';
      factNode.last_changed_at = nowIso;
    }

    plan.refreshed_facts.push({
      entity_id: f.entity_id,
      field_name: f.field_name,
      updated_fields: updatedFields,
      new_version: f.version,
    });
  }

  plan.status =
    plan.refreshed_facts.length > 0 && plan.failed_facts.length === 0
      ? 'SUCCEEDED'
      : plan.refreshed_facts.length > 0
      ? 'PARTIAL_FAILURE'
      : 'FAILED_FAIL_CLOSED';
  plan.completed_at = new Date().toISOString();
  plan.explanation = `${mode} revalidation completed: ${plan.refreshed_facts.length} refreshed, ${plan.failed_facts.length} kept stale/blocked.`;

  return { plan, conflict_evaluations: conflictEvaluations };
}
