/**
 * Feature 17: Runtime Behavior Baseline & Safe Replay
 *
 * Tracks Observed vs Declared vs Expected tool behavior per (tenant_id, tool_id, version),
 * emits typed BehaviorDriftEvents on anomalies (unexpected permission, unexpected destination,
 * data sensitivity escalation, error spike, or frequency spike), and runs Safe Declarative
 * Sanitized Tenant-Isolated Replay Packs without executing arbitrary code or real side effects.
 */

import crypto from 'crypto';
import type {
  BehaviorDriftEventRecord,
  DataSensitivityTier,
  DecisionOutcome,
  SafeReplayPackRecord,
  ToolBehaviorBaselineRecord,
  ToolIdentityRecord,
} from './types.ts';

const TIER_ORDER: Record<DataSensitivityTier, number> = {
  PUBLIC: 1,
  INTERNAL: 2,
  CONFIDENTIAL: 3,
  RESTRICTED: 4,
};

export function upsertAndRecordBehaviorBaseline(params: {
  baselines: ToolBehaviorBaselineRecord[];
  driftEvents: BehaviorDriftEventRecord[];
  toolIdentities: ToolIdentityRecord[];
  tenantId: string;
  toolId: string;
  toolVersion?: string;
  observedPermission?: string;
  observedDestination?: string;
  observedDataTier?: DataSensitivityTier;
  hadError: boolean;
}): { baseline: ToolBehaviorBaselineRecord; newEvents: BehaviorDriftEventRecord[] } {
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const identity = params.toolIdentities.find(
    (t) => t.tenant_id === params.tenantId && (t.tool_id === params.toolId || t.name === params.toolId)
  );
  const version = params.toolVersion || identity?.current_version || '1.0.0';
  const latestDef = identity?.history[0]?.definition;

  let baseline = params.baselines.find(
    (b) => b.tenant_id === params.tenantId && b.tool_id === params.toolId && b.tool_version === version
  );

  if (!baseline) {
    baseline = {
      baseline_id: `tbase-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      tool_id: params.toolId,
      tool_version: version,
      declared_summary: {
        permissions: latestDef?.declared_permissions ? [...latestDef.declared_permissions] : [],
        endpoints: latestDef?.declared_endpoints ? [...latestDef.declared_endpoints] : [],
        capabilities: latestDef?.capabilities ? [...latestDef.capabilities] : [],
      },
      expected_summary: {
        max_calls_per_minute: 60,
        max_error_rate: 0.35,
        allowed_data_tiers: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
      },
      observed_stats: {
        total_calls: 0,
        error_count: 0,
        error_rate: 0,
        observed_permissions: [],
        observed_destinations: [],
        observed_data_categories: [],
        recent_timestamps: [],
      },
      deviation_status: 'NORMAL',
      updated_at: nowIso,
    };
    params.baselines.unshift(baseline);
  }

  // Update observed stats
  baseline.observed_stats.total_calls += 1;
  if (params.hadError) baseline.observed_stats.error_count += 1;
  baseline.observed_stats.error_rate = Number(
    (baseline.observed_stats.error_count / Math.max(1, baseline.observed_stats.total_calls)).toFixed(3)
  );
  baseline.observed_stats.recent_timestamps = [
    nowMs,
    ...baseline.observed_stats.recent_timestamps.filter((ts) => nowMs - ts <= 60_000),
  ].slice(0, 120);
  baseline.observed_stats.last_call_at = nowIso;

  const newEvents: BehaviorDriftEventRecord[] = [];
  const pushEvent = (
    category: BehaviorDriftEventRecord['category'],
    severity: BehaviorDriftEventRecord['severity'],
    detail: string,
    triggersReview: boolean
  ) => {
    const ev: BehaviorDriftEventRecord = {
      event_id: `bdrift-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      tool_id: params.toolId,
      tool_version: version,
      baseline_id: baseline!.baseline_id,
      category,
      severity,
      detail,
      policy_review_triggered: triggersReview,
      detected_at: nowIso,
    };
    newEvents.push(ev);
    params.driftEvents.unshift(ev);
    if (params.driftEvents.length > 300) params.driftEvents.pop();
  };

  if (params.observedPermission && !baseline.observed_stats.observed_permissions.includes(params.observedPermission)) {
    baseline.observed_stats.observed_permissions.push(params.observedPermission);
    if (
      baseline.declared_summary.permissions.length > 0 &&
      !baseline.declared_summary.permissions.includes(params.observedPermission)
    ) {
      pushEvent(
        'UNEXPECTED_PERMISSION',
        'HIGH',
        `Observed permission "${params.observedPermission}" deviates from declared permissions [${baseline.declared_summary.permissions.join(', ')}].`,
        true
      );
    }
  }

  if (params.observedDestination && !baseline.observed_stats.observed_destinations.includes(params.observedDestination)) {
    baseline.observed_stats.observed_destinations.push(params.observedDestination);
    if (
      baseline.declared_summary.endpoints.length > 0 &&
      !baseline.declared_summary.endpoints.some((ep) => params.observedDestination!.includes(ep) || ep === '*')
    ) {
      pushEvent(
        'UNEXPECTED_DESTINATION',
        'CRITICAL',
        `Observed destination "${params.observedDestination}" is outside declared endpoints [${baseline.declared_summary.endpoints.join(', ')}].`,
        true
      );
    }
  }

  if (params.observedDataTier) {
    if (!baseline.observed_stats.observed_data_categories.includes(params.observedDataTier)) {
      baseline.observed_stats.observed_data_categories.push(params.observedDataTier);
    }
    const maxExpectedRank = Math.max(...baseline.expected_summary.allowed_data_tiers.map((t) => TIER_ORDER[t]));
    if (TIER_ORDER[params.observedDataTier] > maxExpectedRank) {
      pushEvent(
        'DATA_CATEGORY_ESCALATION',
        'CRITICAL',
        `Observed data tier "${params.observedDataTier}" exceeds baseline ceiling [${baseline.expected_summary.allowed_data_tiers.join(', ')}].`,
        true
      );
    }
  }

  if (
    baseline.observed_stats.total_calls >= 3 &&
    baseline.observed_stats.error_rate > baseline.expected_summary.max_error_rate
  ) {
    pushEvent(
      'ERROR_SPIKE',
      'MEDIUM',
      `Observed error rate ${(baseline.observed_stats.error_rate * 100).toFixed(1)}% exceeded threshold ${(baseline.expected_summary.max_error_rate * 100).toFixed(1)}%.`,
      false
    );
  }

  if (baseline.observed_stats.recent_timestamps.length > baseline.expected_summary.max_calls_per_minute) {
    pushEvent(
      'FREQUENCY_ANOMALY',
      'HIGH',
      `Call frequency ${baseline.observed_stats.recent_timestamps.length}/min exceeded expected limit ${baseline.expected_summary.max_calls_per_minute}/min.`,
      true
    );
  }

  if (newEvents.some((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH')) {
    baseline.deviation_status = 'POLICY_VIOLATION';
  } else if (newEvents.length > 0) {
    baseline.deviation_status = 'DEVIATION_WARNING';
  }
  baseline.updated_at = nowIso;

  return { baseline, newEvents };
}

export function createSafeReplayPack(input: {
  tenant_id: string;
  incident_id?: string;
  name: string;
  version?: string;
  tool_id: string;
  agent_id: string;
  mode?: 'DRY_RUN' | 'MOCK_ADAPTER' | 'SANDBOX_SIMULATION';
  sanitized_actions: Array<{
    step_id?: string;
    capability: string;
    target: string;
    sanitized_parameters?: Record<string, unknown>;
    expected_decision?: DecisionOutcome;
  }>;
}): SafeReplayPackRecord {
  const serializeStr = JSON.stringify(input.sanitized_actions || []);
  if (/__proto__|constructor\.prototype|eval\(|child_process|require\(|process\.exit/i.test(serializeStr)) {
    throw new Error('Unsafe replay specification rejected: arbitrary code or prototype payloads forbidden.');
  }

  // Sanitize any lingering sensitive parameter keys before persisting
  const cleanedActions = (input.sanitized_actions || []).map((a, idx) => {
    const cleanParams: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(a.sanitized_parameters || {})) {
      if (/secret|token|password|api_key|card_number|cvv/i.test(k)) {
        cleanParams[k] = '[SANITIZED_FOR_REPLAY]';
      } else {
        cleanParams[k] = v;
      }
    }
    return {
      step_id: a.step_id || `step-${idx + 1}`,
      capability: a.capability,
      target: a.target,
      sanitized_parameters: cleanParams,
      expected_decision: a.expected_decision || 'ALLOW',
    };
  });

  return {
    replay_pack_id: `srpk-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id,
    incident_id: input.incident_id,
    name: input.name,
    version: input.version || '1.0.0',
    tool_id: input.tool_id,
    agent_id: input.agent_id,
    mode: input.mode || 'DRY_RUN',
    sanitized_actions: cleanedActions,
    side_effect_guard: {
      external_network_blocked: true,
      financial_mutations_blocked: true,
      code_exec_blocked: true,
    },
    created_at: new Date().toISOString(),
  };
}

export function executeSafeReplayPack(params: {
  pack: SafeReplayPackRecord;
  evaluateGateDryRun: (actionInput: {
    capability: string;
    target: string;
    agent: string;
    tenant_id: string;
    tool_id: string;
    parameters: Record<string, unknown>;
    shadow_mode: boolean;
  }) => { result: { decision?: string; simulated_decision?: string; reason?: string } };
}): NonNullable<SafeReplayPackRecord['last_run']> {
  const { pack, evaluateGateDryRun } = params;
  const runId = `srun-${crypto.randomUUID().slice(0, 8)}`;
  const nowIso = new Date().toISOString();

  // Verify safety guard invariants strictly
  if (
    !pack.side_effect_guard?.external_network_blocked ||
    !pack.side_effect_guard?.financial_mutations_blocked ||
    !pack.side_effect_guard?.code_exec_blocked
  ) {
    const blockedRun: NonNullable<SafeReplayPackRecord['last_run']> = {
      run_id: runId,
      run_at: nowIso,
      status: 'BLOCKED_UNSAFE_REPLAY',
      step_results: [],
      summary: 'Replay rejected: side_effect_guard flags must strictly prohibit external network/financial/code execution.',
    };
    pack.last_run = blockedRun;
    return blockedRun;
  }

  const stepResults: NonNullable<SafeReplayPackRecord['last_run']>['step_results'] = [];
  let regressions = 0;

  for (const step of pack.sanitized_actions) {
    // Evaluate in shadow_mode=true (zero real downstream mutation!)
    const out = evaluateGateDryRun({
      capability: step.capability,
      target: step.target,
      agent: pack.agent_id,
      tenant_id: pack.tenant_id,
      tool_id: pack.tool_id,
      parameters: { ...step.sanitized_parameters, __cck_dry_run: true },
      shadow_mode: true,
    });

    const resObj = (out.result || {}) as Record<string, unknown>;
    const actualDecision = String(resObj.observed_verdict || resObj.simulated_decision || resObj.decision || 'BLOCK') as DecisionOutcome;
    const matched = actualDecision === step.expected_decision;
    if (!matched) regressions += 1;

    stepResults.push({
      step_id: step.step_id,
      actual_decision: actualDecision,
      expected_decision: step.expected_decision,
      matched,
      reason: String(out.result?.reason || ''),
    });
  }

  const runResult: NonNullable<SafeReplayPackRecord['last_run']> = {
    run_id: runId,
    run_at: nowIso,
    status: regressions === 0 ? 'PASSED' : 'REGRESSION_DETECTED',
    step_results: stepResults,
    summary:
      regressions === 0
        ? `Safe ${pack.mode} replay PASSED (${stepResults.length}/${stepResults.length} steps matched with zero real external mutations).`
        : `Safe ${pack.mode} replay detected ${regressions} regression(s) across ${stepResults.length} steps.`,
  };
  pack.last_run = runResult;
  return runResult;
}
