/**
 * Feature 12 (+ Batch 2 Composition): MCP Runtime Enforcement Gateway
 *
 * Physical interception proxy positioned between AI agents/MCP clients and
 * downstream MCP tools. Evaluates the complete CCK Batch 1 + Batch 2 pipeline
 * BEFORE any downstream tool handler or remote MCP server is called:
 *
 *   Identity & Tenant Check
 *   -> Upstream Status Check
 *   -> Tool Identity & Drift Policy (Features 9 & 10)
 *   -> Permission Graph & Least Privilege (Feature 11)
 *   -> Multi-Source Conflict Resolver (Feature 5, when observations exist)
 *   -> Dependency Invalidation Cascade (Feature 4)
 *   -> Adaptive Fact Freshness (Feature 1)
 *   -> Data Flow & Leakage Guard (Feature 15) — inspects, redacts/minimizes, or blocks BEFORE egress
 *   -> Ephemeral Secret Broker Lease Issuance (Feature 13, when secret_ref requested)
 *   -> Per-Call Isolation Context Allocation (Feature 14)
 *   -> Core Action Gate (Kill Switch, Mandates, Contracts, Delegations, Budgets, Policies, Preconditions)
 *   -> ONLY ON ALLOW: Network Egress Controller + Governed Downstream Dispatch (Feature 16)
 *   -> Runtime Behavior Baseline & Drift Check (Feature 17)
 *   -> Deterministic Teardown (revoking per-call secret leases & clearing volatile scratch)
 *   -> Zero-Leakage Decision Receipt + Audit Hash Chain Entry + Invocation Ledger
 *
 * Fail-Closed Guarantee:
 * - On BLOCK, REQUIRE_APPROVAL, REVALIDATE, tenant mismatch, missing permissions,
 *   drifted schema, unresolved conflict, unauthorized data flow, invalid secret lease,
 *   disallowed egress/redirect, or internal exception: downstream execution = 0 calls.
 */

import crypto from 'crypto';
import type {
  BehaviorDriftEventRecord,
  ConflictResolutionPolicy,
  DataClassificationRule,
  DataFlowEvaluationResult,
  DataFlowPolicyRecord,
  DecisionOutcome,
  DependencyEdgeRecord,
  DependencyNodeRecord,
  EgressDecisionReceipt,
  EphemeralSecretLease,
  FactSourceObservation,
  FreshnessPolicyRecord,
  InvocationContextSnapshot,
  McpGatewayInvocationRecord,
  McpUpstreamToolRecord,
  NetworkEgressPolicyRecord,
  PermissionGrantRecord,
  RegisteredSecretRecord,
  SecretAccessAuditRecord,
  ToolBehaviorBaselineRecord,
  ToolDriftFinding,
  ToolIdentityRecord,
} from './types.ts';
import type { FreshnessFactInput } from './freshness_engine.ts';
import { evaluateFactFreshness } from './freshness_engine.ts';
import { checkProtectedActionCascadeBlock } from './dependency_cascade.ts';
import { evaluateToolDriftPolicy } from './tool_intelligence.ts';
import { evaluatePermissionGraph } from './permission_graph.ts';
import { evaluateMultiSourceConflict } from './conflict_resolver.ts';
import { evaluateDataFlowGuard } from './data_flow_guard.ts';
import { governedEgressFetch } from './network_egress.ts';
import { issueEphemeralSecretLease, resolveEphemeralLeaseForExecution } from './secret_broker.ts';
import { createIsolatedInvocationContext } from './invocation_isolation.ts';
import { upsertAndRecordBehaviorBaseline } from './behavior_replay.ts';
import type { DelegationRecord } from '../governance/types.ts';

export type LocalMcpToolHandler = (args: Record<string, unknown>, context: {
  tenantId: string;
  agentId: string;
  traceId: string;
  toolId: string;
  invocationId?: string;
  hasEphemeralCredential?: boolean;
}) => Promise<unknown> | unknown;

const localToolHandlers = new Map<string, LocalMcpToolHandler>();

export function registerLocalMcpHandler(handlerKey: string, handler: LocalMcpToolHandler): void {
  localToolHandlers.set(handlerKey, handler);
}

export function unregisterLocalMcpHandler(handlerKey: string): void {
  localToolHandlers.delete(handlerKey);
}

// Built-in safe local handler so registered LOCAL_HANDLER tools work out of the box
registerLocalMcpHandler('builtin:echo_verified', (args, ctx) => ({
  executed: true,
  handler: 'builtin:echo_verified',
  trace_id: ctx.traceId,
  agent_id: ctx.agentId,
  invocation_id: ctx.invocationId,
  echo: args,
  executed_at: new Date().toISOString(),
}));

export async function dispatchUpstreamMcpTool(params: {
  upstream: McpUpstreamToolRecord;
  toolName: string;
  args: Record<string, unknown>;
  tenantId: string;
  agentId: string;
  traceId: string;
  invocationId?: string;
  ephemeralAuthToken?: string;
  abortSignal?: AbortSignal;
  allowLoopback?: boolean;
  egressPolicies?: NetworkEgressPolicyRecord[];
  egressReceipts?: EgressDecisionReceipt[];
}): Promise<{
  ok: boolean;
  status: 'SUCCEEDED' | 'TIMEOUT' | 'UPSTREAM_ERROR' | 'CANCELLED';
  result?: unknown;
  egress_receipt?: EgressDecisionReceipt;
  error?: string;
}> {
  const {
    upstream,
    toolName,
    args,
    tenantId,
    agentId,
    traceId,
    invocationId,
    ephemeralAuthToken,
    abortSignal,
    allowLoopback = false,
    egressPolicies = [],
    egressReceipts = [],
  } = params;

  if (abortSignal?.aborted) {
    return { ok: false, status: 'CANCELLED', error: 'Caller aborted MCP execution before dispatch.' };
  }

  if (upstream.transport === 'LOCAL_HANDLER') {
    const key = upstream.handler_key || 'builtin:echo_verified';
    const handler = localToolHandlers.get(key);
    if (!handler) {
      return {
        ok: false,
        status: 'UPSTREAM_ERROR',
        error: `Local MCP handler "${key}" is not registered.`,
      };
    }
    try {
      const res = await handler(args, {
        tenantId,
        agentId,
        traceId,
        toolId: upstream.tool_id,
        invocationId,
        hasEphemeralCredential: Boolean(ephemeralAuthToken),
      });
      return { ok: true, status: 'SUCCEEDED', result: res };
    } catch (err: unknown) {
      return {
        ok: false,
        status: 'UPSTREAM_ERROR',
        error: err instanceof Error ? err.message : 'Local handler execution failed',
      };
    }
  }

  // HTTP_JSONRPC remote downstream MCP dispatch via Hardened Network Egress Controller
  if (!upstream.endpoint_url) {
    return {
      ok: false,
      status: 'UPSTREAM_ERROR',
      error: 'Upstream MCP server has no endpoint_url configured.',
    };
  }

  const maxAttempts = upstream.is_idempotent ? Math.max(1, Math.min(3, (upstream.max_retries || 0) + 1)) : 1;
  const timeoutMs = Math.max(200, Math.min(30000, upstream.timeout_ms || 5000));

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onParentAbort = () => controller.abort();
    abortSignal?.addEventListener('abort', onParentAbort);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'x-cck-trace-id': traceId,
        'x-cck-tenant-id': tenantId,
        'x-cck-agent-id': agentId,
      };
      if (invocationId) {
        headers['x-cck-invocation-id'] = invocationId;
      }
      if (ephemeralAuthToken) {
        // Ephemeral credential injected strictly in-memory over the wire — never persisted to logs/receipts
        headers['Authorization'] = `Bearer ${ephemeralAuthToken}`;
      }

      const egressOut = await governedEgressFetch({
        tenantId,
        toolId: upstream.tool_id,
        agentId,
        url: upstream.endpoint_url,
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: `gw-${traceId}-${attempt}`,
          method: 'tools/call',
          params: {
            name: toolName,
            arguments: args,
          },
        }),
        signal: controller.signal,
        policies: egressPolicies,
        receiptsLedger: egressReceipts,
        allowLoopbackForTest: allowLoopback,
      });

      clearTimeout(timer);
      abortSignal?.removeEventListener('abort', onParentAbort);

      if (!egressOut.ok || !egressOut.response) {
        return {
          ok: false,
          status: 'UPSTREAM_ERROR',
          egress_receipt: egressOut.receipt,
          error: egressOut.error || egressOut.receipt.reason,
        };
      }

      const response = egressOut.response;
      if (!response.ok) {
        if (attempt < maxAttempts && response.status >= 500) {
          continue;
        }
        return {
          ok: false,
          status: 'UPSTREAM_ERROR',
          egress_receipt: egressOut.receipt,
          error: `Upstream MCP tool responded HTTP ${response.status}`,
        };
      }

      const payload = (await response.json()) as { result?: unknown; error?: { message?: string } };
      if (payload.error) {
        return {
          ok: false,
          status: 'UPSTREAM_ERROR',
          egress_receipt: egressOut.receipt,
          error: payload.error.message || 'Downstream MCP returned JSON-RPC error',
        };
      }
      return { ok: true, status: 'SUCCEEDED', result: payload.result, egress_receipt: egressOut.receipt };
    } catch (err: unknown) {
      clearTimeout(timer);
      abortSignal?.removeEventListener('abort', onParentAbort);
      const isAbort = err instanceof Error && err.name === 'AbortError';
      if (abortSignal?.aborted) {
        return { ok: false, status: 'CANCELLED', error: 'MCP call cancelled by caller.' };
      }
      if (attempt < maxAttempts && isAbort) {
        continue;
      }
      return {
        ok: false,
        status: isAbort ? 'TIMEOUT' : 'UPSTREAM_ERROR',
        error: isAbort
          ? `Upstream MCP execution timed out after ${timeoutMs}ms`
          : err instanceof Error
          ? err.message
          : 'Upstream MCP dispatch failure',
      };
    }
  }

  return { ok: false, status: 'UPSTREAM_ERROR', error: 'Exceeded maximum gateway dispatch retries.' };
}

export interface GatewayPipelineDeps {
  upstreams: McpUpstreamToolRecord[];
  toolIdentities: ToolIdentityRecord[];
  toolDrifts: ToolDriftFinding[];
  permissionGrants: PermissionGrantRecord[];
  freshnessPolicies: FreshnessPolicyRecord[];
  facts: FreshnessFactInput[];
  dependencyNodes: DependencyNodeRecord[];
  dependencyEdges: DependencyEdgeRecord[];
  delegations: DelegationRecord[];
  invocations: McpGatewayInvocationRecord[];
  // Batch 2 extensions (optional for backwards compatibility with unit calls)
  factObservations?: FactSourceObservation[];
  conflictPolicies?: ConflictResolutionPolicy[];
  secrets?: RegisteredSecretRecord[];
  secretLeases?: EphemeralSecretLease[];
  secretAccessLogs?: SecretAccessAuditRecord[];
  invocationContexts?: InvocationContextSnapshot[];
  dataClassifications?: DataClassificationRule[];
  dataFlowPolicies?: DataFlowPolicyRecord[];
  egressPolicies?: NetworkEgressPolicyRecord[];
  egressReceipts?: EgressDecisionReceipt[];
  behaviorBaselines?: ToolBehaviorBaselineRecord[];
  behaviorDrifts?: BehaviorDriftEventRecord[];
  evaluateActionGate: (body: Record<string, unknown>) => { status: number; result: Record<string, unknown> };
  recordGatewayAudit: (params: {
    actionId: string;
    agentId: string;
    tenantId: string;
    decision: DecisionOutcome;
    riskScore: number;
    reason: string;
    executionStatus: string;
  }) => { audit_id: string };
}

export async function executeThroughMcpGateway(params: {
  deps: GatewayPipelineDeps;
  tenantId: string;
  agentId: string;
  userId?: string;
  upstreamId?: string;
  toolId?: string;
  toolName: string;
  capability?: string;
  target: string;
  entityId?: string;
  requiredFactField?: string;
  requestedScopes?: string[];
  delegationId?: string;
  secretRef?: string;
  secretScope?: string;
  sessionId?: string;
  parameters?: Record<string, unknown>;
  traceId?: string;
  idempotencyKey?: string;
  allowLoopbackUpstream?: boolean;
  abortSignal?: AbortSignal;
}): Promise<{
  allowed: boolean;
  decision: DecisionOutcome;
  invocation: McpGatewayInvocationRecord;
  downstream_result?: unknown;
  action_gate_result?: Record<string, unknown>;
  permission_evaluation?: ReturnType<typeof evaluatePermissionGraph>;
  freshness_evaluation?: ReturnType<typeof evaluateFactFreshness>;
  data_flow_evaluation?: DataFlowEvaluationResult;
  egress_receipt?: EgressDecisionReceipt;
  invocation_isolation?: InvocationContextSnapshot;
  secret_lease_id?: string;
  error?: string;
}> {
  const startedAt = Date.now();
  const traceId = params.traceId || `tr-${crypto.randomUUID().slice(0, 10)}`;
  const stages: McpGatewayInvocationRecord['pipeline_stages'] = [];

  const finalizeBlocked = (
    decision: DecisionOutcome,
    reason: string,
    extra?: {
      capability?: string;
      toolId?: string;
      receiptId?: string;
      actionGateResult?: Record<string, unknown>;
      permissionEval?: ReturnType<typeof evaluatePermissionGraph>;
      freshnessEval?: ReturnType<typeof evaluateFactFreshness>;
      dataFlowEval?: DataFlowEvaluationResult;
      egressReceipt?: EgressDecisionReceipt;
    }
  ) => {
    const actionId = `mcpgw-${crypto.randomUUID().slice(0, 8)}`;
    const audit = params.deps.recordGatewayAudit({
      actionId,
      agentId: params.agentId,
      tenantId: params.tenantId,
      decision,
      riskScore: decision === 'BLOCK' ? 0.95 : 0.65,
      reason,
      executionStatus: `MCP_GATEWAY_${decision}`,
    });
    const inv: McpGatewayInvocationRecord = {
      invocation_id: `minv-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      trace_id: traceId,
      agent_id: params.agentId,
      user_id: params.userId,
      tool_id: extra?.toolId || params.toolId || params.toolName,
      tool_name: params.toolName,
      capability: extra?.capability || params.capability || `mcp.${params.toolName}`,
      target: params.target,
      verdict_decision: decision,
      downstream_dispatched: false,
      downstream_status: 'NOT_CALLED',
      latency_ms: Date.now() - startedAt,
      receipt_id: extra?.receiptId,
      audit_id: audit.audit_id,
      reason,
      pipeline_stages: stages,
      created_at: new Date().toISOString(),
    };
    params.deps.invocations.unshift(inv);
    if (params.deps.invocations.length > 200) {
      params.deps.invocations.pop();
    }
    return {
      allowed: false,
      decision,
      invocation: inv,
      action_gate_result: extra?.actionGateResult,
      permission_evaluation: extra?.permissionEval,
      freshness_evaluation: extra?.freshnessEval,
      data_flow_evaluation: extra?.dataFlowEval,
      egress_receipt: extra?.egressReceipt,
    };
  };

  let isolationHandle: ReturnType<typeof createIsolatedInvocationContext> | null = null;
  let issuedLeaseId: string | undefined;

  try {
    // Stage 1: Resolve Registered Upstream Tool within Tenant Isolation Boundary
    const candidateUpstream = params.deps.upstreams.find(
      (u) =>
        (params.upstreamId && u.upstream_id === params.upstreamId) ||
        (params.toolId && u.tool_id === params.toolId && u.tenant_id === params.tenantId) ||
        (u.tool_name === params.toolName && u.tenant_id === params.tenantId)
    );

    if (!candidateUpstream) {
      stages.push({
        stage: 'UPSTREAM_REGISTRY',
        status: 'FAIL',
        detail: `No registered MCP upstream found for tool "${params.toolName}" in tenant "${params.tenantId}".`,
      });
      return finalizeBlocked(
        'BLOCK',
        `MCP Gateway BLOCKED: Tool "${params.toolName}" is not registered for tenant "${params.tenantId}" (fail-closed zero-bypass policy).`
      );
    }

    if (candidateUpstream.tenant_id !== params.tenantId) {
      stages.push({
        stage: 'TENANT_ISOLATION',
        status: 'FAIL',
        detail: `Cross-tenant MCP dispatch blocked (caller=${params.tenantId}, upstream=${candidateUpstream.tenant_id}).`,
      });
      return finalizeBlocked(
        'BLOCK',
        `MCP Gateway BLOCKED: Cross-tenant dispatch attempt denied (${params.tenantId} != ${candidateUpstream.tenant_id}).`,
        { toolId: candidateUpstream.tool_id, capability: candidateUpstream.capability }
      );
    }

    if (candidateUpstream.status !== 'ACTIVE') {
      stages.push({
        stage: 'UPSTREAM_STATUS',
        status: 'FAIL',
        detail: `Upstream tool status is ${candidateUpstream.status}.`,
      });
      return finalizeBlocked(
        'BLOCK',
        `MCP Gateway BLOCKED: Upstream tool "${candidateUpstream.tool_name}" is ${candidateUpstream.status}.`,
        { toolId: candidateUpstream.tool_id, capability: candidateUpstream.capability }
      );
    }

    stages.push({
      stage: 'UPSTREAM_REGISTRY',
      status: 'PASS',
      detail: `Verified upstream ${candidateUpstream.upstream_id} (${candidateUpstream.transport}).`,
    });

    const effectiveCap = params.capability || candidateUpstream.capability;
    const effectiveToolId = candidateUpstream.tool_id;
    const destinationLabel = candidateUpstream.endpoint_url || effectiveToolId;

    // Stage 2: Tool Identity Fingerprint & Drift Policy (Features 9 & 10)
    const toolIdentity = params.deps.toolIdentities.find(
      (t) => t.tenant_id === params.tenantId && (t.tool_id === effectiveToolId || t.name === params.toolName)
    );
    const driftRes = evaluateToolDriftPolicy({
      identity: toolIdentity,
      drifts: params.deps.toolDrifts,
      requestedScope: params.requestedScopes?.[0] || effectiveCap,
    });

    if (driftRes.decision !== 'ALLOW') {
      stages.push({
        stage: 'TOOL_DRIFT_CHECK',
        status: 'FAIL',
        detail: driftRes.reason,
      });
      return finalizeBlocked(driftRes.decision, driftRes.reason, {
        toolId: effectiveToolId,
        capability: effectiveCap,
      });
    }
    stages.push({
      stage: 'TOOL_DRIFT_CHECK',
      status: 'PASS',
      detail: driftRes.reason,
    });

    // Stage 3: Permission Graph & Least Privilege (Feature 11) — strictly Fail-Closed in Gateway!
    const boundDelegation = params.delegationId
      ? params.deps.delegations.find((d) => d.delegation_id === params.delegationId) || null
      : null;
    const permRes = evaluatePermissionGraph({
      tenantId: params.tenantId,
      agentId: params.agentId,
      toolId: effectiveToolId,
      resource: params.target,
      action: effectiveCap,
      requestedScopes: params.requestedScopes,
      grants: params.deps.permissionGrants,
      toolIdentity,
      delegation: boundDelegation,
      strictNoImplicitAllow: true,
    });

    if (!permRes.allowed) {
      stages.push({
        stage: 'PERMISSION_GRAPH',
        status: 'FAIL',
        detail: permRes.reason,
      });
      return finalizeBlocked('BLOCK', permRes.reason, {
        toolId: effectiveToolId,
        capability: effectiveCap,
        permissionEval: permRes,
      });
    }
    stages.push({
      stage: 'PERMISSION_GRAPH',
      status: 'PASS',
      detail: permRes.reason,
    });

    // Stage 3.5: Multi-Source Conflict Resolver (Feature 5) if observations exist
    if (params.entityId && params.requiredFactField && params.deps.factObservations && params.deps.factObservations.length > 0) {
      const relevantObs = params.deps.factObservations.filter(
        (o) => o.tenant_id === params.tenantId && o.entity_id === params.entityId && o.field_name === params.requiredFactField
      );
      if (relevantObs.length > 0) {
        const conflictEval = evaluateMultiSourceConflict({
          observations: params.deps.factObservations,
          policies: params.deps.conflictPolicies || [],
          tenantId: params.tenantId,
          entityId: params.entityId,
          fieldName: params.requiredFactField,
        });
        if (conflictEval.recommended_action !== 'ALLOW') {
          stages.push({
            stage: 'CONFLICT_RESOLVER',
            status: 'FAIL',
            detail: conflictEval.explanation,
          });
          return finalizeBlocked(conflictEval.recommended_action, conflictEval.explanation, {
            toolId: effectiveToolId,
            capability: effectiveCap,
            permissionEval: permRes,
          });
        }
        stages.push({
          stage: 'CONFLICT_RESOLVER',
          status: 'PASS',
          detail: conflictEval.explanation,
        });
      }
    }

    // Stage 4: Dependency Invalidation Cascade Check (Feature 4)
    const cascadeCheck = checkProtectedActionCascadeBlock({
      nodes: params.deps.dependencyNodes,
      edges: params.deps.dependencyEdges,
      tenantId: params.tenantId,
      capability: effectiveCap,
      entityId: params.entityId,
      toolId: effectiveToolId,
    });
    if (cascadeCheck.blocked || cascadeCheck.requiresRevalidation) {
      const cascadeDecision: DecisionOutcome = cascadeCheck.blocked ? 'BLOCK' : 'REVALIDATE';
      stages.push({
        stage: 'DEPENDENCY_CASCADE',
        status: 'FAIL',
        detail: cascadeCheck.reason || 'Upstream dependency cascade triggered.',
      });
      return finalizeBlocked(cascadeDecision, cascadeCheck.reason || 'Upstream dependency invalidated.', {
        toolId: effectiveToolId,
        capability: effectiveCap,
        permissionEval: permRes,
      });
    }
    stages.push({
      stage: 'DEPENDENCY_CASCADE',
      status: 'PASS',
      detail: 'No upstream dependency invalidation cascade blocks this action.',
    });

    // Stage 5: Adaptive Fact Freshness Check (Feature 1) if entityId + field specified
    let freshnessEval: ReturnType<typeof evaluateFactFreshness> | undefined;
    if (params.entityId && params.requiredFactField) {
      const fact =
        params.deps.facts.find(
          (f: any) =>
            f.entity_id === params.entityId &&
            f.field_name === params.requiredFactField &&
            f.tenant_id === params.tenantId
        ) ||
        params.deps.facts.find(
          (f: any) =>
            f.entity_id === params.entityId &&
            f.field_name === params.requiredFactField &&
            (!f.tenant_id || f.tenant_id === 'tenant_default')
        );
      freshnessEval = evaluateFactFreshness({
        fact,
        entityId: params.entityId,
        fieldName: params.requiredFactField,
        tenantId: params.tenantId,
        policies: params.deps.freshnessPolicies,
      });

      if (freshnessEval.recommended_action !== 'ALLOW') {
        stages.push({
          stage: 'ADAPTIVE_FRESHNESS',
          status: 'FAIL',
          detail: freshnessEval.explanation,
        });
        return finalizeBlocked(freshnessEval.recommended_action, freshnessEval.explanation, {
          toolId: effectiveToolId,
          capability: effectiveCap,
          permissionEval: permRes,
          freshnessEval,
        });
      }
      stages.push({
        stage: 'ADAPTIVE_FRESHNESS',
        status: 'PASS',
        detail: freshnessEval.explanation,
      });
    } else {
      stages.push({
        stage: 'ADAPTIVE_FRESHNESS',
        status: 'SKIP',
        detail: 'No explicit entity_id+required_fact_field constraint; delegated to core Action Gate dependencies.',
      });
    }

    // Stage 5.5: Data Flow & Leakage Guard (Feature 15) — redact/minimize or block BEFORE egress
    const dataFlowEval = evaluateDataFlowGuard({
      tenantId: params.tenantId,
      destination: destinationLabel,
      payload: params.parameters || {},
      classifications: params.deps.dataClassifications || [],
      policies: params.deps.dataFlowPolicies || [],
    });

    if (dataFlowEval.decision === 'BLOCK') {
      stages.push({
        stage: 'DATA_FLOW_GUARD',
        status: 'FAIL',
        detail: dataFlowEval.reason,
      });
      return finalizeBlocked('BLOCK', dataFlowEval.reason, {
        toolId: effectiveToolId,
        capability: effectiveCap,
        permissionEval: permRes,
        freshnessEval,
        dataFlowEval,
      });
    }
    stages.push({
      stage: 'DATA_FLOW_GUARD',
      status: dataFlowEval.decision === 'ALLOW_REDACTED' ? 'WARN' : 'PASS',
      detail: dataFlowEval.reason,
    });

    const sanitizedArgs = dataFlowEval.sanitized_payload;

    // Stage 6: Core Action Gate Evaluation
    const gateRes = params.deps.evaluateActionGate({
      capability: effectiveCap,
      target: params.target,
      entity_id: params.entityId || params.target,
      agent: params.agentId,
      tenant_id: params.tenantId,
      tool_id: effectiveToolId,
      tool_name: params.toolName,
      delegation_id: params.delegationId,
      idempotency_key: params.idempotencyKey,
      trace_id: traceId,
      parameters: sanitizedArgs,
      skip_gateway_perm_recheck: true,
    });

    const gateDecision = String(gateRes.result?.decision || 'BLOCK') as DecisionOutcome;
    if (gateDecision !== 'ALLOW') {
      stages.push({
        stage: 'ACTION_GATE',
        status: 'FAIL',
        detail: String(gateRes.result?.reason || `Action Gate returned ${gateDecision}`),
      });
      return finalizeBlocked(
        gateDecision,
        String(gateRes.result?.reason || `Action Gate returned ${gateDecision}`),
        {
          toolId: effectiveToolId,
          capability: effectiveCap,
          receiptId: gateRes.result?.receipt_id as string | undefined,
          actionGateResult: gateRes.result,
          permissionEval: permRes,
          freshnessEval,
          dataFlowEval,
        }
      );
    }

    stages.push({
      stage: 'ACTION_GATE',
      status: 'PASS',
      detail: 'Action Gate returned ALLOW.',
    });

    // Stage 6.5: Ephemeral Secret Broker Lease Issuance (Feature 13, if secretRef requested)
    if (params.secretRef) {
      if (!params.deps.secrets || !params.deps.secretLeases || !params.deps.secretAccessLogs) {
        return finalizeBlocked('BLOCK', 'Secret Broker store unavailable (fail-closed).', {
          toolId: effectiveToolId,
          capability: effectiveCap,
          permissionEval: permRes,
          freshnessEval,
          dataFlowEval,
        });
      }
      const leaseRes = issueEphemeralSecretLease({
        secrets: params.deps.secrets,
        leases: params.deps.secretLeases,
        accessLogs: params.deps.secretAccessLogs,
        tenantId: params.tenantId,
        principalId: params.userId || params.agentId,
        agentId: params.agentId,
        toolId: effectiveToolId,
        secretRef: params.secretRef,
        sessionId: params.sessionId || traceId,
        requestedScope: params.secretScope || params.requestedScopes?.[0] || effectiveCap,
        resourceScope: params.target,
        purpose: `mcp_gateway:${params.toolName}`,
        ttlSeconds: 30,
      });
      if (!leaseRes.ok) {
        stages.push({
          stage: 'SECRET_BROKER',
          status: 'FAIL',
          detail: leaseRes.reason,
        });
        return finalizeBlocked('BLOCK', leaseRes.reason, {
          toolId: effectiveToolId,
          capability: effectiveCap,
          permissionEval: permRes,
          freshnessEval,
          dataFlowEval,
        });
      }
      issuedLeaseId = leaseRes.lease.lease_id;
      stages.push({
        stage: 'SECRET_BROKER',
        status: 'PASS',
        detail: `Issued ephemeral per-call lease ${issuedLeaseId} (zero raw secret exposure).`,
      });
    }

    // Stage 6.8: Per-Call Isolation Context Allocation (Feature 14)
    isolationHandle = createIsolatedInvocationContext({
      invocationsLedger: params.deps.invocationContexts || [],
      leases: params.deps.secretLeases || [],
      secrets: params.deps.secrets || [],
      accessLogs: params.deps.secretAccessLogs || [],
      tenantId: params.tenantId,
      agentId: params.agentId,
      toolId: effectiveToolId,
      traceId,
      effectiveScopes: permRes.effective_scopes,
      matchedGrants: permRes.matched_grant_ids,
      classifications: dataFlowEval.detected_labels,
      maxTier: dataFlowEval.highest_tier,
      secretLeaseIds: issuedLeaseId ? [issuedLeaseId] : [],
      timeoutMs: candidateUpstream.timeout_ms,
      payloadObject: sanitizedArgs,
    });

    if (!isolationHandle.ok) {
      stages.push({
        stage: 'PER_CALL_ISOLATION',
        status: 'FAIL',
        detail: isolationHandle.error,
      });
      return finalizeBlocked('BLOCK', isolationHandle.error, {
        toolId: effectiveToolId,
        capability: effectiveCap,
        permissionEval: permRes,
        freshnessEval,
        dataFlowEval,
      });
    }

    const activeContext = isolationHandle.handle;
    let ephemeralAuthToken: string | undefined;
    if (issuedLeaseId && params.deps.secrets && params.deps.secretLeases) {
      const resolved = resolveEphemeralLeaseForExecution({
        secrets: params.deps.secrets,
        leases: params.deps.secretLeases,
        leaseId: issuedLeaseId,
        tenantId: params.tenantId,
        toolId: effectiveToolId,
      });
      if (!resolved.ok) {
        activeContext.teardown('FAILED_CLEANED');
        return finalizeBlocked('BLOCK', resolved.reason, {
          toolId: effectiveToolId,
          capability: effectiveCap,
          permissionEval: permRes,
          freshnessEval,
          dataFlowEval,
        });
      }
      ephemeralAuthToken = resolved.secretValue;
      activeContext.resolvedSecretsBuffer.set(issuedLeaseId, resolved.secretValue);
    }

    stages.push({
      stage: 'PER_CALL_ISOLATION',
      status: 'PASS',
      detail: `Allocated isolated InvocationContext ${activeContext.invocationId}.`,
    });

    // Stage 7: Physical Downstream MCP Tool Dispatch via Governed Egress Controller (Feature 16)
    let dispatch: Awaited<ReturnType<typeof dispatchUpstreamMcpTool>>;
    try {
      dispatch = await dispatchUpstreamMcpTool({
        upstream: candidateUpstream,
        toolName: params.toolName,
        args: sanitizedArgs,
        tenantId: params.tenantId,
        agentId: params.agentId,
        traceId,
        invocationId: activeContext.invocationId,
        ephemeralAuthToken,
        abortSignal: params.abortSignal || activeContext.abortController.signal,
        allowLoopback: params.allowLoopbackUpstream,
        egressPolicies: params.deps.egressPolicies || [],
        egressReceipts: params.deps.egressReceipts || [],
      });
    } finally {
      ephemeralAuthToken = undefined;
      activeContext.teardown(params.abortSignal?.aborted ? 'TIMED_OUT_CLEANED' : 'COMPLETED_CLEANED');
    }

    stages.push({
      stage: 'NETWORK_EGRESS_DISPATCH',
      status: dispatch.ok ? 'PASS' : 'FAIL',
      detail: dispatch.ok
        ? `Dispatched to ${candidateUpstream.transport} cleanly; ephemeral secrets revoked on teardown.`
        : dispatch.error || 'Downstream execution failed.',
    });

    // Stage 8: Runtime Behavior Baseline & Drift Recording (Feature 17)
    if (params.deps.behaviorBaselines && params.deps.behaviorDrifts) {
      const bRes = upsertAndRecordBehaviorBaseline({
        baselines: params.deps.behaviorBaselines,
        driftEvents: params.deps.behaviorDrifts,
        toolIdentities: params.deps.toolIdentities,
        tenantId: params.tenantId,
        toolId: effectiveToolId,
        toolVersion: toolIdentity?.current_version,
        observedPermission: params.requestedScopes?.[0] || effectiveCap,
        observedDestination: destinationLabel,
        observedDataTier: dataFlowEval.highest_tier,
        hadError: !dispatch.ok,
      });
      stages.push({
        stage: 'BEHAVIOR_BASELINE',
        status: bRes.newEvents.length > 0 ? 'WARN' : 'PASS',
        detail:
          bRes.newEvents.length > 0
            ? `Recorded ${bRes.newEvents.length} behavior drift event(s): ${bRes.newEvents[0].detail}`
            : `Updated tool behavior baseline (${bRes.baseline.observed_stats.total_calls} calls, status=${bRes.baseline.deviation_status}).`,
      });
    }

    const inv: McpGatewayInvocationRecord = {
      invocation_id: activeContext.invocationId,
      tenant_id: params.tenantId,
      trace_id: traceId,
      agent_id: params.agentId,
      user_id: params.userId,
      tool_id: effectiveToolId,
      tool_name: params.toolName,
      capability: effectiveCap,
      target: params.target,
      verdict_decision: 'ALLOW',
      downstream_dispatched: true,
      downstream_status: dispatch.status,
      latency_ms: Date.now() - startedAt,
      receipt_id: gateRes.result?.receipt_id as string | undefined,
      reason: dispatch.ok ? 'Allowed & executed via MCP Runtime Gateway.' : dispatch.error || 'Upstream failure',
      pipeline_stages: stages,
      created_at: new Date().toISOString(),
    };
    params.deps.invocations.unshift(inv);
    if (params.deps.invocations.length > 200) {
      params.deps.invocations.pop();
    }

    return {
      allowed: dispatch.ok,
      decision: 'ALLOW',
      invocation: inv,
      downstream_result: dispatch.result,
      action_gate_result: gateRes.result,
      permission_evaluation: permRes,
      freshness_evaluation: freshnessEval,
      data_flow_evaluation: dataFlowEval,
      egress_receipt: dispatch.egress_receipt,
      invocation_isolation: activeContext.snapshot,
      secret_lease_id: issuedLeaseId,
      error: dispatch.error,
    };
  } catch (err: unknown) {
    if (isolationHandle && isolationHandle.ok) {
      isolationHandle.handle.teardown('FAILED_CLEANED');
    }
    const errMsg = err instanceof Error ? err.message : 'Unknown MCP Gateway exception';
    stages.push({ stage: 'GATEWAY_ERROR', status: 'FAIL', detail: errMsg });
    return finalizeBlocked('BLOCK', `MCP Gateway Fail-Closed BLOCK due to internal error: ${errMsg}`);
  }
}
