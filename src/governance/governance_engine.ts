/**
 * CCK Advanced Agent Governance Engine
 * Pure deterministic algorithms for:
 * 1. Multi-Hop Delegation with non-expansion & cascading revocation
 * 2. Runtime Budget Guard with multi-model pricing & denial-of-wallet protection
 * 3. MCP Server Lifecycle & Schema Drift Detection
 * 4. Capability Evidence Proof generation
 */

import crypto from 'crypto';
import {
  DelegationRecord,
  DelegationChainVerificationResult,
  DelegationScope,
  SpendingCeiling,
  BudgetPolicyRecord,
  ModelPricingTier,
  CostEstimate,
  McpServerRecord,
  McpToolSchema,
  CapabilityEvidenceReceiptRecord,
} from './types';

const HMAC_SECRET = process.env.CCK_SIGNING_SECRET || 'cck_gov_deterministic_kernel_secret_key_v2';

// ============================================================================
// Phase 1: Multi-Hop Delegation Engine
// ============================================================================

export function computeDelegationSignature(payload: {
  delegator_agent_id: string;
  delegatee_agent_id: string;
  parent_delegation_id: string | null;
  root_delegation_id: string;
  scope: DelegationScope;
  spending_limit: SpendingCeiling;
  valid_until: string;
}): string {
  const canonical = JSON.stringify({
    delegator: payload.delegator_agent_id,
    delegatee: payload.delegatee_agent_id,
    parent: payload.parent_delegation_id,
    root: payload.root_delegation_id,
    actions: [...payload.scope.allowed_actions].sort(),
    resources: [...payload.scope.allowed_resources].sort(),
    max_depth: payload.scope.max_depth,
    current_depth: payload.scope.current_depth,
    spending: payload.spending_limit,
    valid_until: payload.valid_until,
  });
  return crypto.createHmac('sha256', HMAC_SECRET).update(canonical).digest('hex');
}

/**
 * Creates a signed Root Delegation tied to root agent authority
 */
export function createRootDelegation(params: {
  delegator_agent_id: string;
  delegatee_agent_id: string;
  tenant_id: string;
  allowed_actions: string[];
  allowed_resources: string[];
  allowed_tools?: string[];
  max_depth?: number;
  spending_limit: SpendingCeiling;
  valid_until: string;
}): DelegationRecord {
  const delegation_id = `del-${crypto.randomUUID().slice(0, 10)}`;
  const max_depth = params.max_depth ?? 3;
  const current_depth = 0;

  const scope: DelegationScope = {
    allowed_actions: [...params.allowed_actions],
    allowed_resources: [...params.allowed_resources],
    allowed_tools: params.allowed_tools ? [...params.allowed_tools] : undefined,
    max_depth,
    current_depth,
  };

  const signature = computeDelegationSignature({
    delegator_agent_id: params.delegator_agent_id,
    delegatee_agent_id: params.delegatee_agent_id,
    parent_delegation_id: null,
    root_delegation_id: delegation_id,
    scope,
    spending_limit: params.spending_limit,
    valid_until: params.valid_until,
  });

  return {
    delegation_id,
    parent_delegation_id: null,
    root_delegation_id: delegation_id,
    delegator_agent_id: params.delegator_agent_id,
    delegatee_agent_id: params.delegatee_agent_id,
    tenant_id: params.tenant_id,
    scope,
    spending_limit: params.spending_limit,
    valid_until: params.valid_until,
    revoked: false,
    signature,
    created_at: new Date().toISOString(),
  };
}

/**
 * Creates a Sub-Delegation with strictly monotonic, non-expanding rights.
 * Fails with Error if child requests rights exceeding parent delegation.
 */
export function createSubDelegation(params: {
  parent: DelegationRecord;
  delegatee_agent_id: string;
  allowed_actions: string[];
  allowed_resources: string[];
  allowed_tools?: string[];
  spending_limit?: Partial<SpendingCeiling>;
  valid_until?: string;
}): DelegationRecord {
  const { parent } = params;

  if (parent.revoked) {
    throw new Error(`Cannot sub-delegate from a revoked delegation ${parent.delegation_id}`);
  }

  // Check expiration
  if (new Date(parent.valid_until).getTime() < Date.now()) {
    throw new Error(`Parent delegation ${parent.delegation_id} has expired`);
  }

  // Depth constraint
  const nextDepth = parent.scope.current_depth + 1;
  if (nextDepth > parent.scope.max_depth) {
    throw new Error(
      `Delegation depth limit exceeded: parent depth ${parent.scope.current_depth} + 1 > max_depth ${parent.scope.max_depth}`
    );
  }

  // Non-expansion constraint: allowed_actions must be a subset of parent's actions (unless parent has wildcard '*')
  const parentAllowsAllActions = parent.scope.allowed_actions.includes('*');
  for (const act of params.allowed_actions) {
    if (!parentAllowsAllActions && !parent.scope.allowed_actions.includes(act)) {
      throw new Error(
        `Sub-delegation expansion violation: action "${act}" is not permitted by parent delegation authority`
      );
    }
  }

  // Non-expansion constraint: allowed_resources must be a subset of parent's resources
  const parentAllowsAllResources = parent.scope.allowed_resources.includes('*');
  for (const res of params.allowed_resources) {
    if (!parentAllowsAllResources && !parent.scope.allowed_resources.includes(res)) {
      throw new Error(
        `Sub-delegation expansion violation: resource "${res}" is not permitted by parent delegation authority`
      );
    }
  }

  // Non-expansion constraint: allowed_tools
  if (params.allowed_tools && parent.scope.allowed_tools) {
    for (const tool of params.allowed_tools) {
      if (!parent.scope.allowed_tools.includes(tool)) {
        throw new Error(
          `Sub-delegation expansion violation: tool "${tool}" is not permitted by parent delegation`
        );
      }
    }
  }

  // Spending limits constraint
  const childMaxPerAction = params.spending_limit?.max_per_action ?? parent.spending_limit.max_per_action;
  if (childMaxPerAction > parent.spending_limit.max_per_action) {
    throw new Error(
      `Sub-delegation expansion violation: max_per_action (${childMaxPerAction}) cannot exceed parent limit (${parent.spending_limit.max_per_action})`
    );
  }

  const childTotalBudget = params.spending_limit?.total_budget ?? parent.spending_limit.total_budget;
  if (childTotalBudget > parent.spending_limit.total_budget) {
    throw new Error(
      `Sub-delegation expansion violation: total_budget (${childTotalBudget}) cannot exceed parent limit (${parent.spending_limit.total_budget})`
    );
  }

  // Validity time constraint
  const childValidUntil = params.valid_until || parent.valid_until;
  if (new Date(childValidUntil).getTime() > new Date(parent.valid_until).getTime()) {
    throw new Error(`Sub-delegation valid_until cannot extend beyond parent validity (${parent.valid_until})`);
  }

  const delegation_id = `del-${crypto.randomUUID().slice(0, 10)}`;
  const childScope: DelegationScope = {
    allowed_actions: [...params.allowed_actions],
    allowed_resources: [...params.allowed_resources],
    allowed_tools: params.allowed_tools ? [...params.allowed_tools] : parent.scope.allowed_tools,
    max_depth: parent.scope.max_depth,
    current_depth: nextDepth,
  };

  const childSpendingLimit: SpendingCeiling = {
    max_per_action: childMaxPerAction,
    total_budget: childTotalBudget,
    currency: parent.spending_limit.currency,
  };

  const signature = computeDelegationSignature({
    delegator_agent_id: parent.delegatee_agent_id,
    delegatee_agent_id: params.delegatee_agent_id,
    parent_delegation_id: parent.delegation_id,
    root_delegation_id: parent.root_delegation_id,
    scope: childScope,
    spending_limit: childSpendingLimit,
    valid_until: childValidUntil,
  });

  return {
    delegation_id,
    parent_delegation_id: parent.delegation_id,
    root_delegation_id: parent.root_delegation_id,
    delegator_agent_id: parent.delegatee_agent_id,
    delegatee_agent_id: params.delegatee_agent_id,
    tenant_id: parent.tenant_id,
    scope: childScope,
    spending_limit: childSpendingLimit,
    valid_until: childValidUntil,
    revoked: false,
    signature,
    created_at: new Date().toISOString(),
  };
}

/**
 * Verifies a delegation chain back to root for an active action dispatch
 */
export function verifyDelegationChain(params: {
  delegation_id: string;
  all_delegations: DelegationRecord[];
  action_capability?: string;
  target_resource?: string;
  amount?: number;
}): DelegationChainVerificationResult {
  const { delegation_id, all_delegations, action_capability, target_resource, amount } = params;

  const chain: DelegationRecord[] = [];
  let current: DelegationRecord | undefined = all_delegations.find((d) => d.delegation_id === delegation_id);

  if (!current) {
    return {
      valid: false,
      chain_length: 0,
      root_delegation_id: '',
      leaf_delegation_id: delegation_id,
      delegations: [],
      failure_reason: `Delegation "${delegation_id}" not found`,
    };
  }

  const visited = new Set<string>();

  while (current) {
    if (visited.has(current.delegation_id)) {
      return {
        valid: false,
        chain_length: chain.length,
        root_delegation_id: current.root_delegation_id,
        leaf_delegation_id: delegation_id,
        delegations: chain,
        failure_reason: `Cycle detected in delegation chain at ${current.delegation_id}`,
        violated_delegation_id: current.delegation_id,
      };
    }
    visited.add(current.delegation_id);
    chain.push(current);

    // 1. Check if revoked
    if (current.revoked) {
      return {
        valid: false,
        chain_length: chain.length,
        root_delegation_id: current.root_delegation_id,
        leaf_delegation_id: delegation_id,
        delegations: chain,
        failure_reason: `Delegation link ${current.delegation_id} is REVOKED (Reason: ${current.revocation_reason || 'Manual revocation'})`,
        violated_delegation_id: current.delegation_id,
      };
    }

    // 2. Check if expired
    if (new Date(current.valid_until).getTime() < Date.now()) {
      return {
        valid: false,
        chain_length: chain.length,
        root_delegation_id: current.root_delegation_id,
        leaf_delegation_id: delegation_id,
        delegations: chain,
        failure_reason: `Delegation link ${current.delegation_id} has EXPIRED (${current.valid_until})`,
        violated_delegation_id: current.delegation_id,
      };
    }

    // 3. Check action capability scope if provided
    if (action_capability) {
      const allowsAction =
        current.scope.allowed_actions.includes('*') ||
        current.scope.allowed_actions.includes(action_capability) ||
        current.scope.allowed_actions.some((a) => a.endsWith('*') && action_capability.startsWith(a.replace('*', '')));

      if (!allowsAction) {
        return {
          valid: false,
          chain_length: chain.length,
          root_delegation_id: current.root_delegation_id,
          leaf_delegation_id: delegation_id,
          delegations: chain,
          failure_reason: `Action capability "${action_capability}" is unauthorized at delegation hop ${current.delegation_id}`,
          violated_delegation_id: current.delegation_id,
        };
      }
    }

    // 4. Check target resource scope if provided
    if (target_resource) {
      const allowsResource =
        current.scope.allowed_resources.includes('*') ||
        current.scope.allowed_resources.includes(target_resource) ||
        current.scope.allowed_resources.some((r) => r.endsWith('*') && target_resource.startsWith(r.replace('*', '')));

      if (!allowsResource) {
        return {
          valid: false,
          chain_length: chain.length,
          root_delegation_id: current.root_delegation_id,
          leaf_delegation_id: delegation_id,
          delegations: chain,
          failure_reason: `Target resource "${target_resource}" is unauthorized at delegation hop ${current.delegation_id}`,
          violated_delegation_id: current.delegation_id,
        };
      }
    }

    // 5. Check spending ceiling if provided
    if (typeof amount === 'number' && amount > 0) {
      if (amount > current.spending_limit.max_per_action) {
        return {
          valid: false,
          chain_length: chain.length,
          root_delegation_id: current.root_delegation_id,
          leaf_delegation_id: delegation_id,
          delegations: chain,
          failure_reason: `Amount $${amount} exceeds spending ceiling $${current.spending_limit.max_per_action} at hop ${current.delegation_id}`,
          violated_delegation_id: current.delegation_id,
        };
      }
    }

    if (!current.parent_delegation_id) {
      break; // Reached root
    }

    const nextId: string = current.parent_delegation_id;
    current = all_delegations.find((d) => d.delegation_id === nextId);
    if (!current) {
      return {
        valid: false,
        chain_length: chain.length,
        root_delegation_id: '',
        leaf_delegation_id: delegation_id,
        delegations: chain,
        failure_reason: `Broken chain: Parent delegation "${nextId}" does not exist`,
      };
    }
  }

  return {
    valid: true,
    chain_length: chain.length,
    root_delegation_id: chain[chain.length - 1].delegation_id,
    leaf_delegation_id: delegation_id,
    delegations: chain,
  };
}

/**
 * Cascades revocation to a delegation and all of its descendants
 */
export function cascadeRevokeDelegation(
  target_delegation_id: string,
  all_delegations: DelegationRecord[],
  reason: string
): { revoked_count: number; revoked_ids: string[] } {
  const revoked_ids: string[] = [];
  const now = new Date().toISOString();

  // Find all descendants using BFS
  const queue = [target_delegation_id];
  const toRevoke = new Set<string>();

  while (queue.length > 0) {
    const currentId = queue.shift()!;
    if (toRevoke.has(currentId)) continue;
    toRevoke.add(currentId);

    // Find children
    for (const d of all_delegations) {
      if (d.parent_delegation_id === currentId || (currentId === d.root_delegation_id && d.delegation_id !== currentId)) {
        queue.push(d.delegation_id);
      }
    }
  }

  for (const d of all_delegations) {
    if (toRevoke.has(d.delegation_id)) {
      d.revoked = true;
      d.revoked_at = now;
      d.revocation_reason = reason;
      revoked_ids.push(d.delegation_id);
    }
  }

  return { revoked_count: revoked_ids.length, revoked_ids };
}

// ============================================================================
// Phase 2: Runtime Budget Guard — Denial-of-Wallet Protection
// ============================================================================

export const MODEL_PRICING_CATALOG: Record<string, ModelPricingTier> = {
  'gemini-1.5-flash': {
    model_id: 'gemini-1.5-flash',
    provider: 'google',
    input_per_million_usd: 0.075,
    output_per_million_usd: 0.3,
    per_tool_call_usd: 0.0005,
  },
  'gemini-2.0-flash': {
    model_id: 'gemini-2.0-flash',
    provider: 'google',
    input_per_million_usd: 0.1,
    output_per_million_usd: 0.4,
    per_tool_call_usd: 0.0005,
  },
  'gemini-1.5-pro': {
    model_id: 'gemini-1.5-pro',
    provider: 'google',
    input_per_million_usd: 1.25,
    output_per_million_usd: 5.0,
    per_tool_call_usd: 0.001,
  },
  'gpt-4o': {
    model_id: 'gpt-4o',
    provider: 'openai',
    input_per_million_usd: 2.5,
    output_per_million_usd: 10.0,
    per_tool_call_usd: 0.002,
  },
  'gpt-4o-mini': {
    model_id: 'gpt-4o-mini',
    provider: 'openai',
    input_per_million_usd: 0.15,
    output_per_million_usd: 0.6,
    per_tool_call_usd: 0.0005,
  },
  'claude-3-5-sonnet': {
    model_id: 'claude-3-5-sonnet',
    provider: 'anthropic',
    input_per_million_usd: 3.0,
    output_per_million_usd: 15.0,
    per_tool_call_usd: 0.002,
  },
};

/**
 * Pre-call cost estimation based on model pricing catalog
 */
export function estimateCallCost(params: {
  model_id: string;
  estimated_input_tokens?: number;
  estimated_output_tokens?: number;
  tool_calls_count?: number;
}): CostEstimate {
  const modelId = params.model_id || 'gemini-1.5-flash';
  const tier = MODEL_PRICING_CATALOG[modelId] || MODEL_PRICING_CATALOG['gemini-1.5-flash'];
  const inTokens = params.estimated_input_tokens || 1000;
  const outTokens = params.estimated_output_tokens || 500;
  const tools = params.tool_calls_count || 1;

  const cost =
    (inTokens / 1_000_000) * tier.input_per_million_usd +
    (outTokens / 1_000_000) * tier.output_per_million_usd +
    tools * tier.per_tool_call_usd;

  return {
    model_id: modelId,
    estimated_input_tokens: inTokens,
    estimated_output_tokens: outTokens,
    tool_calls_count: tools,
    estimated_cost_usd: Number(cost.toFixed(6)),
  };
}

/**
 * Checks budget guard policy limits (Denial-of-Wallet protection)
 */
export function evaluateBudgetGuard(params: {
  budget: BudgetPolicyRecord;
  estimated_cost_usd: number;
  additional_tool_calls?: number;
  active_runs?: number;
}): {
  allowed: boolean;
  halt_reason?: string;
  remaining_budget_usd: number;
} {
  const { budget, estimated_cost_usd } = params;
  const remaining = Math.max(0, budget.limits.max_budget_usd - budget.usage.spent_usd);

  if (budget.status === 'HALTED' || budget.status === 'EXHAUSTED') {
    return {
      allowed: false,
      halt_reason: budget.halt_reason || 'Budget policy is already halted.',
      remaining_budget_usd: Number(remaining.toFixed(4)),
    };
  }

  // 1. Cost Ceiling Check
  if (budget.usage.spent_usd + estimated_cost_usd > budget.limits.max_budget_usd) {
    const reason = `Denial-of-Wallet Protection: Projected cost $${estimated_cost_usd.toFixed(
      4
    )} exceeds remaining budget $${remaining.toFixed(4)} (Spent: $${budget.usage.spent_usd.toFixed(
      4
    )} / Max: $${budget.limits.max_budget_usd.toFixed(4)})`;
    return {
      allowed: false,
      halt_reason: reason,
      remaining_budget_usd: Number(remaining.toFixed(4)),
    };
  }

  // 2. Model Calls Limit Check
  if (budget.usage.model_calls >= budget.limits.max_model_calls) {
    const reason = `Denial-of-Wallet Protection: Model call limit reached (${budget.usage.model_calls}/${budget.limits.max_model_calls} calls)`;
    return {
      allowed: false,
      halt_reason: reason,
      remaining_budget_usd: Number(remaining.toFixed(4)),
    };
  }

  // 3. Tool Calls Limit Check
  const additionalTools = params.additional_tool_calls || 1;
  if (budget.usage.tool_calls + additionalTools > budget.limits.max_tool_calls) {
    const reason = `Denial-of-Wallet Protection: Tool execution limit exceeded (${budget.usage.tool_calls + additionalTools}/${budget.limits.max_tool_calls} allowed)`;
    return {
      allowed: false,
      halt_reason: reason,
      remaining_budget_usd: Number(remaining.toFixed(4)),
    };
  }

  // 4. Concurrency Limit Check
  if (
    typeof params.active_runs === 'number' &&
    params.active_runs >= budget.limits.max_concurrent_runs
  ) {
    const reason = `Concurrency limit exceeded (${params.active_runs}/${budget.limits.max_concurrent_runs} runs)`;
    return {
      allowed: false,
      halt_reason: reason,
      remaining_budget_usd: Number(remaining.toFixed(4)),
    };
  }

  return {
    allowed: true,
    remaining_budget_usd: Number(remaining.toFixed(4)),
  };
}

// ============================================================================
// Phase 3: MCP Server Lifecycle & Drift Detection
// ============================================================================

export function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k])).join(',') + '}';
}

export function computeToolSchemaHash(input_schema: Record<string, unknown>): string {
  const canonical = canonicalJsonStringify(input_schema);
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

export function detectMcpDrift(
  existingServer: McpServerRecord,
  newTools: Array<{
    name: string;
    description: string;
    input_schema: Record<string, unknown>;
    is_sensitive?: boolean;
    sensitive_reason?: string;
    required_permissions?: string[];
  }>
): {
  has_drift: boolean;
  requires_review: boolean;
  drift_reasons: string[];
  updated_tools: McpToolSchema[];
} {
  const drift_reasons: string[] = [];
  let requires_review = false;
  const existingMap = new Map(existingServer.exposed_tools.map((t) => [t.name, t]));
  const updated_tools: McpToolSchema[] = [];

  for (const tool of newTools) {
    const newHash = computeToolSchemaHash(tool.input_schema);
    const existing = existingMap.get(tool.name);

    const isSensitive =
      Boolean(tool.is_sensitive) ||
      tool.name.toLowerCase().includes('exec') ||
      tool.name.toLowerCase().includes('delete') ||
      tool.name.toLowerCase().includes('shell') ||
      tool.name.toLowerCase().includes('payment') ||
      tool.name.toLowerCase().includes('refund');

    if (!existing) {
      drift_reasons.push(`New tool added: "${tool.name}"`);
      if (isSensitive) {
        requires_review = true;
        drift_reasons.push(`Sensitive tool added without supervisor approval: "${tool.name}"`);
      }
      updated_tools.push({
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        schema_hash: newHash,
        is_sensitive: isSensitive,
        sensitive_reason: tool.sensitive_reason || (isSensitive ? 'Automated sensitivity heuristic' : undefined),
        approved_for_production: !isSensitive, // Sensitive tools start unapproved
        required_permissions: tool.required_permissions || [],
      });
    } else {
      if (existing.schema_hash !== newHash) {
        drift_reasons.push(`Schema drift detected for tool "${tool.name}" (Hash: ${existing.schema_hash} -> ${newHash})`);
        requires_review = true;
      }
      updated_tools.push({
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        schema_hash: newHash,
        is_sensitive: isSensitive,
        sensitive_reason: tool.sensitive_reason || existing.sensitive_reason,
        // Retain previous approval ONLY if schema has not drifted
        approved_for_production: existing.schema_hash === newHash ? existing.approved_for_production : !isSensitive,
        required_permissions: tool.required_permissions || existing.required_permissions,
      });
    }
  }

  return {
    has_drift: drift_reasons.length > 0,
    requires_review,
    drift_reasons,
    updated_tools,
  };
}

// ============================================================================
// Phase 4: Capability Evidence Proof
// ============================================================================

export function mintCapabilityEvidenceReceipt(params: {
  tenant_id: string;
  agent_id: string;
  agent_version: string;
  skills_used: string[];
  task_name: string;
  model_id: string;
  results: {
    total_tests: number;
    passed: number;
    failed: number;
    success_rate: number;
    latency_p95_ms: number;
    total_cost_usd: number;
  };
}): CapabilityEvidenceReceiptRecord {
  const evidence_receipt_id = `cap-rec-${crypto.randomUUID().slice(0, 10)}`;
  const issued_at = new Date().toISOString();

  const canonical = JSON.stringify({
    receipt_id: evidence_receipt_id,
    agent_id: params.agent_id,
    version: params.agent_version,
    skills: [...params.skills_used].sort(),
    task: params.task_name,
    model: params.model_id,
    results: params.results,
    issued_at,
  });

  const tamper_hash = crypto.createHmac('sha256', HMAC_SECRET).update(canonical).digest('hex');

  return {
    evidence_receipt_id,
    tenant_id: params.tenant_id,
    agent_id: params.agent_id,
    agent_version: params.agent_version,
    skills_used: params.skills_used,
    task_name: params.task_name,
    model_id: params.model_id,
    test_suite_environment: {
      isolated_sandbox: true,
      node_version: process.version,
      mock_external_calls: true,
      concurrency_limit: 1,
    },
    results: params.results,
    issued_at,
    tamper_hash,
  };
}
