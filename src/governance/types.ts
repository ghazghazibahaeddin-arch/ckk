/**
 * CCK Advanced Agent Governance & Assurance Types
 * Phase 1: Multi-Hop Delegation & Contextual Permission Gateway
 * Phase 2: Runtime Budget Guard — Denial-of-Wallet Protection
 * Phase 3: MCP Server Lifecycle Governance
 * Phase 4: Skill Trust, Capability Evidence Proof & Impact
 */

// ============================================================================
// Phase 1: Multi-Hop Delegation
// ============================================================================

export interface DelegationScope {
  allowed_actions: string[]; // Monotonic subset
  allowed_resources: string[]; // Monotonic subset
  allowed_tools?: string[];
  max_depth: number;
  current_depth: number;
}

export interface SpendingCeiling {
  max_per_action: number;
  total_budget: number;
  currency: string;
}

export interface DelegationRecord {
  delegation_id: string;
  parent_delegation_id: string | null; // null for root
  root_delegation_id: string;
  delegator_agent_id: string;
  delegatee_agent_id: string;
  tenant_id: string;
  scope: DelegationScope;
  spending_limit: SpendingCeiling;
  valid_until: string; // ISO date
  revoked: boolean;
  revocation_reason?: string;
  revoked_at?: string;
  signature: string; // HMAC-SHA256 of canonical payload
  created_at: string;
}

export interface DelegationChainVerificationResult {
  valid: boolean;
  chain_length: number;
  root_delegation_id: string;
  leaf_delegation_id: string;
  delegations: DelegationRecord[];
  failure_reason?: string;
  violated_delegation_id?: string;
}

// ============================================================================
// Phase 2: Runtime Budget Guard (Denial-of-Wallet Protection)
// ============================================================================

export type BudgetScopeType = 'TENANT' | 'AGENT' | 'TASK';

export interface ModelPricingTier {
  model_id: string;
  provider: 'google' | 'openai' | 'anthropic';
  input_per_million_usd: number;
  output_per_million_usd: number;
  per_tool_call_usd: number;
}

export interface BudgetLimits {
  max_budget_usd: number;
  max_model_calls: number;
  max_tool_calls: number;
  max_retries: number;
  max_delegation_depth: number;
  max_execution_timeout_ms: number;
  max_concurrent_runs: number;
}

export interface BudgetUsage {
  spent_usd: number;
  model_calls: number;
  tool_calls: number;
  retries: number;
  active_concurrent_runs: number;
}

export interface BudgetPolicyRecord {
  budget_id: string;
  tenant_id: string;
  scope_type: BudgetScopeType;
  scope_id: string;
  limits: BudgetLimits;
  usage: BudgetUsage;
  status: 'ACTIVE' | 'EXHAUSTED' | 'HALTED';
  halt_reason?: string;
  created_at: string;
  updated_at: string;
}

export interface CostEstimate {
  model_id: string;
  estimated_input_tokens: number;
  estimated_output_tokens: number;
  tool_calls_count: number;
  estimated_cost_usd: number;
}

// ============================================================================
// Phase 3: MCP Server Lifecycle Governance
// ============================================================================

export type McpTransport = 'STDIO' | 'SSE' | 'STREAMABLE_HTTP' | 'IN_PROCESS';

export type McpLifecycleStatus =
  | 'REGISTERED'
  | 'ACTIVE'
  | 'REVIEW_REQUIRED'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'UNAVAILABLE';

export interface McpToolSchema {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  schema_hash: string;
  is_sensitive: boolean;
  sensitive_reason?: string;
  approved_for_production: boolean;
  required_permissions: string[];
}

export interface McpServerRecord {
  server_id: string;
  tenant_id: string;
  name: string;
  transport: McpTransport;
  endpoint_url?: string;
  version: string;
  fingerprint: string;
  auth_method: 'BEARER_TOKEN' | 'MTLS' | 'API_KEY' | 'NONE';
  exposed_tools: McpToolSchema[];
  requested_permissions: string[];
  health_status: 'HEALTHY' | 'DEGRADED' | 'DOWN';
  last_seen: string;
  changelog: Array<{
    timestamp: string;
    event: string;
    details: string;
  }>;
  trust_state: 'VERIFIED' | 'COMMUNITY' | 'PROVISIONAL' | 'UNTRUSTED';
  lifecycle_status: McpLifecycleStatus;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Phase 4: Capability Evidence Proof (4B) & Trust (4A)
// ============================================================================

export interface CapabilityEvidenceReceiptRecord {
  evidence_receipt_id: string;
  tenant_id: string;
  agent_id: string;
  agent_version: string;
  skills_used: string[];
  task_name: string;
  model_id: string;
  test_suite_environment: {
    isolated_sandbox: boolean;
    node_version: string;
    mock_external_calls: boolean;
    concurrency_limit: number;
  };
  results: {
    total_tests: number;
    passed: number;
    failed: number;
    success_rate: number;
    latency_p95_ms: number;
    total_cost_usd: number;
  };
  issued_at: string;
  tamper_hash: string;
}
