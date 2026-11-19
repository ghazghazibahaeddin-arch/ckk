/**
 * Core type definitions for CCK TypeScript SDK.
 */

export interface AgentIdentity {
  agent_id: string;
  name: string;
  version?: string;
  tenant_id?: string;
  trust_tier?: 'sandboxed' | 'standard' | 'privileged' | 'admin';
}

export type ActionSeverity = 'INFORMATIONAL' | 'STANDARD' | 'MUTATION' | 'DESTRUCTIVE';

export type VerdictDecision = 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE' | 'SIMULATE_ONLY';

export interface AgentAction {
  action_id?: string;
  agent: AgentIdentity;
  session_id: string;
  capability: string;
  target: string;
  entity_id?: string;
  tool_id?: string;
  delegation_id?: string;
  trace_id?: string;
  tenant_id?: string;
  parameters?: Record<string, unknown>;
  severity?: ActionSeverity;
  idempotency_key?: string;
}

export interface PolicyMatch {
  rule_id: string;
  rule_name: string;
  effect: VerdictDecision;
  reason: string;
  risk_score: number;
}

export interface ExecutionVerdict {
  verdict_id: string;
  action_id: string;
  decision: VerdictDecision;
  risk_level: string;
  risk_score: number;
  reason: string;
  matched_policies: PolicyMatch[];
  remediation_suggestions: string[];
  evaluated_at: string;
  shadow_mode?: boolean;
  simulated_decision?: VerdictDecision;
  receipt_id?: string;
}

export interface DecisionReceipt {
  receipt_id: string;
  action_id: string;
  decision: VerdictDecision;
  agent_id: string;
  tenant_id: string;
  project_id: string;
  capability: string;
  target_resource: string;
  risk_score: number;
  timestamp: string;
  rule_name: string;
  receipt_hash: string;
  verified_chain_status: boolean;
}

export interface HeartbeatResult {
  status: 'CONNECTED' | 'DISCONNECTED' | 'INVALID_CREDENTIALS' | 'REVOKED' | 'ERROR';
  agent_id: string;
  last_seen_at: string;
  heartbeat_acknowledged: boolean;
  message?: string;
}

export interface CCKClientOptions {
  baseUrl?: string;
  apiKey?: string;
  sessionToken?: string;
  tenantId?: string;
  timeoutMs?: number;
  maxRetries?: number;
}
