/**
 * CCK Decision & Action Assurance Types
 * Core domain contracts for EFFECT, CASCADE, Mandate OS, Invariants, Skills, and Incidents.
 */

// -------------------------------------------------------------
// 1. Verified Action Contracts (EFFECT)
// -------------------------------------------------------------
export interface ActionContractRecord {
  contract_id: string;
  tenant_id: string;
  agent_id: string;
  name: string;
  description: string;
  action_capability: string;
  permitted_action?: string; // Convenience alias
  target_resource: string;
  permitted_scope: string[] | { max_occurrences?: number; allowed_parameters?: string[] };
  required_evidence_fields: Array<{
    entity_id: string;
    field_name: string;
    max_age_seconds: number;
  }>;
  required_evidence?: string[]; // Convenience alias
  applicable_invariants: string[];
  expires_at: string;
  expiration_iso?: string; // Convenience alias
  auth_limit: {
    max_executions: number;
    current_executions: number;
    max_total_value?: number;
    spending_ceiling?: number;
    currency?: string;
  };
  spending_ceiling?: number; // Convenience alias
  compensation_supported: boolean;
  compensation_capability?: string;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  created_at: string;
}

export type ExecutionLifecycleState =
  | 'PREPARED'
  | 'AUTHORIZED'
  | 'EXECUTING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'UNKNOWN'
  | 'CANCELLED'
  | 'COMPENSATED';

export interface ContractExecutionRecord {
  execution_id: string;
  tenant_id?: string;
  contract_id: string;
  idempotency_key: string;
  agent_id: string;
  capability: string;
  action_capability?: string; // Convenience alias
  target: string;
  target_resource?: string; // Convenience alias
  command: string;
  parameters: Record<string, unknown>;
  state: ExecutionLifecycleState;
  external_status_verified: boolean;
  external_check_status: 'NOT_CHECKED' | 'CONFIRMED_COMMITTED' | 'CONFIRMED_ABORTED' | 'PENDING_PROBE';
  external_verification_status?: string;
  compensation_supported: boolean;
  compensation_action?: {
    capability: string;
    target: string;
    command: string;
  };
  result_evidence?: {
    payload_hash: string;
    response_snapshot?: unknown;
    receipt_id?: string;
  };
  receipt?: any;
  receipt_id?: string;
  failure_reason?: string;
  error_details?: string;
  history?: Array<{
    state: ExecutionLifecycleState;
    timestamp: string;
    note?: string;
    receipt_id?: string;
  }>;
  created_at: string;
  updated_at: string;
}

// -------------------------------------------------------------
// 2. Evidence Change & Conflict Intelligence (CASCADE + Crossflow)
// -------------------------------------------------------------
export interface FactVersionHistoryRecord {
  history_id: string;
  tenant_id?: string;
  entity_id: string;
  field_name: string;
  version: number;
  value: unknown;
  source: string;
  observed_at: string;
  validity_state: 'VALID' | 'INVALIDATED' | 'STALE' | 'CONFLICT' | 'REVOKED';
  change_type: 'INITIAL' | 'UPDATE' | 'CORRECTION' | 'REVOCATION' | 'CONFLICT_DETECTED';
  provenance: {
    system: string;
    author?: string;
    signature?: string;
    payload_hash: string;
  };
  reason?: string;
}

export interface ConflictRecord {
  conflict_id: string;
  tenant_id?: string;
  entity_id: string;
  field_name: string;
  existing_value: unknown;
  existing_source: string;
  conflicting_value: unknown;
  conflicting_source: string;
  detected_at: string;
  status: 'ACTIVE_CONFLICT' | 'RESOLVED';
  resolution?: {
    resolved_value: unknown;
    resolver: string;
    strategy: 'LATEST_WINS' | 'AUTHORITATIVE_SOURCE' | 'MANUAL_SUPERVISOR';
    resolved_at: string;
    note?: string;
  };
}

export interface RevalidationNoticeRecord {
  revalidation_id: string;
  tenant_id?: string;
  fact_key: string;
  affected_receipt_ids: string[];
  affected_agent_ids: string[];
  reason: string;
  status: 'PENDING_REVALIDATION' | 'REVALIDATED' | 'BLOCKED';
  created_at: string;
}

// -------------------------------------------------------------
// 3. Delegated Authority & Invariant Rules (Mandate OS + INVARIANT)
// -------------------------------------------------------------
export interface AgentMandateRecord {
  mandate_id: string;
  tenant_id: string;
  agent_id: string;
  name: string;
  principal: {
    user_id: string;
    user_email: string;
    role: string;
  };
  allowed_actions: string[];
  allowed_resources: string[];
  spending_limits: {
    max_per_action: number;
    single_action_limit?: number; // Convenience alias
    currency: string;
    total_budget: number;
    current_spent: number;
  };
  merchant_restrictions: {
    allowed_merchants: string[];
    prohibited_merchants: string[];
  };
  destination_restrictions: {
    allowed_domains: string[];
    allow_external_egress: boolean;
  };
  time_limit: {
    valid_from: string;
    valid_until: string;
  };
  explicit_approval_threshold?: {
    amount_greater_than?: number;
    destructive_action: boolean;
  };
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  signature: string;
  created_at: string;
}

export interface BusinessInvariantRule {
  invariant_id: string;
  name: string;
  description: string;
  rule_type: 'DOUBLE_CHARGE' | 'SPEND_LIMIT' | 'DESTINATION_EGRESS' | 'REVOKED_EVIDENCE' | 'SKILL_AUTHORITY';
  enforcement_effect: 'BLOCK' | 'REQUIRE_APPROVAL';
  active: boolean;
}

// -------------------------------------------------------------
// 4. Skill Trust & Lifecycle
// -------------------------------------------------------------
export interface SkillRecord {
  skill_id: string;
  tenant_id?: string;
  name: string;
  version: string;
  publisher: {
    name: string;
    domain: string;
    verified: boolean;
  };
  cryptographic_hash: string;
  signature: string;
  review_info: {
    reviewer_id: string;
    reviewer_name: string;
    verified_credential: boolean;
    credential_details?: string;
    review_date: string;
    review_notes: string;
  };
  domain: string;
  jurisdiction: string;
  status: 'VALID' | 'REVIEW_REQUIRED' | 'EXPIRED' | 'REVOKED' | 'UNVERIFIED';
  expires_at: string;
  history: Array<{
    event: string;
    timestamp: string;
    note: string;
    actor: string;
  }>;
  created_at: string;
}

// -------------------------------------------------------------
// 5. Skill Impact Evaluation
// -------------------------------------------------------------
export interface SkillImpactReceiptRecord {
  impact_receipt_id: string;
  tenant_id?: string;
  receipt_id?: string; // Convenience alias
  skill_id: string;
  skill_version: string;
  model_id: string;
  task_category: string;
  test_method: 'ISOLATED_SANDBOX_REPLAY' | 'DETERMINISTIC_EVAL_HARNESS';
  sample_size: number;
  metrics: {
    baseline_success_rate: number;
    skill_success_rate: number;
    relative_improvement: number;
    baseline_cost_usd: number;
    skill_cost_usd: number;
    baseline_avg_duration_ms: number;
    skill_avg_duration_ms: number;
    safety_violation_rate_baseline: number;
    safety_violation_rate_skill: number;
    human_acceptance_rate?: number;
    baseline?: {
      success_rate: number;
      average_duration_ms: number;
      safety_violations: number;
    };
    with_skill?: {
      success_rate: number;
      average_duration_ms: number;
      safety_violations: number;
    };
  };
  confidence_assessment: string;
  evaluated_at: string;
  privacy_config: {
    external_sharing_enabled: boolean;
    opt_in_telemetry: boolean;
  };
  allow_external_sharing?: boolean; // Convenience alias
  tamper_hash: string;
  cryptographic_hash?: string; // Convenience alias
}

// -------------------------------------------------------------
// 6. Incident-to-Correction + Replay Packs
// -------------------------------------------------------------
export interface IncidentRecord {
  incident_id: string;
  tenant_id: string;
  agent_id: string;
  action_id?: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cause_of_failure: string;
  description?: string;
  root_cause_type?: string;
  affected_agent_id?: string;
  affected_action?: string;
  affected_entity_id?: string;
  affected_skill_id?: string;
  affected_contract_id?: string;
  affected_entities?: string[];
  affected_skills?: string[];
  affected_contracts?: string[];
  status: 'OPEN' | 'INVESTIGATING' | 'CORRECTION_PROPOSED' | 'IN_CORRECTION' | 'RESOLVED';
  resolved_by_correction_pack_id?: string;
  created_at: string;
}

export interface CorrectionPackRecord {
  pack_id: string;
  tenant_id?: string;
  correction_pack_id?: string; // Convenience alias
  incident_id: string;
  version: string;
  target_type?: 'POLICY' | 'SKILL' | 'CONTRACT' | 'PRECONDITION_RULE';
  proposed_diff?: string;
  patch_description?: string;
  precondition_rule_change?: any;
  invariant_rule_change?: any;
  verification_tests: Array<{
    test_id?: string;
    test_name?: string;
    description?: string;
    expected_result?: string;
    passed?: boolean;
  }>;
  state: 'DRAFT' | 'TESTED' | 'APPROVED' | 'REJECTED';
  reviewed_by?: string;
  reviewed_at?: string;
  requires_human_approval: boolean;
  created_at: string;
}

export interface ReplayPackRecord {
  replay_pack_id: string;
  tenant_id?: string;
  incident_id: string;
  sanitized_inputs: Record<string, unknown>;
  expected_baseline_failure: string;
  expected_corrected_success: string;
  last_run_result?: {
    run_at: string;
    status: 'VERIFIED_CORRECTED' | 'REGRESSION_DETECTED' | 'FAILED';
    details: string;
  };
  created_at: string;
}
