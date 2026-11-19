/**
 * CCK Batch 1 Core Intelligence Types
 *
 * Covers:
 * - Feature 1: Adaptive Freshness Engine
 * - Feature 2: Live Change Radar
 * - Feature 3: Semantic Change Detection
 * - Feature 4: Impact & Invalidation Cascade
 * - Feature 9: Tool Identity Fingerprint
 * - Feature 10: Tool Drift Intelligence
 * - Feature 11: Permission Graph & Least Privilege
 * - Feature 12: MCP Runtime Enforcement Gateway
 */

export type DecisionOutcome = 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';

// -------------------------------------------------------------
// Feature 1: Adaptive Freshness Engine
// -------------------------------------------------------------
export type FactRiskClass = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FreshnessStatus = 'FRESH' | 'STALE' | 'EXPIRED' | 'INVALIDATED' | 'UNKNOWN';
export type FreshnessFailMode = 'REVALIDATE_ON_STALE' | 'BLOCK_ON_STALE' | 'BLOCK_ON_EXPIRED';

export interface FreshnessPolicyRecord {
  policy_id: string;
  tenant_id: string;
  source_id?: string; // '*' or specific source
  fact_type?: string; // '*' or field_name / pattern
  entity_pattern?: string; // '*' or prefix like 'order:*'
  risk_class: FactRiskClass;
  min_ttl_seconds: number;
  default_ttl_seconds: number;
  max_ttl_seconds: number;
  stale_grace_seconds: number;
  fail_mode: FreshnessFailMode;
  policy_version: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface FreshnessEvaluationResult {
  entity_id: string;
  field_name: string;
  freshness_status: FreshnessStatus;
  recommended_action: DecisionOutcome;
  risk_class: FactRiskClass;
  age_seconds: number;
  base_ttl_seconds: number;
  effective_ttl_seconds: number;
  adaptive_factor: number;
  expires_at: string | null;
  policy_id: string;
  policy_version: number;
  explanation: string;
}

// -------------------------------------------------------------
// Feature 2: Live Change Radar
// -------------------------------------------------------------
export type ChangeSourceType = 'WEBHOOK' | 'HTTP_POLL' | 'API_POLL' | 'MCP_EVENT' | 'MANUAL';
export type ChangeSourceStatus = 'ACTIVE' | 'PAUSED' | 'FAILED' | 'DEGRADED';

export interface ChangeSourceRecord {
  source_id: string;
  tenant_id: string;
  name: string;
  source_type: ChangeSourceType;
  endpoint_url?: string;
  poll_interval_seconds: number;
  cursor?: string;
  etag?: string;
  last_polled_at?: string;
  last_success_at?: string;
  last_error?: string;
  consecutive_failures: number;
  status: ChangeSourceStatus;
  rate_limit_per_minute: number;
  schema_version: string;
  created_at: string;
  updated_at: string;
}

export interface ChangeEventRecord {
  event_id: string;
  tenant_id: string;
  source_id: string;
  event_type: string;
  schema_version: string;
  entity_id: string;
  field_name: string;
  new_value: unknown;
  previous_value?: unknown;
  version?: number;
  event_timestamp: string;
  ingested_at: string;
  trace_id: string;
  idempotency_key: string;
  payload_hash: string;
  status: 'APPLIED' | 'DUPLICATE_IGNORED' | 'OUT_OF_ORDER_REJECTED' | 'FAILED';
  semantic_diff_id?: string;
  cascade_id?: string;
  error_reason?: string;
  redacted_payload: Record<string, unknown>;
}

export interface FailedChangeEventRecord {
  dead_letter_id: string;
  tenant_id: string;
  source_id: string;
  raw_event_redacted: Record<string, unknown>;
  error_code: string;
  error_message: string;
  trace_id: string;
  idempotency_key?: string;
  failed_at: string;
  retry_count: number;
  replayed_at?: string;
  status: 'PENDING_RETRY' | 'REPLAYED_SUCCEEDED' | 'REPLAYED_FAILED';
}

// -------------------------------------------------------------
// Feature 3: Semantic Change Detection
// -------------------------------------------------------------
export type SemanticChangeClass =
  | 'MATERIAL_CHANGE'
  | 'NON_MATERIAL_CHANGE'
  | 'STRUCTURAL_CHANGE'
  | 'SECURITY_SENSITIVE_CHANGE'
  | 'UNKNOWN_CHANGE';

export interface SemanticFieldDiff {
  path: string;
  change_kind: 'ADDED' | 'REMOVED' | 'MODIFIED' | 'TYPE_CHANGED' | 'CONSTRAINT_CHANGED' | 'PERMISSION_CHANGED' | 'ENDPOINT_CHANGED';
  before_value: unknown;
  after_value: unknown;
  before_type?: string;
  after_type?: string;
  is_material: boolean;
  is_security_sensitive: boolean;
  reason: string;
}

export interface SemanticDiffResult {
  diff_id: string;
  tenant_id: string;
  subject_id: string;
  classification: SemanticChangeClass;
  has_changes: boolean;
  requires_invalidation: boolean;
  added_fields: string[];
  removed_fields: string[];
  modified_fields: string[];
  type_changes: string[];
  permission_changes: string[];
  endpoint_changes: string[];
  constraint_changes: string[];
  diffs: SemanticFieldDiff[];
  summary: string;
  redacted: boolean;
  computed_at: string;
}

// -------------------------------------------------------------
// Feature 4: Impact & Invalidation Cascade
// -------------------------------------------------------------
export type DependencyNodeType =
  | 'SOURCE'
  | 'FACT'
  | 'EVIDENCE'
  | 'ENTITY'
  | 'AGENT_TASK'
  | 'PLAN'
  | 'CONTRACT'
  | 'TOOL'
  | 'DECISION'
  | 'PROTECTED_ACTION';

export type DependencyNodeState = 'VALID' | 'STALE' | 'INVALIDATED' | 'REVALIDATE_REQUIRED';

export interface DependencyNodeRecord {
  node_id: string;
  tenant_id: string;
  node_type: DependencyNodeType;
  ref_id: string; // e.g. 'order:1099:status' or 'tool:stripe.refund' or 'action:logistics.ship'
  label: string;
  state: DependencyNodeState;
  last_changed_at: string;
  invalidated_by_cascade_id?: string;
  metadata?: Record<string, unknown>;
}

export interface DependencyEdgeRecord {
  edge_id: string;
  tenant_id: string;
  from_node_id: string; // Upstream dependency (e.g. FACT or SOURCE)
  to_node_id: string;   // Downstream dependent (e.g. ENTITY, AGENT_TASK, CONTRACT, TOOL, PROTECTED_ACTION)
  relation: 'PROVIDES_EVIDENCE' | 'FEEDS' | 'GATES' | 'USES_TOOL' | 'AUTHORIZES' | 'TRIGGERS';
  created_at: string;
}

export interface CascadeOutboxEntry {
  outbox_id: string;
  target_node_id: string;
  target_type: DependencyNodeType;
  action: 'MARK_INVALIDATED' | 'MARK_REVALIDATE_REQUIRED' | 'EMIT_NOTICE';
  status: 'COMPLETED' | 'PENDING_RETRY' | 'FAILED';
  error_message?: string;
  attempts: number;
}

export interface InvalidationCascadeRecord {
  cascade_id: string;
  tenant_id: string;
  trigger_node_id: string;
  trigger_reason: string;
  trace_id: string;
  idempotency_key: string;
  max_depth_reached: number;
  direct_dependents: string[];
  indirect_dependents: string[];
  affected_protected_actions: string[];
  outbox_entries: CascadeOutboxEntry[];
  partial_failure: boolean;
  created_at: string;
}

// -------------------------------------------------------------
// Features 9 & 10: Tool Identity Fingerprint & Drift Intelligence
// -------------------------------------------------------------
export type ToolIdentityTrustSource = 'DECLARED' | 'OBSERVED' | 'VERIFIED_PUBLISHER';
export type ToolDriftSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ToolDriftType =
  | 'NEW_TOOL_ADDED'
  | 'TOOL_REMOVED'
  | 'INPUT_SCHEMA_CHANGED'
  | 'OUTPUT_SCHEMA_CHANGED'
  | 'PERMISSIONS_ADDED'
  | 'PERMISSIONS_REMOVED'
  | 'ENDPOINTS_ADDED'
  | 'ENDPOINTS_CHANGED'
  | 'CAPABILITY_CHANGED'
  | 'VERSION_DRIFT'
  | 'PUBLISHER_OR_PROTOCOL_DRIFT';

export interface CanonicalToolDefinition {
  tool_id: string;
  name: string;
  server_id?: string;
  server_name?: string;
  package_identity?: string;
  version: string;
  input_schema: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  declared_permissions: string[];
  declared_endpoints: string[];
  capabilities: string[];
  protocol_metadata?: Record<string, unknown>;
  publisher_info?: {
    publisher_id?: string;
    verified?: boolean;
    source_repo?: string;
  };
  identity_source: ToolIdentityTrustSource;
}

export interface ToolFingerprintVersion {
  version_seq: number;
  version_label: string;
  fingerprint_hash: string;
  canonical_version: 'cck-tool-canon-v1';
  identity_source: ToolIdentityTrustSource;
  definition: CanonicalToolDefinition;
  recorded_at: string;
  recorded_by: string;
  approved: boolean;
  approved_by?: string;
  approved_at?: string;
}

export interface ToolIdentityRecord {
  tool_identity_id: string;
  tenant_id: string;
  tool_id: string;
  name: string;
  server_id?: string;
  current_fingerprint: string;
  current_version: string;
  identity_source: ToolIdentityTrustSource;
  drift_status: 'CLEAN' | 'DRIFT_WARNING' | 'DRIFT_BLOCKED' | 'PENDING_APPROVAL';
  history: ToolFingerprintVersion[];
  created_at: string;
  updated_at: string;
}

export interface ToolDriftFinding {
  drift_id: string;
  tenant_id: string;
  tool_identity_id: string;
  tool_id: string;
  from_fingerprint: string;
  to_fingerprint: string;
  from_version: string;
  to_version: string;
  drift_types: ToolDriftType[];
  severity: ToolDriftSeverity;
  recommended_action: 'ALLOW' | 'REVALIDATE' | 'REQUIRE_APPROVAL' | 'BLOCK';
  explanation: string[];
  affected_scopes: string[];
  detected_at: string;
  resolved: boolean;
  resolved_by?: string;
  resolved_at?: string;
}

// -------------------------------------------------------------
// Feature 11: Permission Graph & Least Privilege
// -------------------------------------------------------------
export type PermissionOriginType = 'DECLARED' | 'CONFIGURED' | 'OBSERVED' | 'GRANTED' | 'EFFECTIVE';

export interface PermissionGrantRecord {
  grant_id: string;
  tenant_id: string;
  org_id: string;
  user_id?: string;
  agent_id: string;
  tool_id: string; // '*' or specific tool_id / capability
  resource_pattern: string; // '*' or e.g. 'order:*'
  action: string; // '*' or 'read' | 'write' | 'execute' | 'refund' | etc.
  scopes: string[];
  origin: 'CONFIGURED' | 'GRANTED'; // DECLARED tool claims NEVER become grants!
  policy_id?: string;
  delegation_id?: string;
  expires_at?: string;
  revoked: boolean;
  revoked_at?: string;
  created_by: string;
  created_at: string;
}

export interface PermissionEvaluationResult {
  allowed: boolean;
  decision: DecisionOutcome;
  tenant_id: string;
  agent_id: string;
  tool_id: string;
  resource: string;
  action: string;
  requested_scopes: string[];
  declared_scopes: string[];
  configured_scopes: string[];
  observed_scopes: string[];
  granted_scopes: string[];
  effective_scopes: string[];
  missing_scopes: string[];
  excess_permissions: Array<{
    grant_id: string;
    tool_id: string;
    resource_pattern: string;
    action: string;
    scopes: string[];
    reason: string;
  }>;
  matched_grant_ids: string[];
  reason: string;
  evaluated_at: string;
}

// -------------------------------------------------------------
// Feature 12: MCP Runtime Enforcement Gateway
// -------------------------------------------------------------
export interface McpUpstreamToolRecord {
  upstream_id: string;
  tenant_id: string;
  server_id: string;
  tool_id: string;
  tool_name: string;
  capability: string;
  transport: 'HTTP_JSONRPC' | 'LOCAL_HANDLER';
  endpoint_url?: string;
  handler_key?: string;
  timeout_ms: number;
  max_retries: number;
  is_idempotent: boolean;
  declared_permissions: string[];
  declared_endpoints: string[];
  status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  created_at: string;
}

export interface McpGatewayInvocationRecord {
  invocation_id: string;
  tenant_id: string;
  trace_id: string;
  agent_id: string;
  user_id?: string;
  tool_id: string;
  tool_name: string;
  capability: string;
  target: string;
  verdict_decision: DecisionOutcome;
  downstream_dispatched: boolean;
  downstream_status: 'NOT_CALLED' | 'SUCCEEDED' | 'TIMEOUT' | 'UPSTREAM_ERROR' | 'CANCELLED';
  latency_ms: number;
  receipt_id?: string;
  audit_id?: string;
  reason: string;
  pipeline_stages: Array<{
    stage: string;
    status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
    detail: string;
  }>;
  created_at: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 5: Multi-Source Conflict Resolver
// -------------------------------------------------------------
export type ConflictResolutionStrategy =
  | 'TRUSTED_SOURCE_PRIORITY'
  | 'OFFICIAL_SOURCE_PRIORITY'
  | 'CONTRACTED_SOURCE_PRIORITY'
  | 'RECENCY'
  | 'EVIDENCE_COMPLETENESS'
  | 'EXPLICIT_SOURCE_RULES'
  | 'MANUAL_RESOLUTION';

export type ConflictResolutionStatus =
  | 'NO_CONFLICT'
  | 'RESOLVED'
  | 'UNRESOLVED'
  | 'INSUFFICIENT_EVIDENCE'
  | 'SOURCE_UNAVAILABLE';

export type SourceAuthorityTier = 'OFFICIAL' | 'CONTRACTED' | 'TRUSTED' | 'THIRD_PARTY' | 'UNVERIFIED';

export interface FactSourceObservation {
  observation_id: string;
  tenant_id: string;
  entity_id: string;
  field_name: string;
  value: unknown;
  source_id: string;
  source_authority: SourceAuthorityTier;
  source_version: string;
  verified_at?: string;
  observed_at: string;
  expiry?: string;
  provenance: Record<string, unknown>;
  evidence_ref?: string;
  data_quality: number;
  source_available: boolean;
  created_at: string;
}

export interface ConflictResolutionPolicy {
  policy_id: string;
  tenant_id: string;
  entity_pattern: string;
  field_pattern: string;
  strategy_order: ConflictResolutionStrategy[];
  trusted_source_order: string[];
  explicit_source_rules?: Array<{
    preferred_source_id: string;
    min_quality?: number;
  }>;
  min_evidence_quality: number;
  allow_mathematical_averaging: false;
  on_unresolved_decision: DecisionOutcome;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface MultiSourceConflictEvaluation {
  evaluation_id: string;
  tenant_id: string;
  entity_id: string;
  field_name: string;
  status: ConflictResolutionStatus;
  recommended_action: DecisionOutcome;
  winning_observation?: FactSourceObservation;
  retained_non_winning: FactSourceObservation[];
  policy_id: string;
  strategy_applied?: ConflictResolutionStrategy;
  explanation: string;
  history_trail: Array<{
    step: string;
    detail: string;
    at: string;
  }>;
  evaluated_at: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 6: Smart Revalidation & Delta Refresh
// -------------------------------------------------------------
export type RefreshMode = 'DELTA' | 'FULL';
export type RevalidationJobStatus =
  | 'PLANNED'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'PARTIAL_FAILURE'
  | 'FAILED_FAIL_CLOSED'
  | 'RATE_LIMITED';

export interface RevalidationPlanRecord {
  plan_id: string;
  tenant_id: string;
  trigger_reason: string;
  mode: RefreshMode;
  target_facts: Array<{
    entity_id: string;
    field_name: string;
    source_id?: string;
    expiration_reason: string;
  }>;
  dependency_node_ids: string[];
  refresh_budget: number;
  max_retries: number;
  timeout_ms: number;
  status: RevalidationJobStatus;
  refreshed_facts: Array<{
    entity_id: string;
    field_name: string;
    updated_fields: string[];
    new_version: number;
  }>;
  failed_facts: Array<{
    entity_id: string;
    field_name: string;
    error: string;
    kept_stale: true;
  }>;
  attempts: number;
  conflict_rechecks: number;
  explanation: string;
  created_at: string;
  completed_at?: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 13: Ephemeral Secret Broker
// -------------------------------------------------------------
export interface RegisteredSecretRecord {
  secret_ref: string;
  tenant_id: string;
  principal_id: string;
  provider: string;
  allowed_tools: string[];
  allowed_scopes: string[];
  allowed_resources: string[];
  encrypted_envelope: {
    ciphertext_b64: string;
    iv_b64: string;
    auth_tag_b64: string;
    alg: 'aes-256-gcm';
  };
  fingerprint_prefix: string;
  version: number;
  revoked: boolean;
  revoked_at?: string;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface EphemeralSecretLease {
  lease_id: string;
  secret_ref: string;
  tenant_id: string;
  principal_id: string;
  agent_id: string;
  tool_id: string;
  session_id: string;
  invocation_id?: string;
  requested_scope: string;
  resource_scope: string;
  purpose: string;
  issued_at: string;
  expires_at: string;
  revoked: boolean;
  revoked_at?: string;
  revoke_reason?: string;
  used_count: number;
}

export interface SecretAccessAuditRecord {
  access_id: string;
  tenant_id: string;
  secret_ref: string;
  lease_id?: string;
  principal_id: string;
  agent_id: string;
  tool_id: string;
  session_id: string;
  purpose: string;
  outcome:
    | 'GRANTED'
    | 'DENIED_MISSING'
    | 'DENIED_EXPIRED'
    | 'DENIED_REVOKED'
    | 'DENIED_SCOPE'
    | 'DENIED_TENANT'
    | 'LEASE_REVOKED'
    | 'ROTATED';
  reason: string;
  timestamp: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 14: Per-Call Isolation
// -------------------------------------------------------------
export interface InvocationContextSnapshot {
  invocation_id: string;
  tenant_id: string;
  agent_id: string;
  tool_id: string;
  trace_id: string;
  permission_context: {
    effective_scopes: string[];
    matched_grants: string[];
  };
  data_classification_context: {
    classifications: string[];
    max_tier: DataSensitivityTier;
  };
  secret_lease_ids: string[];
  timeout_ms: number;
  max_payload_bytes: number;
  status: 'ACTIVE' | 'COMPLETED_CLEANED' | 'FAILED_CLEANED' | 'TIMED_OUT_CLEANED';
  cleaned_at?: string;
  leases_revoked_count: number;
  isolation_boundary_note: string;
  created_at: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 15: Data Flow & Leakage Guard
// -------------------------------------------------------------
export type DataSensitivityTier = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface DataClassificationRule {
  rule_id: string;
  tenant_id: string;
  label: string;
  tier: DataSensitivityTier;
  field_paths: string[];
  value_categories: Array<'PII' | 'PHI' | 'PCI' | 'CREDENTIAL' | 'TOKEN' | 'CUSTOM'>;
  description: string;
  created_at: string;
}

export interface DataFlowPolicyRecord {
  flow_policy_id: string;
  tenant_id: string;
  name: string;
  source_scope: string;
  allowed_destinations: string[];
  blocked_destinations: string[];
  max_allowed_tier: DataSensitivityTier;
  redaction_mode: 'MASK' | 'DROP' | 'HASH' | 'BLOCK';
  block_unclassified_sensitive: boolean;
  is_active: boolean;
  created_at: string;
}

export interface DataFlowEvaluationResult {
  evaluation_id: string;
  tenant_id: string;
  destination: string;
  decision: 'ALLOW' | 'ALLOW_REDACTED' | 'BLOCK';
  highest_tier: DataSensitivityTier;
  detected_labels: string[];
  detected_fields: Array<{
    path: string;
    label: string;
    tier: DataSensitivityTier;
    category: string;
    action: 'KEPT' | 'REDACTED' | 'DROPPED' | 'BLOCKED';
  }>;
  sanitized_payload: Record<string, unknown>;
  reason: string;
  evaluated_at: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 16: Network Egress Control
// -------------------------------------------------------------
export interface NetworkEgressPolicyRecord {
  egress_policy_id: string;
  tenant_id: string;
  tool_id: string;
  agent_id: string;
  policy_version: number;
  hostname_allowlist: string[];
  domain_rules: {
    allowed_domains: string[];
    denied_domains: string[];
  };
  port_rules: {
    allowed_ports: number[];
    denied_ports: number[];
  };
  protocol_rules: Array<'https' | 'http'>;
  ip_rules: {
    block_private_ips: boolean;
    block_loopback: boolean;
    block_link_local: boolean;
    block_metadata: boolean;
    allowed_ips?: string[];
    allow_loopback_for_test?: boolean;
  };
  redirect_policy: 'BLOCK' | 'VALIDATE_HOPS';
  max_redirects: number;
  method_policy: string[];
  destination_risk_policy: {
    require_tls_in_prod: boolean;
    max_risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
  };
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface EgressDecisionReceipt {
  egress_receipt_id: string;
  tenant_id: string;
  tool_id: string;
  agent_id: string;
  destination_url: string;
  hostname: string;
  resolved_ips: string[];
  port: number;
  protocol: string;
  method: string;
  redirect_hops: string[];
  decision: 'ALLOW' | 'BLOCK';
  policy_id?: string;
  policy_version?: number;
  reason: string;
  evaluated_at: string;
}

// -------------------------------------------------------------
// Batch 2 — Feature 17: Runtime Behavior Baseline & Safe Replay
// -------------------------------------------------------------
export interface ToolBehaviorBaselineRecord {
  baseline_id: string;
  tenant_id: string;
  tool_id: string;
  tool_version: string;
  declared_summary: {
    permissions: string[];
    endpoints: string[];
    capabilities: string[];
  };
  expected_summary: {
    max_calls_per_minute: number;
    max_error_rate: number;
    allowed_data_tiers: DataSensitivityTier[];
  };
  observed_stats: {
    total_calls: number;
    error_count: number;
    error_rate: number;
    observed_permissions: string[];
    observed_destinations: string[];
    observed_data_categories: string[];
    recent_timestamps: number[];
    last_call_at?: string;
  };
  deviation_status: 'NORMAL' | 'DEVIATION_WARNING' | 'POLICY_VIOLATION';
  updated_at: string;
}

export interface BehaviorDriftEventRecord {
  event_id: string;
  tenant_id: string;
  tool_id: string;
  tool_version: string;
  baseline_id: string;
  category:
    | 'DECLARED_VS_OBSERVED'
    | 'UNEXPECTED_PERMISSION'
    | 'UNEXPECTED_DESTINATION'
    | 'DATA_CATEGORY_ESCALATION'
    | 'ERROR_SPIKE'
    | 'FREQUENCY_ANOMALY';
  severity: ToolDriftSeverity;
  detail: string;
  policy_review_triggered: boolean;
  detected_at: string;
}

export interface SafeReplayPackRecord {
  replay_pack_id: string;
  tenant_id: string;
  incident_id?: string;
  name: string;
  version: string;
  tool_id: string;
  agent_id: string;
  mode: 'DRY_RUN' | 'MOCK_ADAPTER' | 'SANDBOX_SIMULATION';
  sanitized_actions: Array<{
    step_id: string;
    capability: string;
    target: string;
    sanitized_parameters: Record<string, unknown>;
    expected_decision: DecisionOutcome;
  }>;
  side_effect_guard: {
    external_network_blocked: true;
    financial_mutations_blocked: true;
    code_exec_blocked: true;
  };
  created_at: string;
  last_run?: {
    run_id: string;
    run_at: string;
    status: 'PASSED' | 'REGRESSION_DETECTED' | 'BLOCKED_UNSAFE_REPLAY';
    step_results: Array<{
      step_id: string;
      actual_decision: DecisionOutcome;
      expected_decision: DecisionOutcome;
      matched: boolean;
      reason: string;
    }>;
    summary: string;
  };
}

// -------------------------------------------------------------
// Batch 3 — Feature 7: Public Source Health Profile
// -------------------------------------------------------------
export interface SourceMetricMethodology {
  value: number | null;
  display: string;
  unit: string;
  calculation_method: string;
  sample_size: number;
  measurement_window: {
    from: string;
    to: string;
    duration_seconds: number;
  };
  last_updated_at: string;
  scope_included: string;
  scope_excluded: string;
}

export interface SourceDowntimeEvent {
  event_id: string;
  started_at: string;
  recovered_at?: string;
  duration_seconds: number;
  error_summary: string;
}

export interface SourceHealthProfileRecord {
  profile_id: string;
  tenant_id: string;
  source_id: string;
  source_name: string;
  source_identity: string;
  connector_version: string;
  is_public: boolean;
  public_consent_granted: boolean;
  public_consent_by?: string;
  public_consent_at?: string;
  sufficiency_status: 'SUFFICIENT_DATA' | 'INSUFFICIENT_DATA';
  min_sample_threshold: number;
  sample_size: number;
  measurement_window: {
    from: string;
    to: string;
    duration_seconds: number;
  };
  last_successful_verification?: string;
  last_failed_verification?: string;
  failure_count: number;
  downtime_events: SourceDowntimeEvent[];
  data_coverage: {
    entities_covered: number;
    fields_covered: number;
    events_applied: number;
    events_failed: number;
  };
  metrics: {
    median_freshness: SourceMetricMethodology;
    p95_freshness: SourceMetricMethodology;
    observed_update_interval: SourceMetricMethodology;
    verification_success_rate: SourceMetricMethodology;
    error_rate: SourceMetricMethodology;
  };
  known_limitations: string[];
  last_profile_update: string;
  created_at: string;
}

export type PublicSourceHealthProfileView = Omit<
  SourceHealthProfileRecord,
  'tenant_id' | 'public_consent_by'
> & {
  visibility: 'PUBLIC';
};

// -------------------------------------------------------------
// Batch 3 — Feature 8: Connector SDK & Test Harness
// -------------------------------------------------------------
export type ConnectorDeclaredCapability =
  | 'READ'
  | 'WRITE'
  | 'CONDITIONAL_WRITE'
  | 'IDEMPOTENCY'
  | 'COMPENSATION'
  | 'SUBSCRIBE_CHANGES'
  | 'CURSOR_PAGINATION'
  | 'RATE_LIMIT_BACKOFF'
  | 'HEALTH_CHECK'
  | 'VERIFY_SOURCE';

export interface ConnectorManifest {
  connector_id: string;
  name: string;
  version: string;
  publisher: string;
  supported_source_types: ChangeSourceType[];
  required_permissions: string[];
  required_secrets_refs: string[];
  declared_capabilities: ConnectorDeclaredCapability[];
  network_requirements: {
    allowed_hosts: string[];
    protocols: Array<'https' | 'http'>;
    requires_tls: boolean;
  };
  compatibility_range: {
    min_cck_version: string;
    max_cck_version: string;
  };
  digest_sha256?: string;
  signature?: {
    signer_id: string;
    algorithm: string;
    signature_b64: string;
  };
}

export type ConnectorHarnessTestName =
  | 'SCHEMA_VALIDATION'
  | 'IDENTITY_VALIDATION'
  | 'AUTHENTICATION_FAILURE'
  | 'EXPIRY_HANDLING'
  | 'DUPLICATE_EVENT'
  | 'OUT_OF_ORDER_EVENT'
  | 'RATE_LIMIT_HANDLING'
  | 'ERROR_HANDLING'
  | 'DATA_NORMALIZATION'
  | 'TENANT_ISOLATION'
  | 'REDACTION_SAFETY'
  | 'VERSION_COMPATIBILITY';

export interface ConnectorHarnessCaseResult {
  test_name: ConnectorHarnessTestName;
  passed: boolean;
  detail: string;
  duration_ms: number;
}

export interface ConnectorHarnessReport {
  report_id: string;
  connector_id: string;
  connector_version: string;
  tenant_id: string;
  passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  declared_capabilities: ConnectorDeclaredCapability[];
  verified_capabilities: ConnectorDeclaredCapability[];
  unverified_capabilities: ConnectorDeclaredCapability[];
  test_results: ConnectorHarnessCaseResult[];
  credentials_leaked: boolean;
  manifest_digest_sha256: string;
  executed_at: string;
}

export interface ConnectorPackageSubmission {
  submission_id: string;
  tenant_id: string;
  manifest: ConnectorManifest;
  verified_capabilities: ConnectorDeclaredCapability[];
  harness_report_id: string;
  harness_passed: boolean;
  review_status: 'PENDING_REVIEW' | 'APPROVED_FOR_SANDBOX' | 'VERIFIED' | 'REJECTED';
  isolation_policy: {
    arbitrary_code_execution_blocked: true;
    sandbox_mode: 'DECLARATIVE_MANIFEST_AND_HARNESS';
  };
  submitted_by: string;
  submitted_at: string;
  updated_at: string;
}

// -------------------------------------------------------------
// Batch 3 — Feature 18: One-Command CCK Scanner
// -------------------------------------------------------------
export type ScanSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ScanMode = 'LOCAL' | 'AUTHENTICATED' | 'UPLOAD_SANITIZED';

export interface ScannerFinding {
  finding_id: string;
  rule_id: string;
  severity: ScanSeverity;
  certainty: 'CONFIRMED' | 'POTENTIAL';
  file: string;
  location?: string;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  confidence: number;
  limitation: string;
  scanner_version: string;
}

export interface ScanReport {
  scan_id: string;
  scanner_version: string;
  mode: ScanMode;
  target_path: string;
  scanned_at: string;
  static_analysis_only: true;
  uploaded_to_cloud: boolean;
  files_discovered: number;
  files_scanned: string[];
  files_skipped_privacy: string[];
  unscanned_summary: string[];
  tool_fingerprints: Array<{
    tool_id: string;
    name: string;
    version: string;
    fingerprint_sha256: string;
    file: string;
    declared_permissions: string[];
    declared_endpoints: string[];
  }>;
  findings: ScannerFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    recommended_exit_code: number;
    status_statement: string;
  };
  scope_and_limitations: string[];
  report_digest_sha256: string;
}

// -------------------------------------------------------------
// Batch 3 — Feature 19: CCK GitHub PR Guardian
// -------------------------------------------------------------
export type PrGuardianVerdict =
  | 'PASS'
  | 'WARNING'
  | 'BLOCKING_FINDING'
  | 'NEEDS_HUMAN_REVIEW'
  | 'INSUFFICIENT_COVERAGE';

export interface PrGuardianEvaluationReport {
  report_ref: string;
  tenant_id?: string;
  repository: string;
  pr_number?: number;
  base_sha: string;
  head_sha: string;
  verdict: PrGuardianVerdict;
  merge_blocked: boolean;
  fail_on_severity: 'CRITICAL' | 'HIGH';
  policy_version: string;
  scanner_version: string;
  changed_files: string[];
  analyzed_tool_files: string[];
  tool_fingerprint_changes: Array<{
    tool_id: string;
    from_fingerprint?: string;
    to_fingerprint?: string;
    from_version?: string;
    to_version?: string;
    drift_severity?: ToolDriftSeverity;
    drift_types?: ToolDriftType[];
  }>;
  changed_permissions: {
    added: string[];
    removed: string[];
  };
  changed_endpoints: {
    added: string[];
    removed: string[];
  };
  schema_changes: string[];
  replay_checks: Array<{
    pack_name: string;
    status: string;
    detail: string;
  }>;
  findings: ScannerFinding[];
  coverage: {
    percentage: number;
    covered_areas: string[];
    uncovered_reasons: string[];
  };
  github_annotations: Array<{
    level: 'notice' | 'warning' | 'error';
    file: string;
    title: string;
    message: string;
  }>;
  markdown_summary: string;
  executed_at: string;
  report_digest_sha256: string;
}

// -------------------------------------------------------------
// Batch 3 — Feature 20: CCK Trust Profile & Public Registry
// -------------------------------------------------------------
export type TrustProfileStatus =
  | 'SUBMITTED'
  | 'VERIFIED_FOR_A_DEFINED_SCOPE'
  | 'REVIEW_REQUIRED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'SUPERSEDED';

export type PublisherVerificationState = 'UNVERIFIED_CLAIM' | 'VERIFIED_PUBLISHER';

export interface TrustProfileSignature {
  signer_id: string;
  algorithm: 'Ed25519';
  public_key_pem: string;
  signed_payload_fields: string[];
  signature_b64: string;
}

export interface TrustProfileRecord {
  profile_id: string;
  owner_tenant_id: string; // Strictly stripped on public endpoints
  visibility: 'PUBLIC' | 'PRIVATE';
  artifact_identity: string;
  artifact_type: 'MCP_TOOL' | 'CONNECTOR' | 'AGENT_PACK';
  name: string;
  publisher_name: string;
  claimed_identity: string;
  publisher_verification: PublisherVerificationState;
  publisher_proof_fingerprint?: string;
  version: string;
  fingerprint: string;
  commit_sha?: string;
  connector_version?: string;
  test_suite_version: string;
  policy_version: string;
  scanner_version: string;
  source_health_ref?: string;
  scope_of_assessment: {
    tested_capabilities: string[];
    included_checks: string[];
    excluded_or_not_tested: string[];
  };
  assessment_statement: string;
  findings: Array<{
    rule_id: string;
    severity: ScanSeverity;
    certainty: 'CONFIRMED' | 'POTENTIAL';
    title: string;
  }>;
  passed_checks: string[];
  failed_checks: string[];
  unsupported_checks: string[];
  status: TrustProfileStatus;
  tested_at: string;
  expires_at: string;
  revoked_at?: string;
  revoke_reason?: string;
  superseded_by_profile_id?: string;
  report_digest_sha256: string;
  signature: TrustProfileSignature;
  created_at: string;
  updated_at: string;
}

export type PublicTrustProfileView = Omit<TrustProfileRecord, 'owner_tenant_id' | 'publisher_proof_fingerprint'>;

export interface PublisherOwnershipClaim {
  claim_id: string;
  artifact_identity: string;
  owner_tenant_id: string;
  publisher_name: string;
  claimed_identity: string;
  verified: boolean;
  verification_method: 'HMAC_CHALLENGE' | 'SELF_CLAIMED';
  created_at: string;
}

// -------------------------------------------------------------
// Batch 3 — Privacy-Respecting Adoption Analytics
// -------------------------------------------------------------
export interface AdoptionAnalyticsRecord {
  analytics_enabled: boolean;
  cli_scans: number;
  local_to_integration_conversions: number;
  github_guardian_installations: number;
  active_projects_count: number;
  published_reports: number;
  report_shares: number;
  new_devs_from_shared_reports: number;
  connector_submissions: number;
  verified_connector_versions: number;
  repeated_usage_events: number;
  last_event_at?: string;
}

