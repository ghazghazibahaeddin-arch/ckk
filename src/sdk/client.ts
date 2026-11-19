/**
 * CCK TypeScript SDK (Layer 6).
 *
 * Official client library for integrating TypeScript/JavaScript AI agents
 * and applications with the CCK Control Plane REST API.
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

export class CCKClient {
  private baseUrl: string;
  private apiKey?: string;
  private sessionToken?: string;
  private tenantId?: string;

  constructor(options: { baseUrl?: string; apiKey?: string; sessionToken?: string; tenantId?: string } = {}) {
    this.baseUrl = options.baseUrl || '';
    this.apiKey = options.apiKey;
    this.sessionToken = options.sessionToken;
    this.tenantId = options.tenantId;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    const bearer = this.apiKey || this.sessionToken;
    if (bearer) {
      headers['Authorization'] = `Bearer ${bearer}`;
    }
    if (this.apiKey && this.apiKey.startsWith('cck_live_')) {
      headers['x-api-key'] = this.apiKey;
    }

    const res = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CCK API Error [${res.status}]: ${errText}`);
    }

    return res.json() as Promise<T>;
  }

  async health(): Promise<{ status: string; version: string }> {
    return this.request<{ status: string; version: string }>('/health');
  }

  async evaluateAction(action: AgentAction): Promise<ExecutionVerdict> {
    return this.request<ExecutionVerdict>('/api/v1/actions/evaluate', {
      method: 'POST',
      body: JSON.stringify(action),
    });
  }

  async evaluateFreshness(params: { entity_id: string; field_name: string }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/freshness/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async ingestRadarEvent(params: {
    entity_id: string;
    field_name: string;
    value: unknown;
    source?: string;
    idempotency_key?: string;
    trace_id?: string;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/webhooks/ingest', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async evaluatePermissions(params: {
    agent_id: string;
    tool_id: string;
    resource?: string;
    action?: string;
    requested_scopes?: string[];
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/permissions/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async mcpGatewayCall(params: {
    agent_id: string;
    tool_name: string;
    target: string;
    entity_id?: string;
    required_fact_field?: string;
    requested_scopes?: string[];
    delegation_id?: string;
    secret_ref?: string;
    secret_scope?: string;
    session_id?: string;
    arguments?: Record<string, unknown>;
    trace_id?: string;
    idempotency_key?: string;
    allow_loopback_upstream?: boolean;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/mcp/gateway/invoke', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async evaluateMultiSourceConflict(params: {
    entity_id: string;
    field_name: string;
    manual_winner_observation_id?: string;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/conflicts/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async runSmartRevalidation(params: {
    mode?: 'DELTA' | 'FULL';
    entity_id?: string;
    field_name?: string;
    source_id?: string;
    refresh_budget?: number;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/revalidation/plan-and-run', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async leaseEphemeralSecret(params: {
    secret_ref: string;
    agent_id: string;
    tool_id: string;
    requested_scope: string;
    resource_scope?: string;
    purpose?: string;
    ttl_seconds?: number;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/secrets/lease', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async evaluateDataFlow(params: {
    destination: string;
    payload: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/data-flow/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async evaluateEgress(params: {
    tool_id?: string;
    agent_id?: string;
    url: string;
    method?: string;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/egress/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async runSafeReplayPack(packId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/api/v1/replay-packs/safe/${encodeURIComponent(packId)}/run`, {
      method: 'POST',
    });
  }

  async computeSourceHealth(sourceId: string, params?: { is_public?: boolean; min_sample_threshold?: number }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/api/v1/sources/${encodeURIComponent(sourceId)}/health/compute`, {
      method: 'POST',
      body: JSON.stringify(params || {}),
    });
  }

  async runConnectorHarness(manifest: Record<string, unknown>, sampleItems?: unknown[]): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/connectors/harness/run', {
      method: 'POST',
      body: JSON.stringify({ manifest, sample_items: sampleItems }),
    });
  }

  async evaluatePrGuardian(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/pr-guardian/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async createTrustProfile(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/trust/profiles', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  async searchTrustRegistry(query?: string): Promise<Array<Record<string, unknown>>> {
    const qs = query ? `?q=${encodeURIComponent(query)}` : '';
    return this.request<Array<Record<string, unknown>>>(`/api/v1/trust/registry${qs}`);
  }

  async verifyPublicTrustProfile(profileId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/api/v1/public/trust/profiles/${encodeURIComponent(profileId)}`);
  }

  async listPolicies(activeOnly: boolean = true): Promise<unknown[]> {
    return this.request<unknown[]>(`/api/v1/policies?active_only=${activeOnly}`);
  }

  async listAudits(limit: number = 50, offset: number = 0): Promise<unknown[]> {
    return this.request<unknown[]>(`/api/v1/audits?limit=${limit}&offset=${offset}`);
  }
}
