/**
 * CCK Official TypeScript Client
 */

import {
  AgentAction,
  ExecutionVerdict,
  DecisionReceipt,
  HeartbeatResult,
  CCKClientOptions,
} from './types.js';
import { CCKConnectionError, CCKError } from './errors.js';

export class CCKClient {
  private baseUrl: string;
  private apiKey?: string;
  private sessionToken?: string;
  private timeoutMs: number;
  private maxRetries: number;

  constructor(options: CCKClientOptions = {}) {
    this.baseUrl = (options.baseUrl || process.env.CCK_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
    this.apiKey = options.apiKey || process.env.CCK_API_KEY;
    this.sessionToken = options.sessionToken || process.env.CCK_SESSION_TOKEN;
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.maxRetries = options.maxRetries ?? 2;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers as Record<string, string>),
    };

    const bearer = this.apiKey || this.sessionToken;
    if (bearer) {
      headers['Authorization'] = `Bearer ${bearer}`;
      if (this.apiKey && this.apiKey.startsWith('cck_live_')) {
        headers['x-api-key'] = this.apiKey;
      }
    }

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(url, {
          ...options,
          headers,
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (!res.ok) {
          const body = await res.text();
          let detail = body;
          try {
            const parsed = JSON.parse(body);
            detail = parsed.detail || parsed.error || body;
          } catch {
            // Keep raw body
          }
          throw new CCKError(`CCK API Error [HTTP ${res.status}]: ${detail}`);
        }

        return (await res.json()) as T;
      } catch (err: unknown) {
        clearTimeout(timer);
        const error = err instanceof Error ? err : new Error(String(err));
        lastError = error;

        // If client error (4xx) or max retries exhausted, don't retry
        if (error.name === 'CCKError' || attempt === this.maxRetries) {
          break;
        }

        // Brief exponential backoff
        await new Promise((r) => setTimeout(r, Math.min(1000, 100 * Math.pow(2, attempt))));
      }
    }

    throw new CCKConnectionError(
      `Failed to connect to CCK Control Plane at ${url}: ${lastError?.message || 'Connection timeout or network failure'}`
    );
  }

  /**
   * Check Control Plane health
   */
  async health(): Promise<{ status: string; engine_version: string }> {
    return this.request<{ status: string; engine_version: string }>('/health');
  }

  /**
   * Send heartbeat to verify agent connection and update last_seen_at
   */
  async heartbeat(agentId: string): Promise<HeartbeatResult> {
    return this.request<HeartbeatResult>(`/api/v1/agents/${encodeURIComponent(agentId)}/heartbeat`, {
      method: 'POST',
    });
  }

  /**
   * Evaluate an agent action against CCK Action Gate
   */
  async evaluateAction(action: AgentAction): Promise<ExecutionVerdict> {
    return this.request<ExecutionVerdict>('/api/v1/actions/evaluate', {
      method: 'POST',
      body: JSON.stringify(action),
    });
  }

  /**
   * Record new evidence / observation to update facts
   */
  async recordEvidence(params: {
    entity_id: string;
    field_name: string;
    value: unknown;
    source?: string;
    payload?: unknown;
    idempotency_key?: string;
    trace_id?: string;
  }): Promise<{ status: string; evidence_id: string }> {
    return this.request<{ status: string; evidence_id: string }>('/api/v1/webhooks/ingest', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  /**
   * Evaluate adaptive freshness of a fact
   */
  async evaluateFreshness(params: { entity_id: string; field_name: string }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/v1/freshness/evaluate', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  /**
   * Evaluate permission graph & least privilege
   */
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

  /**
   * Invoke a downstream MCP tool through CCK Runtime Enforcement Gateway
   */
  async mcpGatewayCall(params: {
    agent_id: string;
    tool_name: string;
    target: string;
    entity_id?: string;
    required_fact_field?: string;
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

  /**
   * Retrieve immutable decision receipt by ID (or signed share token)
   */
  async getReceipt(receiptId: string, shareToken?: string): Promise<DecisionReceipt> {
    const qs = shareToken ? `?share=true&share_token=${encodeURIComponent(shareToken)}` : '';
    return this.request<DecisionReceipt>(`/api/v1/receipts/${encodeURIComponent(receiptId)}${qs}`);
  }
}
