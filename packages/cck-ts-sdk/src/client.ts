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
  private timeoutMs: number;
  private maxRetries: number;

  constructor(options: CCKClientOptions = {}) {
    this.baseUrl = (options.baseUrl || process.env.CCK_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
    this.apiKey = options.apiKey || process.env.CCK_API_KEY;
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

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
      headers['x-api-key'] = this.apiKey;
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
  }): Promise<{ status: string; evidence_id: string }> {
    return this.request<{ status: string; evidence_id: string }>('/api/v1/webhooks/ingest', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  /**
   * Retrieve immutable decision receipt by ID
   */
  async getReceipt(receiptId: string): Promise<DecisionReceipt> {
    return this.request<DecisionReceipt>(`/api/v1/receipts/${encodeURIComponent(receiptId)}`);
  }
}
