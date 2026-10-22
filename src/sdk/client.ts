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
}

export class CCKClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(options: { baseUrl?: string; apiKey?: string } = {}) {
    this.baseUrl = options.baseUrl || '';
    this.apiKey = options.apiKey;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
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

  async listPolicies(activeOnly: boolean = true): Promise<unknown[]> {
    return this.request<unknown[]>(`/api/v1/policies?active_only=${activeOnly}`);
  }

  async listAudits(limit: number = 50, offset: number = 0): Promise<unknown[]> {
    return this.request<unknown[]>(`/api/v1/audits?limit=${limit}&offset=${offset}`);
  }
}
