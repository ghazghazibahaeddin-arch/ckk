import React, { useEffect, useState } from 'react';
import {
  Fingerprint,
  ShieldAlert,
  Network,
  Terminal,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Plus,
  Play,
  Lock,
} from 'lucide-react';
import type {
  ToolIdentityRecord,
  ToolDriftFinding,
  PermissionGrantRecord,
  PermissionEvaluationResult,
  McpUpstreamToolRecord,
  McpGatewayInvocationRecord,
} from '../../intelligence/types';

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  agents: Array<{ agent_id: string; name: string }>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const ToolMcpRuntimeView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  agents,
  onNotification,
}) => {
  const fetcher = apiFetch || fetch;
  const effTenant = tenantId || 'tenant_default';

  const [subTab, setSubTab] = useState<'tools' | 'permissions' | 'gateway'>('gateway');

  // Features 9 & 10: Tool Identity & Drift State
  const [identities, setIdentities] = useState<ToolIdentityRecord[]>([]);
  const [drifts, setDrifts] = useState<ToolDriftFinding[]>([]);
  const [toolId, setToolId] = useState('stripe.refund');
  const [toolName, setToolName] = useState('Stripe Refund Tool');
  const [toolVersion, setToolVersion] = useState('1.0.0');
  const [toolPerms, setToolPerms] = useState('refund:write, orders:read');
  const [toolEndpoints, setToolEndpoints] = useState('https://api.stripe.com/v1/refunds');

  // Feature 11: Permission Graph State
  const [grants, setGrants] = useState<PermissionGrantRecord[]>([]);
  const [graphSummary, setGraphSummary] = useState<Record<string, any> | null>(null);
  const [grantAgentId, setGrantAgentId] = useState(agents[0]?.agent_id || 'agt-console');
  const [grantToolId, setGrantToolId] = useState('stripe.refund');
  const [grantResource, setGrantResource] = useState('order:*');
  const [grantAction, setGrantAction] = useState('execute');
  const [grantScopes, setGrantScopes] = useState('orders:read, refund:write');
  const [permEvalResult, setPermEvalResult] = useState<PermissionEvaluationResult | null>(null);

  // Feature 12: MCP Runtime Gateway State
  const [upstreams, setUpstreams] = useState<McpUpstreamToolRecord[]>([]);
  const [invocations, setInvocations] = useState<McpGatewayInvocationRecord[]>([]);
  const [upToolName, setUpToolName] = useState('stripe_refund_exec');
  const [upCapability, setUpCapability] = useState('payments.refund');
  const [upTransport, setUpTransport] = useState<'LOCAL_HANDLER' | 'HTTP_JSONRPC'>('LOCAL_HANDLER');
  const [upEndpoint, setUpEndpoint] = useState('');

  const [invokeAgentId, setInvokeAgentId] = useState(agents[0]?.agent_id || 'agt-console');
  const [invokeToolName, setInvokeToolName] = useState('stripe_refund_exec');
  const [invokeTarget, setInvokeTarget] = useState('order:1099');
  const [invokeArgs, setInvokeArgs] = useState(JSON.stringify({ amount_cents: 4500, reason: 'requested_by_customer' }));
  const [lastInvokeResult, setLastInvokeResult] = useState<Record<string, any> | null>(null);

  const cardCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-xs';
  const subCls = isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';
  const mutedCls = isDark ? 'text-slate-400' : 'text-slate-600';

  const loadAll = async () => {
    try {
      const q = `?tenant_id=${encodeURIComponent(effTenant)}`;
      const [idRes, driftRes, grRes, graphRes, upRes, invRes] = await Promise.all([
        fetcher(`/api/v1/tools/identities${q}`),
        fetcher(`/api/v1/tools/drifts${q}`),
        fetcher(`/api/v1/permissions/grants${q}`),
        fetcher(`/api/v1/permissions/graph${q}`),
        fetcher(`/api/v1/mcp/gateway/upstreams${q}`),
        fetcher(`/api/v1/mcp/gateway/invocations${q}`),
      ]);
      if (idRes.ok) setIdentities(await idRes.json());
      if (driftRes.ok) setDrifts(await driftRes.json());
      if (grRes.ok) setGrants(await grRes.json());
      if (graphRes.ok) setGraphSummary(await graphRes.json());
      if (upRes.ok) setUpstreams(await upRes.json());
      if (invRes.ok) setInvocations(await invRes.json());
    } catch {
      // ignore transient network errors
    }
  };

  useEffect(() => {
    loadAll();
  }, [effTenant]);

  const handleRegisterTool = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/tools/identities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          tool_id: toolId,
          name: toolName,
          version: toolVersion,
          declared_permissions: toolPerms.split(',').map((s) => s.trim()).filter(Boolean),
          declared_endpoints: toolEndpoints.split(',').map((s) => s.trim()).filter(Boolean),
          capabilities: [upCapability],
          input_schema: { type: 'object', properties: { amount_cents: { type: 'number' } }, required: ['amount_cents'] },
          identity_source: 'OBSERVED',
        }),
      });
      const data = await res.json();
      if (res.ok) {
        if (data.drift) {
          onNotification(`Tool drift detected (${data.drift.severity} -> ${data.drift.recommended_action})!`, 'error');
        } else {
          onNotification('Tool canonical SHA-256 fingerprint verified & stored.', 'success');
        }
        loadAll();
      } else {
        onNotification(data.error || 'Failed to register tool identity.', 'error');
      }
    } catch {
      onNotification('Error registering tool identity.', 'error');
    }
  };

  const handleApproveIdentity = async (id: string) => {
    try {
      const res = await fetcher(`/api/v1/tools/identities/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({ reviewer: 'console-supervisor' }),
      });
      if (res.ok) {
        onNotification('Tool snapshot approved and drift findings resolved.', 'success');
        loadAll();
      } else {
        const err = await res.json();
        onNotification(err.error || 'Approval failed.', 'error');
      }
    } catch {
      onNotification('Error approving tool identity.', 'error');
    }
  };

  const handleCreateGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/permissions/grants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          agent_id: grantAgentId,
          tool_id: grantToolId,
          resource_pattern: grantResource,
          action: grantAction,
          scopes: grantScopes.split(',').map((s) => s.trim()).filter(Boolean),
          origin: 'GRANTED',
        }),
      });
      if (res.ok) {
        onNotification('Explicit least-privilege grant issued.', 'success');
        loadAll();
      } else {
        const err = await res.json();
        onNotification(err.error || 'Failed to create permission grant.', 'error');
      }
    } catch {
      onNotification('Error creating grant.', 'error');
    }
  };

  const handleRevokeGrant = async (grantId: string) => {
    try {
      const res = await fetcher(`/api/v1/permissions/grants/${grantId}/revoke`, {
        method: 'POST',
        headers: { 'x-tenant-id': effTenant },
      });
      if (res.ok) {
        onNotification('Permission grant revoked immediately.', 'info');
        loadAll();
      }
    } catch {
      onNotification('Error revoking grant.', 'error');
    }
  };

  const handleEvaluatePermissions = async () => {
    try {
      const res = await fetcher('/api/v1/permissions/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          agent_id: grantAgentId,
          tool_id: grantToolId,
          resource: grantResource === '*' ? 'order:1099' : grantResource,
          action: grantAction,
          requested_scopes: grantScopes.split(',').map((s) => s.trim()).filter(Boolean),
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setPermEvalResult(data);
        onNotification(`Permission Graph verdict: ${data.allowed ? 'ALLOWED' : 'BLOCKED'}`, data.allowed ? 'success' : 'error');
      }
    } catch {
      onNotification('Error evaluating permission graph.', 'error');
    }
  };

  const handleRegisterUpstream = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/mcp/gateway/upstreams', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          tool_id: toolId,
          tool_name: upToolName,
          capability: upCapability,
          transport: upTransport,
          endpoint_url: upTransport === 'HTTP_JSONRPC' ? upEndpoint : undefined,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification(`Upstream MCP tool "${data.tool_name}" registered on Gateway.`, 'success');
        loadAll();
      } else {
        onNotification(data.error || 'Upstream registration rejected.', 'error');
      }
    } catch {
      onNotification('Error registering MCP upstream.', 'error');
    }
  };

  const handleToggleUpstream = async (up: McpUpstreamToolRecord) => {
    const next = up.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
    try {
      const res = await fetcher(`/api/v1/mcp/gateway/upstreams/${up.upstream_id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({ status: next }),
      });
      if (res.ok) {
        onNotification(`Upstream tool set to ${next}.`, 'info');
        loadAll();
      }
    } catch {
      onNotification('Error updating upstream status.', 'error');
    }
  };

  const handleInvokeGateway = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const parsedArgs = JSON.parse(invokeArgs || '{}');
      const res = await fetcher('/api/v1/mcp/gateway/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          agent_id: invokeAgentId,
          tool_name: invokeToolName,
          target: invokeTarget,
          arguments: parsedArgs,
        }),
      });
      const data = await res.json();
      setLastInvokeResult(data);
      onNotification(
        data.allowed
          ? 'Gateway ALLOW: Downstream tool dispatched with verified receipt.'
          : `Gateway ${data.decision}: Downstream physically NOT called.`,
        data.allowed ? 'success' : 'error'
      );
      loadAll();
    } catch {
      onNotification('Invalid JSON arguments or gateway invocation failure.', 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className={`rounded-2xl border p-6 ${cardCls}`}>
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <Terminal className="w-4 h-4" />
              <span>Tool Intelligence & Runtime Enforcement</span>
            </div>
            <h2 className="text-xl font-bold">Tool Fingerprints, Least-Privilege Graph & MCP Runtime Gateway</h2>
            <p className={`text-sm mt-1 ${mutedCls}`}>
              Cryptographically fingerprint MCP tools, detect runtime schema/permission drift, enforce explicit least-privilege grants, and physically intercept downstream tool execution.
            </p>
          </div>
          <button
            onClick={loadAll}
            className="inline-flex items-center space-x-2 px-3 py-2 rounded-lg text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh State</span>
          </button>
        </div>

        <div className="flex flex-wrap gap-2 mt-5 pt-4 border-t border-slate-800/60">
          {[
            { id: 'gateway' as const, label: 'MCP Runtime Gateway', icon: Terminal, count: upstreams.length },
            { id: 'tools' as const, label: 'Tool Identity & Drift', icon: Fingerprint, count: identities.length },
            { id: 'permissions' as const, label: 'Permission Graph & Least Privilege', icon: Network, count: grants.length },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = subTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setSubTab(tab.id)}
                className={`inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium border transition ${
                  active
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                    : isDark
                    ? 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-slate-200'
                    : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                <span className="px-1.5 py-0.5 rounded bg-slate-800/80 text-[10px] font-mono">{tab.count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* PANEL: MCP RUNTIME GATEWAY */}
      {subTab === 'gateway' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm">Register Downstream MCP Upstream</h3>
              <form onSubmit={handleRegisterUpstream} className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <input
                    value={upToolName}
                    onChange={(e) => setUpToolName(e.target.value)}
                    placeholder="Tool Name (e.g. stripe_refund_exec)"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                  <input
                    value={upCapability}
                    onChange={(e) => setUpCapability(e.target.value)}
                    placeholder="Capability (e.g. payments.refund)"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <select
                    value={upTransport}
                    onChange={(e) => setUpTransport(e.target.value as any)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="LOCAL_HANDLER">LOCAL_HANDLER</option>
                    <option value="HTTP_JSONRPC">HTTP_JSONRPC</option>
                  </select>
                  {upTransport === 'HTTP_JSONRPC' && (
                    <input
                      value={upEndpoint}
                      onChange={(e) => setUpEndpoint(e.target.value)}
                      placeholder="https://mcp-downstream.example.com/rpc"
                      className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                    />
                  )}
                </div>
                <button
                  type="submit"
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Register Upstream Tool</span>
                </button>
              </form>

              <div className="space-y-2 max-h-56 overflow-y-auto pt-2 border-t border-slate-800/60">
                {upstreams.length === 0 && (
                  <p className={`text-xs ${mutedCls}`}>No upstream MCP tools registered for {effTenant}.</p>
                )}
                {upstreams.map((u) => (
                  <div key={u.upstream_id} className={`p-3 rounded-xl border text-xs flex items-center justify-between ${subCls}`}>
                    <div>
                      <div className="font-mono font-bold text-cyan-400">{u.tool_name}</div>
                      <div className={`text-[11px] font-mono ${mutedCls}`}>
                        {u.capability} &bull; {u.transport} &bull; {u.status}
                      </div>
                    </div>
                    <button
                      onClick={() => handleToggleUpstream(u)}
                      className={`px-2.5 py-1 rounded text-[11px] font-medium ${
                        u.status === 'ACTIVE'
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {u.status === 'ACTIVE' ? 'Suspend' : 'Activate'}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm flex items-center space-x-2">
                <Play className="w-4 h-4 text-emerald-400" />
                <span>Execute Gated MCP Tool Call</span>
              </h3>
              <form onSubmit={handleInvokeGateway} className="space-y-3 text-xs">
                <div className="grid grid-cols-3 gap-3">
                  <input
                    value={invokeAgentId}
                    onChange={(e) => setInvokeAgentId(e.target.value)}
                    placeholder="Agent ID"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                  <input
                    value={invokeToolName}
                    onChange={(e) => setInvokeToolName(e.target.value)}
                    placeholder="Tool Name"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                  <input
                    value={invokeTarget}
                    onChange={(e) => setInvokeTarget(e.target.value)}
                    placeholder="Target Resource"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <textarea
                  rows={3}
                  value={invokeArgs}
                  onChange={(e) => setInvokeArgs(e.target.value)}
                  className={`w-full p-2.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                />
                <button
                  type="submit"
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Invoke Through Fail-Closed Gateway</span>
                </button>
              </form>

              {lastInvokeResult && (
                <div className={`p-3 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                  <div className="flex items-center justify-between font-mono font-bold">
                    <span>Decision: {lastInvokeResult.decision}</span>
                    <span className={lastInvokeResult.downstream_dispatched ? 'text-emerald-400' : 'text-rose-400'}>
                      downstream_dispatched={String(Boolean(lastInvokeResult.downstream_dispatched))}
                    </span>
                  </div>
                  <p className={mutedCls}>{lastInvokeResult.reason}</p>
                </div>
              )}
            </div>
          </div>

          <div className={`rounded-2xl border p-5 space-y-3 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Gateway Runtime Invocation Ledger</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {invocations.length === 0 && <p className={`text-xs ${mutedCls}`}>No gateway invocations recorded yet.</p>}
              {invocations.map((inv) => (
                <div key={inv.invocation_id} className={`p-3 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                  <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                    <div>
                      <span className="text-cyan-400 font-bold">{inv.tool_name}</span>
                      <span className={mutedCls}> ({inv.agent_id} &rarr; {inv.target})</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          inv.verdict_decision === 'ALLOW'
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-rose-500/15 text-rose-400'
                        }`}
                      >
                        {inv.verdict_decision}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px]">
                        downstream: {inv.downstream_status} ({inv.latency_ms}ms)
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {inv.pipeline_stages.map((st, idx) => (
                      <span
                        key={idx}
                        className={`px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                          st.status === 'PASS'
                            ? 'border-emerald-500/30 text-emerald-400'
                            : st.status === 'FAIL'
                            ? 'border-rose-500/30 text-rose-400'
                            : 'border-slate-700 text-slate-400'
                        }`}
                      >
                        {st.stage}: {st.status}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PANEL: TOOL IDENTITY & DRIFT */}
      {subTab === 'tools' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm flex items-center space-x-2">
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              <span>Register / Update Canonical Tool Snapshot</span>
            </h3>
            <form onSubmit={handleRegisterTool} className="space-y-3 text-xs">
              <div className="grid grid-cols-3 gap-3">
                <input
                  value={toolId}
                  onChange={(e) => setToolId(e.target.value)}
                  placeholder="Tool ID"
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                />
                <input
                  value={toolName}
                  onChange={(e) => setToolName(e.target.value)}
                  placeholder="Display Name"
                  className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                />
                <input
                  value={toolVersion}
                  onChange={(e) => setToolVersion(e.target.value)}
                  placeholder="Version"
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                />
              </div>
              <input
                value={toolPerms}
                onChange={(e) => setToolPerms(e.target.value)}
                placeholder="Declared permissions (comma-separated)"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
              />
              <input
                value={toolEndpoints}
                onChange={(e) => setToolEndpoints(e.target.value)}
                placeholder="Declared endpoints (comma-separated)"
                className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
              />
              <button
                type="submit"
                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Compute Fingerprint & Check Drift</span>
              </button>
            </form>

            <div className="space-y-2 max-h-60 overflow-y-auto pt-2 border-t border-slate-800/60">
              {identities.map((id) => (
                <div key={id.tool_identity_id} className={`p-3 rounded-xl border text-xs space-y-1 ${subCls}`}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-cyan-400">
                      {id.tool_id} (v{id.current_version})
                    </span>
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                          id.drift_status === 'CLEAN'
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-rose-500/15 text-rose-400'
                        }`}
                      >
                        {id.drift_status}
                      </span>
                      {id.drift_status !== 'CLEAN' && (
                        <button
                          onClick={() => handleApproveIdentity(id.tool_identity_id)}
                          className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px]"
                        >
                          Approve
                        </button>
                      )}
                    </div>
                  </div>
                  <div className={`font-mono text-[10px] truncate ${mutedCls}`}>
                    SHA256: {id.current_fingerprint} &bull; Source: {id.identity_source} &bull; Snapshots: {id.history.length}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Tool Drift Intelligence Findings</span>
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {drifts.length === 0 && <p className={`text-xs ${mutedCls}`}>No tool drift findings recorded.</p>}
              {drifts.map((d) => (
                <div key={d.drift_id} className={`p-3 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-rose-400">
                      {d.tool_id}: {d.from_version} &rarr; {d.to_version}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 text-[10px]">
                      {d.severity} / {d.recommended_action}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {d.drift_types.map((dt) => (
                      <span key={dt} className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px]">
                        {dt}
                      </span>
                    ))}
                  </div>
                  <div className={`text-[11px] ${mutedCls}`}>{d.explanation.join(' | ')}</div>
                  <div className="font-mono text-[10px]">
                    Status: {d.resolved ? `RESOLVED by ${d.resolved_by}` : 'ACTIVE DRIFT'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PANEL: PERMISSION GRAPH & LEAST PRIVILEGE */}
      {subTab === 'permissions' && (
        <div className="space-y-6">
          {graphSummary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Active Grants', value: graphSummary.summary?.active_grants || 0 },
                { label: 'Declared Tool Scopes', value: graphSummary.summary?.declared_tool_scopes || 0 },
                { label: 'Excess Wildcard Grants', value: graphSummary.summary?.wildcard_excess_grants || 0 },
                { label: 'Active Delegations', value: graphSummary.summary?.active_delegations || 0 },
              ].map((m) => (
                <div key={m.label} className={`rounded-xl border p-4 ${cardCls}`}>
                  <div className={`text-xs ${mutedCls}`}>{m.label}</div>
                  <div className="text-2xl font-bold font-mono mt-1">{m.value}</div>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm flex items-center space-x-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Issue Explicit Grant & Evaluate Least Privilege</span>
              </h3>
              <form onSubmit={handleCreateGrant} className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <input
                    value={grantAgentId}
                    onChange={(e) => setGrantAgentId(e.target.value)}
                    placeholder="Agent ID"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                  <input
                    value={grantToolId}
                    onChange={(e) => setGrantToolId(e.target.value)}
                    placeholder="Tool ID"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <input
                    value={grantResource}
                    onChange={(e) => setGrantResource(e.target.value)}
                    placeholder="Resource pattern (e.g. order:*)"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                  <input
                    value={grantAction}
                    onChange={(e) => setGrantAction(e.target.value)}
                    placeholder="Action (e.g. execute)"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <input
                  value={grantScopes}
                  onChange={(e) => setGrantScopes(e.target.value)}
                  placeholder="Granted Scopes (comma-separated)"
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                />
                <div className="flex flex-wrap gap-2">
                  <button
                    type="submit"
                    className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Issue Granted Scope</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleEvaluatePermissions}
                    className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Evaluate Effective Permissions</span>
                  </button>
                </div>
              </form>

              {permEvalResult && (
                <div className={`p-4 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                  <div className="flex items-center justify-between font-mono font-bold">
                    <span>Verdict: {permEvalResult.decision}</span>
                    {permEvalResult.allowed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    )}
                  </div>
                  <div className="font-mono text-[11px]">
                    Declared (Claimed): [{permEvalResult.declared_scopes.join(', ') || 'none'}]
                  </div>
                  <div className="font-mono text-[11px]">
                    Granted: [{permEvalResult.granted_scopes.join(', ') || 'none'}]
                  </div>
                  <div className="font-mono text-[11px] text-cyan-400">
                    Effective: [{permEvalResult.effective_scopes.join(', ') || 'none'}]
                  </div>
                  {permEvalResult.excess_permissions.length > 0 && (
                    <div className="text-amber-400 font-mono text-[11px]">
                      Excess Least-Privilege Warnings: {permEvalResult.excess_permissions.length}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm">Active & Revoked Permission Grants</h3>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {grants.length === 0 && <p className={`text-xs ${mutedCls}`}>No explicit grants issued yet.</p>}
                {grants.map((g) => (
                  <div key={g.grant_id} className={`p-3 rounded-xl border text-xs flex items-center justify-between ${subCls}`}>
                    <div>
                      <div className="font-mono font-bold">
                        {g.agent_id} &rarr; {g.tool_id} ({g.action})
                      </div>
                      <div className={`font-mono text-[11px] ${mutedCls}`}>
                        Resource: {g.resource_pattern} &bull; Scopes: [{g.scopes.join(', ')}] &bull; Origin: {g.origin}
                      </div>
                    </div>
                    {g.revoked ? (
                      <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 font-mono text-[10px]">
                        REVOKED
                      </span>
                    ) : (
                      <button
                        onClick={() => handleRevokeGrant(g.grant_id)}
                        className="px-2.5 py-1 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 text-[11px]"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
