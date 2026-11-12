import React, { useState } from 'react';
import {
  Server,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Plus,
  CheckCircle2,
  XCircle,
  PauseCircle,
  Ban,
  Activity,
  Code2,
  FileCode,
  ArrowRight,
  Eye,
  Sliders,
} from 'lucide-react';
import type { McpServerRecord, McpToolSchema } from '../../governance/types';

interface McpGovernanceViewProps {
  servers: McpServerRecord[];
  onRefresh: () => void;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const McpGovernanceView: React.FC<McpGovernanceViewProps> = ({
  servers,
  onRefresh,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [selectedServer, setSelectedServer] = useState<McpServerRecord | null>(null);
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [showDriftModal, setShowDriftModal] = useState(false);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [confirmRevokeServerId, setConfirmRevokeServerId] = useState<string | null>(null);

  // Register Form
  const [regForm, setRegForm] = useState({
    name: 'Logistics Courier MCP',
    transport: 'STREAMABLE_HTTP' as any,
    endpoint_url: 'http://localhost:3000/api/v1/mcp/courier',
    version: '1.1.0',
    tool_name: 'dispatch_fedex_shipment',
    tool_desc: 'Dispatches parcel to international shipping lane',
    is_sensitive: true,
  });

  const handleApproveServer = async (serverId: string) => {
    setActionMsg(null);
    try {
      const res = await fetch(`/api/v1/mcp/servers/${serverId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewer: 'security-admin-officer' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to approve MCP server');
      setActionMsg({ type: 'success', text: `MCP server ${serverId} approved for production.` });
      onRefresh();
      if (selectedServer?.server_id === serverId) {
        setSelectedServer(data.server);
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleSuspendServer = async (serverId: string) => {
    setActionMsg(null);
    try {
      const res = await fetch(`/api/v1/mcp/servers/${serverId}/suspend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual supervisor temporary suspension' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to suspend MCP server');
      setActionMsg({ type: 'success', text: `MCP server ${serverId} suspended. Tool execution blocked in Action Gate.` });
      onRefresh();
      if (selectedServer?.server_id === serverId) {
        setSelectedServer(data.server);
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const executeRevokeServer = async (serverId: string) => {
    setActionMsg(null);
    try {
      const res = await fetch(`/api/v1/mcp/servers/${serverId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Permanent security revocation' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to revoke MCP server');
      setActionMsg({ type: 'success', text: `MCP server ${serverId} permanently revoked.` });
      onRefresh();
      if (selectedServer?.server_id === serverId) {
        setSelectedServer(data.server);
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    } finally {
      setConfirmRevokeServerId(null);
    }
  };

  const handleSimulateDrift = async () => {
    if (!selectedServer) return;
    setActionMsg(null);
    try {
      // Add or drift a tool schema
      const driftedTools = [
        ...selectedServer.exposed_tools,
        {
          name: `mutated_tool_${Date.now().toString().slice(-4)}`,
          description: 'Newly detected schema addition from remote endpoint',
          input_schema: { type: 'object', properties: { payload: { type: 'string' } } },
          is_sensitive: true,
          sensitive_reason: 'Automated sensitive payload mutation',
        },
      ];

      const res = await fetch(`/api/v1/mcp/servers/${selectedServer.server_id}/tools/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_tools: driftedTools }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Drift test failed');
      setActionMsg({
        type: 'success',
        text: `Drift detected! Server status transitioned to REVIEW_REQUIRED. Tools: ${data.drift_reasons.join(', ')}`,
      });
      setShowDriftModal(false);
      onRefresh();
      setSelectedServer(data.server);
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const activeCount = servers.filter((s) => s.lifecycle_status === 'ACTIVE').length;
  const reviewCount = servers.filter((s) => s.lifecycle_status === 'REVIEW_REQUIRED').length;
  const suspendedCount = servers.filter((s) => s.lifecycle_status === 'SUSPENDED' || s.lifecycle_status === 'REVOKED').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            MCP Server Lifecycle Governance & Schema Drift Console
          </h2>
          <p className={`text-sm ${textMuted} mt-1`}>
            Continuous Model Context Protocol server registration, tool input schema fingerprinting, and human approval gates.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className={`p-2 rounded-lg border ${borderSubtle} hover:${bgSubtle} transition-colors`}
            title="Refresh servers"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {actionMsg && (
        <div
          className={`p-3.5 rounded-lg text-sm border flex items-center justify-between ${
            actionMsg.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
          }`}
        >
          <span>{actionMsg.text}</span>
          <button onClick={() => setActionMsg(null)} className="text-xs opacity-70 hover:opacity-100">
            Dismiss
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Active MCP Servers</div>
          <div className="text-2xl font-bold mt-1 text-emerald-400">{activeCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Verified production tools</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Review Required</div>
          <div className="text-2xl font-bold mt-1 text-amber-400">{reviewCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Schema drift / unapproved</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Suspended / Revoked</div>
          <div className="text-2xl font-bold mt-1 text-rose-400">{suspendedCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Hard blocked in Action Gate</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Fail-Closed Gate</div>
          <div className="text-2xl font-bold mt-1 text-cyan-400">Zero Bypass</div>
          <div className="text-xs text-muted-foreground mt-1">Input schema hash bound</div>
        </div>
      </div>

      {/* Main Grid: Server Cards & Tool Schemas Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Servers List */}
        <div className={`lg:col-span-2 rounded-xl border ${borderSubtle} ${bgCard} p-5 space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Connected MCP Servers
            </h3>
            <span className="text-xs text-muted-foreground">{servers.length} registered</span>
          </div>

          <div className="space-y-3">
            {servers.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">No MCP servers registered.</div>
            ) : (
              servers.map((s) => {
                const isSelected = selectedServer?.server_id === s.server_id;
                const statusColor =
                  s.lifecycle_status === 'ACTIVE'
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                    : s.lifecycle_status === 'REVIEW_REQUIRED'
                    ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                    : 'text-rose-400 bg-rose-500/10 border-rose-500/20';

                return (
                  <div
                    key={s.server_id}
                    onClick={() => setSelectedServer(s)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? isDark
                          ? 'bg-cyan-950/20 border-cyan-800'
                          : 'bg-cyan-50 border-cyan-300'
                        : `bg-zinc-900/60 border-zinc-800 hover:${bgSubtle}`
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm">{s.name}</span>
                        <span className="font-mono text-xs text-muted-foreground">({s.version})</span>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${statusColor}`}>
                        {s.lifecycle_status}
                      </span>
                    </div>

                    <div className="mt-2 flex items-center gap-3 text-xs text-muted-foreground">
                      <span>Transport: <strong className="text-zinc-200">{s.transport}</strong></span>
                      <span>Tools: <strong className="text-cyan-400">{s.exposed_tools.length}</strong></span>
                      <span>Health: <strong className="text-emerald-400">{s.health_status}</strong></span>
                    </div>

                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {s.exposed_tools.map((t) => (
                        <span
                          key={t.name}
                          className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                            t.is_sensitive
                              ? t.approved_for_production
                                ? 'bg-amber-950/30 text-amber-300 border-amber-800/60'
                                : 'bg-rose-950/40 text-rose-300 border-rose-800/80 animate-pulse'
                              : 'bg-zinc-800/60 text-zinc-300 border-zinc-700/50'
                          }`}
                        >
                          {t.name} {t.is_sensitive && (!t.approved_for_production ? '(PENDING APPROVAL)' : '(SENSITIVE)')}
                        </span>
                      ))}
                    </div>

                    {/* Controls Row */}
                    <div className="mt-3 pt-2 border-t border-zinc-800/60 flex items-center justify-between text-xs" onClick={(e) => e.stopPropagation()}>
                      <span className="font-mono text-[11px] text-zinc-500">
                        Fingerprint: {s.fingerprint.slice(0, 16)}...
                      </span>
                      <div className="flex items-center gap-2">
                        {s.lifecycle_status === 'REVIEW_REQUIRED' && (
                          <button
                            onClick={() => handleApproveServer(s.server_id)}
                            className="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-medium flex items-center gap-1"
                          >
                            <CheckCircle2 className="w-3 h-3" /> Approve All
                          </button>
                        )}
                        {s.lifecycle_status === 'ACTIVE' && (
                          <button
                            onClick={() => handleSuspendServer(s.server_id)}
                            className="text-amber-400 hover:text-amber-300 font-medium flex items-center gap-1"
                          >
                            <PauseCircle className="w-3 h-3" /> Suspend
                          </button>
                        )}
                        {s.lifecycle_status !== 'REVOKED' && (
                          <button
                            onClick={() => setConfirmRevokeServerId(s.server_id)}
                            className="text-rose-400 hover:text-rose-300 font-medium flex items-center gap-1"
                          >
                            <Ban className="w-3 h-3" /> Revoke
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Server & Schema Details Inspector */}
        <div className={`rounded-xl border ${borderSubtle} ${bgCard} p-5 space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Tool Schemas & Drift Audit
            </h3>
            {selectedServer && (
              <button
                onClick={() => setShowDriftModal(true)}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <Sliders className="w-3 h-3" /> Test Drift
              </button>
            )}
          </div>

          {!selectedServer ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              Select an MCP server to audit input schemas, SHA-256 schema hashes, sensitive permission requirements, and audit changelogs.
            </div>
          ) : (
            <div className="space-y-4 text-xs">
              <div className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Server ID:</span>
                  <span className="font-mono font-bold text-zinc-200">{selectedServer.server_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Endpoint:</span>
                  <span className="font-mono truncate max-w-[200px] text-zinc-300">{selectedServer.endpoint_url || 'IN_PROCESS'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Auth Method:</span>
                  <span className="font-semibold text-zinc-300">{selectedServer.auth_method}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Trust State:</span>
                  <span className="text-emerald-400 font-semibold">{selectedServer.trust_state}</span>
                </div>
              </div>

              {/* Tool Schemas Accordion */}
              <div>
                <div className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                  Exposed Tool Schemas ({selectedServer.exposed_tools.length})
                </div>
                <div className="space-y-2">
                  {selectedServer.exposed_tools.map((tool) => (
                    <div key={tool.name} className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
                      <div className="flex items-center justify-between font-mono font-semibold">
                        <span className="text-cyan-300">{tool.name}</span>
                        {tool.is_sensitive ? (
                          tool.approved_for_production ? (
                            <span className="text-amber-400 text-[10px]">APPROVED SENSITIVE</span>
                          ) : (
                            <span className="text-rose-400 text-[10px] font-bold">UNAPPROVED SENSITIVE</span>
                          )
                        ) : (
                          <span className="text-zinc-500 text-[10px]">STANDARD</span>
                        )}
                      </div>
                      <div className="text-zinc-400 text-[11px]">{tool.description}</div>
                      <div className="flex justify-between text-[10px] text-zinc-500 font-mono pt-1 border-t border-zinc-900">
                        <span>Schema Hash:</span>
                        <span>{tool.schema_hash}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Changelog */}
              <div>
                <div className="text-xs font-semibold text-muted-foreground uppercase mb-1">Lifecycle Changelog</div>
                <div className="space-y-1.5 max-h-[160px] overflow-y-auto">
                  {selectedServer.changelog.map((log, i) => (
                    <div key={i} className="p-2 rounded bg-zinc-950/70 border border-zinc-800/80 text-[11px]">
                      <div className="flex justify-between text-zinc-400 font-mono">
                        <span className="font-bold text-zinc-300">{log.event}</span>
                        <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <div className="text-zinc-500 mt-0.5">{log.details}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Test Schema Drift */}
      {showDriftModal && selectedServer && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className={`w-full max-w-md rounded-xl border ${borderSubtle} ${bgCard} p-6 space-y-4`}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold">Simulate Remote Schema Drift</h3>
              <button onClick={() => setShowDriftModal(false)} className="text-muted-foreground hover:text-white">
                ✕
              </button>
            </div>
            <p className="text-xs text-muted-foreground">
              Simulate an upstream MCP provider modifying a sensitive tool schema without notice. CCK will immediately detect hash deviation, halt automatic dispatches in Action Gate, and demand human re-approval.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowDriftModal(false)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle}`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSimulateDrift}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium"
              >
                Inject Drift Mutation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Server Revocation */}
      {confirmRevokeServerId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fadeIn">
          <div className={`w-full max-w-md rounded-xl ${bgCard} border ${borderSubtle} p-6 space-y-4 shadow-2xl`}>
            <div className="flex items-center gap-3 text-rose-400">
              <Ban className="w-6 h-6" />
              <h3 className="font-bold text-lg text-white">Permanently Revoke MCP Server</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Are you sure you want to permanently revoke MCP server <span className="font-mono font-bold text-rose-300">{confirmRevokeServerId}</span>?
              All tools exposed by this server will be immediately blocked across all connected agents.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeServerId(null)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle} text-slate-300 hover:text-white transition-colors`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => executeRevokeServer(confirmRevokeServerId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors flex items-center gap-2"
              >
                <Ban className="w-4 h-4" />
                Revoke Server
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
