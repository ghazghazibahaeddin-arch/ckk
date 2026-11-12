import React, { useState } from 'react';
import {
  GitMerge,
  GitBranch,
  ShieldCheck,
  AlertTriangle,
  Plus,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ArrowRight,
  UserCheck,
  KeyRound,
  Trash2,
} from 'lucide-react';
import type { DelegationRecord, DelegationChainVerificationResult } from '../../governance/types';

interface DelegationsViewProps {
  delegations: DelegationRecord[];
  onRefresh: () => void;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const DelegationsView: React.FC<DelegationsViewProps> = ({
  delegations,
  onRefresh,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [selectedDel, setSelectedDel] = useState<DelegationRecord | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showSubModal, setShowSubModal] = useState(false);
  const [parentForSub, setParentForSub] = useState<DelegationRecord | null>(null);
  const [chainResult, setChainResult] = useState<DelegationChainVerificationResult | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);

  // Create Root Form
  const [rootForm, setRootForm] = useState({
    delegator_agent_id: 'agt-ops-supervisor',
    delegatee_agent_id: 'agt-finance-specialist',
    allowed_actions: 'payments.process, refunds.issue, invoices.generate',
    allowed_resources: 'order:*, customer:*, invoice:*',
    allowed_tools: 'stripe_charge, stripe_refund, send_invoice',
    max_depth: 3,
    max_per_action: 500,
    total_budget: 5000,
  });

  // Create Sub-delegation Form
  const [subForm, setSubForm] = useState({
    delegatee_agent_id: 'agt-micro-worker',
    allowed_actions: 'refunds.issue',
    allowed_resources: 'order:*',
    allowed_tools: 'stripe_refund',
    max_per_action: 100,
    total_budget: 1000,
  });

  const handleCreateRoot = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionMsg(null);
    try {
      const res = await fetch('/api/v1/delegations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          delegator_agent_id: rootForm.delegator_agent_id,
          delegatee_agent_id: rootForm.delegatee_agent_id,
          allowed_actions: rootForm.allowed_actions.split(',').map((s) => s.trim()).filter(Boolean),
          allowed_resources: rootForm.allowed_resources.split(',').map((s) => s.trim()).filter(Boolean),
          allowed_tools: rootForm.allowed_tools.split(',').map((s) => s.trim()).filter(Boolean),
          max_depth: Number(rootForm.max_depth),
          spending_limit: {
            max_per_action: Number(rootForm.max_per_action),
            total_budget: Number(rootForm.total_budget),
            currency: 'USD',
          },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create root delegation');
      setActionMsg({ type: 'success', text: `Root delegation ${data.delegation.delegation_id} created with verified signature.` });
      setShowCreateModal(false);
      onRefresh();
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleCreateSub = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!parentForSub) return;
    setActionMsg(null);
    try {
      const res = await fetch(`/api/v1/delegations/${parentForSub.delegation_id}/delegate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          delegatee_agent_id: subForm.delegatee_agent_id,
          allowed_actions: subForm.allowed_actions.split(',').map((s) => s.trim()).filter(Boolean),
          allowed_resources: subForm.allowed_resources.split(',').map((s) => s.trim()).filter(Boolean),
          allowed_tools: subForm.allowed_tools.split(',').map((s) => s.trim()).filter(Boolean),
          spending_limit: {
            max_per_action: Number(subForm.max_per_action),
            total_budget: Number(subForm.total_budget),
            currency: 'USD',
          },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Sub-delegation expansion rejected');
      setActionMsg({ type: 'success', text: `Sub-delegation ${data.delegation.delegation_id} granted at depth ${data.delegation.scope.current_depth}.` });
      setShowSubModal(false);
      onRefresh();
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const executeCascadeRevoke = async (delegationId: string) => {
    setActionMsg(null);
    try {
      const res = await fetch(`/api/v1/delegations/${delegationId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual supervisor cascading revocation via governance console' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to revoke delegation');
      setActionMsg({ type: 'success', text: `Cascading revocation complete: ${data.revoked_count} delegations invalidated.` });
      onRefresh();
      if (selectedDel?.delegation_id === delegationId) {
        setSelectedDel(null);
      }
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    } finally {
      setConfirmRevokeId(null);
    }
  };

  const handleInspectChain = async (delId: string) => {
    setVerifyingChain(true);
    try {
      const res = await fetch(`/api/v1/delegations/${delId}`);
      const data = await res.json();
      setChainResult(data.chain_verification);
    } catch {
      setChainResult(null);
    } finally {
      setVerifyingChain(false);
    }
  };

  const filtered = delegations.filter(
    (d) =>
      d.delegation_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.delegator_agent_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.delegatee_agent_id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const activeCount = delegations.filter((d) => !d.revoked).length;
  const revokedCount = delegations.filter((d) => d.revoked).length;

  return (
    <div className="space-y-6">
      {/* Header & KPI Summary */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <GitMerge className="w-5 h-5 text-indigo-400" />
            Multi-Hop Delegation & Contextual Permission Gateway
          </h2>
          <p className={`text-sm ${textMuted} mt-1`}>
            Cryptographically signed agent delegations with monotonic, non-expanding scope and cascading revocation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className={`p-2 rounded-lg border ${borderSubtle} hover:${bgSubtle} transition-colors`}
            title="Refresh delegations"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg text-sm transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Issue Root Delegation
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
          <div className="text-xs text-muted-foreground uppercase font-semibold">Active Delegations</div>
          <div className="text-2xl font-bold mt-1 text-emerald-400">{activeCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Verified non-expanding</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Revoked / Terminated</div>
          <div className="text-2xl font-bold mt-1 text-rose-400">{revokedCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Cascading invalidations</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Max Delegation Depth</div>
          <div className="text-2xl font-bold mt-1 text-indigo-400">3 Hops</div>
          <div className="text-xs text-muted-foreground mt-1">Hard bounded ceiling</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Fail-Closed Gate</div>
          <div className="text-2xl font-bold mt-1 text-amber-400">100% Monotonic</div>
          <div className="text-xs text-muted-foreground mt-1">Zero bypass permission guard</div>
        </div>
      </div>

      {/* Main Grid: Delegations List & Chain Visualizer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Delegations List */}
        <div className={`lg:col-span-2 rounded-xl border ${borderSubtle} ${bgCard} overflow-hidden`}>
          <div className={`p-4 border-b ${borderSubtle} flex items-center justify-between gap-4`}>
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search delegation by ID, delegator or delegatee..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`w-full pl-9 pr-3 py-1.5 text-sm rounded-lg border ${borderSubtle} ${bgSubtle} focus:outline-none focus:ring-1 focus:ring-indigo-500`}
              />
            </div>
            <span className="text-xs text-muted-foreground whitespace-nowrap">{filtered.length} records</span>
          </div>

          <div className="divide-y divide-zinc-800 max-h-[580px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-sm">No delegations found.</div>
            ) : (
              filtered.map((del) => {
                const isSelected = selectedDel?.delegation_id === del.delegation_id;
                const isRoot = del.parent_delegation_id === null;

                return (
                  <div
                    key={del.delegation_id}
                    onClick={() => {
                      setSelectedDel(del);
                      handleInspectChain(del.delegation_id);
                    }}
                    className={`p-4 cursor-pointer transition-colors ${
                      isSelected ? (isDark ? 'bg-indigo-950/30' : 'bg-indigo-50') : `hover:${bgSubtle}`
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {isRoot ? (
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                            ROOT (Depth 0)
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                            HOP {del.scope.current_depth} / {del.scope.max_depth}
                          </span>
                        )}
                        <span className="font-mono text-xs font-bold">{del.delegation_id}</span>
                      </div>
                      <div>
                        {del.revoked ? (
                          <span className="flex items-center gap-1 text-xs font-medium text-rose-400">
                            <XCircle className="w-3.5 h-3.5" /> REVOKED
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs font-medium text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVE
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Agent Flow */}
                    <div className="mt-2 flex items-center gap-2 text-xs">
                      <span className="text-muted-foreground">Delegator:</span>
                      <span className="font-mono font-medium">{del.delegator_agent_id}</span>
                      <ArrowRight className="w-3 h-3 text-muted-foreground" />
                      <span className="text-muted-foreground">Delegatee:</span>
                      <span className="font-mono font-medium text-indigo-400">{del.delegatee_agent_id}</span>
                    </div>

                    {/* Scope & Spending Summary */}
                    <div className="mt-3 flex flex-wrap gap-2 text-xs">
                      <span className="px-2 py-0.5 rounded bg-zinc-800/60 text-zinc-300">
                        {del.scope.allowed_actions.join(', ')}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-zinc-800/60 text-zinc-400">
                        Ceiling: ${del.spending_limit.max_per_action} / act (${del.spending_limit.total_budget} total)
                      </span>
                    </div>

                    {/* Actions Row */}
                    <div className="mt-3 pt-2 border-t border-zinc-800/50 flex items-center justify-between text-xs">
                      <span className="text-zinc-500 font-mono text-[11px] truncate max-w-[200px]" title={del.signature}>
                        Sig: {del.signature.slice(0, 16)}...
                      </span>
                      <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        {!del.revoked && del.scope.current_depth < del.scope.max_depth && (
                          <button
                            onClick={() => {
                              setParentForSub(del);
                              setSubForm({
                                delegatee_agent_id: 'agt-sub-worker',
                                allowed_actions: del.scope.allowed_actions[0] || 'refunds.issue',
                                allowed_resources: del.scope.allowed_resources[0] || 'order:*',
                                allowed_tools: del.scope.allowed_tools?.[0] || 'stripe_refund',
                                max_per_action: Math.min(100, del.spending_limit.max_per_action),
                                total_budget: Math.min(500, del.spending_limit.total_budget),
                              });
                              setShowSubModal(true);
                            }}
                            className="text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1"
                          >
                            <GitBranch className="w-3.5 h-3.5" /> Sub-Delegate
                          </button>
                        )}
                        {!del.revoked && (
                          <button
                            onClick={() => setConfirmRevokeId(del.delegation_id)}
                            className="text-rose-400 hover:text-rose-300 font-medium flex items-center gap-1"
                          >
                            <Trash2 className="w-3.5 h-3.5" /> Revoke
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

        {/* Chain Verification Panel */}
        <div className={`rounded-xl border ${borderSubtle} ${bgCard} p-5 space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              Delegation Chain Audit
            </h3>
            {verifyingChain && <span className="text-xs text-muted-foreground animate-pulse">Verifying...</span>}
          </div>

          {!selectedDel ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              Select a delegation to inspect its cryptographic signature, monotonic scope invariants, and full ancestor chain.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Selected ID:</span>
                  <span className="font-mono font-bold text-indigo-300">{selectedDel.delegation_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Chain Status:</span>
                  <span className={chainResult?.valid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {chainResult?.valid ? 'VALIDATED (Non-Expanding)' : 'INVALID / REVOKED'}
                  </span>
                </div>
                {chainResult?.failure_reason && (
                  <div className="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">
                    {chainResult.failure_reason}
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Current Depth:</span>
                  <span className="font-semibold">{selectedDel.scope.current_depth} / {selectedDel.scope.max_depth} max</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Valid Until:</span>
                  <span className="font-mono">{new Date(selectedDel.valid_until).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Ancestry Chain Tree */}
              <div>
                <div className="text-xs font-semibold text-muted-foreground uppercase mb-2">Ancestry Resolution Tree</div>
                {chainResult?.delegations && chainResult.delegations.length > 0 ? (
                  <div className="space-y-2">
                    {chainResult.delegations.map((hop, idx) => (
                      <div
                        key={hop.delegation_id}
                        className={`p-3 rounded-lg border text-xs ${
                          hop.revoked
                            ? 'bg-rose-950/20 border-rose-800 text-rose-300'
                            : 'bg-zinc-900/80 border-zinc-800 text-zinc-300'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono font-semibold">
                          <span>
                            Hop #{chainResult.delegations.length - 1 - idx}: {hop.delegation_id}
                          </span>
                          <span>{hop.revoked ? 'REVOKED' : 'VALID'}</span>
                        </div>
                        <div className="mt-1 text-zinc-400">
                          {hop.delegator_agent_id} → {hop.delegatee_agent_id}
                        </div>
                        <div className="mt-1 text-[11px] text-zinc-500">
                          Actions: {hop.scope.allowed_actions.join(', ')}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-muted-foreground">Root delegation (no parent hops).</div>
                )}
              </div>

              {/* Cryptographic Signature Box */}
              <div>
                <div className="text-xs font-semibold text-muted-foreground uppercase mb-1">Root Authority Signature</div>
                <div className="p-2.5 rounded bg-zinc-950 font-mono text-[11px] text-zinc-400 break-all border border-zinc-800">
                  {selectedDel.signature}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create Root Delegation */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className={`w-full max-w-lg rounded-xl border ${borderSubtle} ${bgCard} p-6 space-y-4`}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold">Issue Root Authority Delegation</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted-foreground hover:text-white">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateRoot} className="space-y-3 text-sm">
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Delegator Agent ID</label>
                <input
                  type="text"
                  required
                  value={rootForm.delegator_agent_id}
                  onChange={(e) => setRootForm({ ...rootForm, delegator_agent_id: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Delegatee Agent ID</label>
                <input
                  type="text"
                  required
                  value={rootForm.delegatee_agent_id}
                  onChange={(e) => setRootForm({ ...rootForm, delegatee_agent_id: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Allowed Actions (comma-separated)</label>
                <input
                  type="text"
                  required
                  value={rootForm.allowed_actions}
                  onChange={(e) => setRootForm({ ...rootForm, allowed_actions: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Allowed Resources (comma-separated)</label>
                <input
                  type="text"
                  required
                  value={rootForm.allowed_resources}
                  onChange={(e) => setRootForm({ ...rootForm, allowed_resources: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max Depth</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={rootForm.max_depth}
                    onChange={(e) => setRootForm({ ...rootForm, max_depth: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max/Action ($)</label>
                  <input
                    type="number"
                    value={rootForm.max_per_action}
                    onChange={(e) => setRootForm({ ...rootForm, max_per_action: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Total Budget ($)</label>
                  <input
                    type="number"
                    value={rootForm.total_budget}
                    onChange={(e) => setRootForm({ ...rootForm, total_budget: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className={`px-4 py-2 rounded-lg border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium"
                >
                  Sign & Issue
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create Sub-Delegation */}
      {showSubModal && parentForSub && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className={`w-full max-w-lg rounded-xl border ${borderSubtle} ${bgCard} p-6 space-y-4`}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold">Sub-Delegate Monotonic Authority</h3>
                <p className="text-xs text-muted-foreground">
                  Parent: {parentForSub.delegation_id} (Depth {parentForSub.scope.current_depth} → {parentForSub.scope.current_depth + 1})
                </p>
              </div>
              <button onClick={() => setShowSubModal(false)} className="text-muted-foreground hover:text-white">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateSub} className="space-y-3 text-sm">
              <div className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 text-xs space-y-1">
                <div className="font-semibold text-zinc-300">Non-Expansion Ceiling Enforced:</div>
                <div className="text-zinc-400">Parent Actions: {parentForSub.scope.allowed_actions.join(', ')}</div>
                <div className="text-zinc-400">Parent Max/Action: ${parentForSub.spending_limit.max_per_action}</div>
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">Delegatee Agent ID</label>
                <input
                  type="text"
                  required
                  value={subForm.delegatee_agent_id}
                  onChange={(e) => setSubForm({ ...subForm, delegatee_agent_id: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-muted-foreground mb-1">
                  Allowed Actions (MUST be subset of parent actions)
                </label>
                <input
                  type="text"
                  required
                  value={subForm.allowed_actions}
                  onChange={(e) => setSubForm({ ...subForm, allowed_actions: e.target.value })}
                  className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">
                    Max/Action ($ &le; {parentForSub.spending_limit.max_per_action})
                  </label>
                  <input
                    type="number"
                    max={parentForSub.spending_limit.max_per_action}
                    value={subForm.max_per_action}
                    onChange={(e) => setSubForm({ ...subForm, max_per_action: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">
                    Total Budget ($ &le; {parentForSub.spending_limit.total_budget})
                  </label>
                  <input
                    type="number"
                    max={parentForSub.spending_limit.total_budget}
                    value={subForm.total_budget}
                    onChange={(e) => setSubForm({ ...subForm, total_budget: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowSubModal(false)}
                  className={`px-4 py-2 rounded-lg border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium"
                >
                  Issue Sub-Delegation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Cascading Revocation */}
      {confirmRevokeId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fadeIn">
          <div className={`w-full max-w-md rounded-xl ${bgCard} border ${borderSubtle} p-6 space-y-4 shadow-2xl`}>
            <div className="flex items-center gap-3 text-rose-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="font-bold text-lg text-white">Confirm Cascading Revocation</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Are you sure you want to trigger cascading revocation on delegation <span className="font-mono font-bold text-rose-300">{confirmRevokeId}</span>?
              All descendant child and grandchild delegations in this chain will be permanently invalidated.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeId(null)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle} text-slate-300 hover:text-white transition-colors`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => executeCascadeRevoke(confirmRevokeId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Revoke Chain Now
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
