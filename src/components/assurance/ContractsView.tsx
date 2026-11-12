import React, { useState } from 'react';
import {
  ShieldCheck,
  Play,
  RotateCcw,
  Search,
  Plus,
  RefreshCw,
  ExternalLink,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Layers,
  FileCheck,
} from 'lucide-react';
import type { ActionContractRecord, ContractExecutionRecord } from '../../assurance/types';

interface ContractsViewProps {
  contracts: ActionContractRecord[];
  executions: ContractExecutionRecord[];
  onRefresh: () => void;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const ContractsView: React.FC<ContractsViewProps> = ({
  contracts,
  executions,
  onRefresh,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [selectedContract, setSelectedContract] = useState<ActionContractRecord | null>(null);
  const [showNewModal, setShowNewModal] = useState(false);
  const [showExecuteModal, setShowExecuteModal] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [probingId, setProbingId] = useState<string | null>(null);
  const [compensatingId, setCompensatingId] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<any | null>(null);

  // New Contract Form
  const [newForm, setNewForm] = useState({
    agent_id: 'agt-console',
    permitted_action: 'payment.charge',
    target_resource: 'api.stripe.com',
    spending_ceiling: 500,
    currency: 'USD',
    required_evidence: 'fact:order:1099:status',
    applicable_invariants: 'INV_NEVER_CHARGE_TWICE, INV_NEVER_EXCEED_LIMIT',
    compensation_supported: true,
  });

  // Execute Form
  const [execForm, setExecForm] = useState({
    contract_id: '',
    idempotency_key: `idemp-${Date.now()}`,
    order_id: 'order:1099',
    amount: 150,
    simulate_unknown: false,
  });

  const handleCreateContract = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/contracts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newForm,
          required_evidence: newForm.required_evidence.split(',').map((s) => s.trim()).filter(Boolean),
          applicable_invariants: newForm.applicable_invariants.split(',').map((s) => s.trim()).filter(Boolean),
        }),
      });
      if (res.ok) {
        setShowNewModal(false);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to create contract:', err);
    }
  };

  const handleExecuteContract = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!execForm.contract_id) return;
    setExecuting(true);
    setActionResult(null);
    try {
      const res = await fetch(`/api/v1/contracts/${execForm.contract_id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: execForm.idempotency_key,
          simulate_unknown: execForm.simulate_unknown,
          parameters: {
            order_id: execForm.order_id,
            entity_id: execForm.order_id,
            amount: Number(execForm.amount),
            currency: 'USD',
          },
        }),
      });
      const data = await res.json();
      setActionResult({ status: res.status, data });
      onRefresh();
    } catch (err: any) {
      setActionResult({ status: 500, data: { error: err.message } });
    } finally {
      setExecuting(false);
    }
  };

  const handleProbeExternal = async (executionId: string) => {
    setProbingId(executionId);
    try {
      const res = await fetch(`/api/v1/contracts/executions/${executionId}/probe-external`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ simulated_outcome: 'SUCCEEDED' }),
      });
      if (res.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to probe external status:', err);
    } finally {
      setProbingId(null);
    }
  };

  const handleCompensate = async (executionId: string) => {
    setCompensatingId(executionId);
    try {
      const res = await fetch(`/api/v1/contracts/executions/${executionId}/compensate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual supervisor rollback via UI console' }),
      });
      if (res.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to compensate execution:', err);
    } finally {
      setCompensatingId(null);
    }
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'SUCCEEDED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">SUCCEEDED</span>;
      case 'EXECUTING':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 animate-pulse">EXECUTING</span>;
      case 'AUTHORIZED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">AUTHORIZED</span>;
      case 'PREPARED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/20 text-slate-300 border border-slate-500/30">PREPARED</span>;
      case 'UNKNOWN':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">UNKNOWN (PROBE REQ)</span>;
      case 'COMPENSATED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">COMPENSATED</span>;
      case 'FAILED':
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">FAILED</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className={`rounded-2xl border p-6 ${bgCard}`}>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-1">
              <ShieldCheck className="w-4 h-4" />
              <span>Assurance Module — EFFECT</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold">Verified Action Contracts</h2>
            <p className={`text-xs mt-1 ${textMuted}`}>
              Full lifecycle contracts with idempotency keys, spending ceilings, external UNKNOWN status verification probes, and compensation rollback.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={onRefresh}
              className={`p-2 rounded-xl border text-xs font-medium hover:bg-slate-800 transition-colors ${borderSubtle}`}
              title="Refresh Contracts"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                setExecForm((prev) => ({
                  ...prev,
                  contract_id: contracts[0]?.contract_id || '',
                  idempotency_key: `idemp-${Date.now()}`,
                }));
                setShowExecuteModal(true);
              }}
              className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-xs"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute Action</span>
            </button>
            <button
              onClick={() => setShowNewModal(true)}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold flex items-center space-x-1.5 border border-slate-700 transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Contract</span>
            </button>
          </div>
        </div>

        {/* Lifecycle Explanation Ribbon */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px] font-mono">
          <span className="text-slate-400 font-semibold">Lifecycle Flow:</span>
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">PREPARED</span>
          <span className="text-slate-500">→</span>
          <span className="px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300">AUTHORIZED</span>
          <span className="text-slate-500">→</span>
          <span className="px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300">EXECUTING</span>
          <span className="text-slate-500">→</span>
          <span className="px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300">SUCCEEDED</span>
          <span className="text-slate-500">/</span>
          <span className="px-1.5 py-0.5 rounded bg-rose-900/60 text-rose-300">FAILED</span>
          <span className="text-slate-500">/</span>
          <span className="px-1.5 py-0.5 rounded bg-amber-900/60 text-amber-300">UNKNOWN (Probe Required)</span>
          <span className="text-slate-500">→</span>
          <span className="px-1.5 py-0.5 rounded bg-purple-900/60 text-purple-300">COMPENSATED</span>
        </div>
      </div>

      {/* Contracts Table */}
      <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-sm flex items-center space-x-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>Active Action Contracts ({contracts.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Deterministic Enforcement</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 ${bgSubtle}`}>
              <tr>
                <th className="py-2.5 px-4">Contract ID</th>
                <th className="py-2.5 px-4">Permitted Action</th>
                <th className="py-2.5 px-4">Target Resource</th>
                <th className="py-2.5 px-4">Spending Ceiling</th>
                <th className="py-2.5 px-4">Invariants</th>
                <th className="py-2.5 px-4">Compensation</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {contracts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 font-sans">
                    No action contracts configured. Click &ldquo;New Contract&rdquo; to define one.
                  </td>
                </tr>
              ) : (
                contracts.map((c) => (
                  <tr key={c.contract_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyan-300">{c.contract_id}</td>
                    <td className="py-3 px-4 font-semibold text-slate-200">{c.action_capability || c.permitted_action}</td>
                    <td className="py-3 px-4 text-slate-300">{c.target_resource}</td>
                    <td className="py-3 px-4 text-emerald-400 font-bold">
                      {c.auth_limit?.spending_ceiling ? `$${c.auth_limit.spending_ceiling}` : 'Unlimited'}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {c.applicable_invariants?.map((inv) => (
                        <span key={inv} className="inline-block mr-1 px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                          {inv}
                        </span>
                      ))}
                    </td>
                    <td className="py-3 px-4">
                      {c.compensation_supported ? (
                        <span className="text-purple-400 flex items-center space-x-1 font-sans text-xs">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Supported</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 font-sans text-xs">None</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => {
                          setExecForm((prev) => ({
                            ...prev,
                            contract_id: c.contract_id,
                            idempotency_key: `idemp-${Date.now()}`,
                          }));
                          setShowExecuteModal(true);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-cyan-900/40 hover:bg-cyan-800/60 text-cyan-300 border border-cyan-700/50 text-[10px] font-bold transition-colors"
                      >
                        Execute
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Execution Lifecycle Audit Table */}
      <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-sm flex items-center space-x-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Contract Execution Ledger & Lifecycle State ({executions.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Idempotency & External Verification Probes</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 ${bgSubtle}`}>
              <tr>
                <th className="py-2.5 px-4">Execution ID</th>
                <th className="py-2.5 px-4">Contract</th>
                <th className="py-2.5 px-4">Idempotency Key</th>
                <th className="py-2.5 px-4">Lifecycle State</th>
                <th className="py-2.5 px-4">External Verification</th>
                <th className="py-2.5 px-4">Receipt</th>
                <th className="py-2.5 px-4 text-right">Recovery Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {executions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400 font-sans">
                    No executions recorded yet. Execute an action contract above to view real-time lifecycle transitions.
                  </td>
                </tr>
              ) : (
                executions.map((e) => (
                  <tr key={e.execution_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-slate-200">{e.execution_id}</td>
                    <td className="py-3 px-4 text-cyan-300">{e.contract_id}</td>
                    <td className="py-3 px-4 text-slate-400 truncate max-w-[150px]">{e.idempotency_key}</td>
                    <td className="py-3 px-4">{getStateBadge(e.state)}</td>
                    <td className="py-3 px-4">
                      {e.state === 'UNKNOWN' ? (
                        <span className="text-amber-400 font-bold flex items-center space-x-1">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>Probe Required</span>
                        </span>
                      ) : e.external_status_verified ? (
                        <span className="text-emerald-400 flex items-center space-x-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Probed & Verified</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 font-sans text-xs">Standard</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {e.receipt_id || e.receipt?.receipt_id ? (
                        <span className="text-cyan-400 font-bold flex items-center space-x-1">
                          <FileCheck className="w-3.5 h-3.5" />
                          <span>{e.receipt_id || e.receipt?.receipt_id}</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 font-sans text-xs">None</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right space-x-1.5">
                      {e.state === 'UNKNOWN' && (
                        <button
                          onClick={() => handleProbeExternal(e.execution_id)}
                          disabled={probingId === e.execution_id}
                          className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-[10px] font-bold transition-colors inline-flex items-center space-x-1"
                        >
                          <Search className="w-3 h-3" />
                          <span>{probingId === e.execution_id ? 'Probing...' : 'Probe External Status'}</span>
                        </button>
                      )}
                      {(e.state === 'SUCCEEDED' || e.state === 'FAILED') && e.compensation_supported && (
                        <button
                          onClick={() => handleCompensate(e.execution_id)}
                          disabled={compensatingId === e.execution_id}
                          className="px-2 py-1 rounded bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 text-[10px] font-bold transition-colors inline-flex items-center space-x-1"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>{compensatingId === e.execution_id ? 'Rolling back...' : 'Compensate'}</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Execution Modal */}
      {showExecuteModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Execute Verified Action Contract</h3>
            <p className={`text-xs ${textMuted}`}>
              Execute through CCK Action Gate with strict idempotency verification and invariant checks.
            </p>

            <form onSubmit={handleExecuteContract} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Contract</label>
                <select
                  value={execForm.contract_id}
                  onChange={(e) => setExecForm({ ...execForm, contract_id: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                >
                  <option value="">Select Contract</option>
                  {contracts.map((c) => (
                    <option key={c.contract_id} value={c.contract_id}>
                      {c.contract_id} ({c.action_capability || c.permitted_action} → {c.target_resource})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Idempotency Key</label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={execForm.idempotency_key}
                    onChange={(e) => setExecForm({ ...execForm, idempotency_key: e.target.value })}
                    className={`flex-1 px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setExecForm({ ...execForm, idempotency_key: `idemp-${Date.now()}` })}
                    className={`px-2 py-2 rounded-xl border text-[11px] ${borderSubtle}`}
                    title="Generate Fresh Key"
                  >
                    Fresh
                  </button>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  Reusing an idempotency key safely replays the previous verdict with zero duplicate mutation.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Entity / Order ID</label>
                  <input
                    type="text"
                    value={execForm.order_id}
                    onChange={(e) => setExecForm({ ...execForm, order_id: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Amount ($ USD)</label>
                  <input
                    type="number"
                    value={execForm.amount}
                    onChange={(e) => setExecForm({ ...execForm, amount: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800">
                <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={execForm.simulate_unknown}
                    onChange={(e) => setExecForm({ ...execForm, simulate_unknown: e.target.checked })}
                    className="rounded border-slate-700 text-cyan-500"
                  />
                  <span>Simulate network timeout (produce UNKNOWN state requiring external probe)</span>
                </label>
              </div>

              {actionResult && (
                <div
                  className={`p-3 rounded-xl border text-xs font-mono ${
                    actionResult.status === 200 || actionResult.status === 202
                      ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
                  }`}
                >
                  <div className="font-bold flex items-center justify-between">
                    <span>HTTP {actionResult.status}</span>
                    <span>State: {actionResult.data.state || 'PROCESSED'}</span>
                  </div>
                  {actionResult.data.idempotency_replayed && (
                    <div className="text-amber-400 text-[11px] font-sans mt-1">
                      Idempotency matched! Replayed previous result without duplicate external execution.
                    </div>
                  )}
                  {actionResult.data.reason && (
                    <div className="text-[11px] font-sans mt-1 text-slate-300">{actionResult.data.reason}</div>
                  )}
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowExecuteModal(false)}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle}`}
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={executing}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  {executing ? 'Executing...' : 'Dispatch Execution'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Contract Modal */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Create Action Contract (EFFECT)</h3>
            <form onSubmit={handleCreateContract} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Agent ID</label>
                <input
                  type="text"
                  value={newForm.agent_id}
                  onChange={(e) => setNewForm({ ...newForm, agent_id: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Permitted Action</label>
                  <input
                    type="text"
                    value={newForm.permitted_action}
                    onChange={(e) => setNewForm({ ...newForm, permitted_action: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Target Resource</label>
                  <input
                    type="text"
                    value={newForm.target_resource}
                    onChange={(e) => setNewForm({ ...newForm, target_resource: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Spending Ceiling ($)</label>
                <input
                  type="number"
                  value={newForm.spending_ceiling}
                  onChange={(e) => setNewForm({ ...newForm, spending_ceiling: Number(e.target.value) })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Required Evidence (Comma-separated)</label>
                <input
                  type="text"
                  value={newForm.required_evidence}
                  onChange={(e) => setNewForm({ ...newForm, required_evidence: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Applicable Invariants</label>
                <input
                  type="text"
                  value={newForm.applicable_invariants}
                  onChange={(e) => setNewForm({ ...newForm, applicable_invariants: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div>
                <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newForm.compensation_supported}
                    onChange={(e) => setNewForm({ ...newForm, compensation_supported: e.target.checked })}
                    className="rounded border-slate-700 text-cyan-500"
                  />
                  <span>Compensation / Rollback Supported by Target System</span>
                </label>
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  Create Contract
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
