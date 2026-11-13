import React, { useState } from 'react';
import {
  Wallet,
  ShieldAlert,
  Plus,
  RefreshCw,
  Calculator,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Sparkles,
  Zap,
} from 'lucide-react';
import type { BudgetPolicyRecord, CostEstimate } from '../../governance/types';

interface BudgetGuardViewProps {
  budgets: BudgetPolicyRecord[];
  onRefresh: () => void;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const BudgetGuardView: React.FC<BudgetGuardViewProps> = ({
  budgets,
  onRefresh,
  tenantId,
  apiFetch,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [estimating, setEstimating] = useState(false);
  const [estimateResult, setEstimateResult] = useState<CostEstimate | null>(null);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Estimator Form
  const [estForm, setEstForm] = useState({
    model_id: 'gemini-1.5-flash',
    input_tokens: 15000,
    output_tokens: 3000,
    tool_calls: 3,
  });

  // Create Budget Form
  const [createForm, setCreateForm] = useState({
    scope_type: 'AGENT' as 'TENANT' | 'AGENT' | 'TASK',
    scope_id: 'agt-billing-worker',
    max_budget_usd: 50.0,
    max_model_calls: 2000,
    max_tool_calls: 4000,
    max_retries: 3,
    max_delegation_depth: 3,
    max_execution_timeout_ms: 30000,
    max_concurrent_runs: 5,
  });

  const handleEstimate = async (e: React.FormEvent) => {
    e.preventDefault();
    setEstimating(true);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher('/api/v1/budgets/estimate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model_id: estForm.model_id,
          estimated_input_tokens: Number(estForm.input_tokens),
          estimated_output_tokens: Number(estForm.output_tokens),
          tool_calls_count: Number(estForm.tool_calls),
        }),
      });
      const data = await res.json();
      setEstimateResult(data.estimate);
    } catch {
      setEstimateResult(null);
    } finally {
      setEstimating(false);
    }
  };

  const handleCreateBudget = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionMsg(null);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher('/api/v1/budgets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: tenantId || 'tenant_default',
          scope_type: createForm.scope_type,
          scope_id: createForm.scope_id,
          limits: {
            max_budget_usd: Number(createForm.max_budget_usd),
            max_model_calls: Number(createForm.max_model_calls),
            max_tool_calls: Number(createForm.max_tool_calls),
            max_retries: Number(createForm.max_retries),
            max_delegation_depth: Number(createForm.max_delegation_depth),
            max_execution_timeout_ms: Number(createForm.max_execution_timeout_ms),
            max_concurrent_runs: Number(createForm.max_concurrent_runs),
          },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create budget');
      setActionMsg({ type: 'success', text: `Budget policy ${data.budget.budget_id} configured.` });
      setShowCreateModal(false);
      onRefresh();
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleResetBudget = async (budgetId: string) => {
    setActionMsg(null);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/budgets/${budgetId}/reset`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to reset budget');
      setActionMsg({ type: 'success', text: `Budget ${budgetId} reset to 0 spent and restored to ACTIVE.` });
      onRefresh();
    } catch (err: any) {
      setActionMsg({ type: 'error', text: err.message });
    }
  };

  const totalSpent = budgets.reduce((acc, b) => acc + (b.usage?.spent_usd || 0), 0);
  const totalBudgetCap = budgets.reduce((acc, b) => acc + (b.limits?.max_budget_usd || 0), 0);
  const activeCount = budgets.filter((b) => b.status === 'ACTIVE').length;
  const haltedCount = budgets.filter((b) => b.status === 'HALTED' || b.status === 'EXHAUSTED').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Wallet className="w-5 h-5 text-amber-400" />
            Runtime Budget Guard — Denial-of-Wallet Protection
          </h2>
          <p className={`text-sm ${textMuted} mt-1`}>
            Autonomous multi-model cost containment, pre-call expenditure estimation, and hard dispatch halts.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className={`p-2 rounded-lg border ${borderSubtle} hover:${bgSubtle} transition-colors`}
            title="Refresh budgets"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 bg-amber-600 hover:bg-amber-700 text-white font-medium rounded-lg text-sm transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Set Budget Policy
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
          <div className="text-xs text-muted-foreground uppercase font-semibold">Total Spent (USD)</div>
          <div className="text-2xl font-bold mt-1 text-zinc-100">${totalSpent.toFixed(4)}</div>
          <div className="text-xs text-muted-foreground mt-1">Across all scopes</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Total Ceiling Cap</div>
          <div className="text-2xl font-bold mt-1 text-amber-400">${totalBudgetCap.toFixed(2)}</div>
          <div className="text-xs text-muted-foreground mt-1">Hard limit sum</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Active Policies</div>
          <div className="text-2xl font-bold mt-1 text-emerald-400">{activeCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Under strict governance</div>
        </div>
        <div className={`p-4 rounded-xl border ${borderSubtle} ${bgCard}`}>
          <div className="text-xs text-muted-foreground uppercase font-semibold">Halted / Exhausted</div>
          <div className="text-2xl font-bold mt-1 text-rose-400">{haltedCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Denial-of-wallet active</div>
        </div>
      </div>

      {/* Main Content: Budgets List & Pre-Call Cost Calculator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Budgets List */}
        <div className={`lg:col-span-2 rounded-xl border ${borderSubtle} ${bgCard} p-5 space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Configured Budget Guard Policies
            </h3>
            <span className="text-xs text-muted-foreground">{budgets.length} policies</span>
          </div>

          <div className="space-y-3">
            {budgets.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">No budget policies found.</div>
            ) : (
              budgets.map((b) => {
                const spent = b.usage?.spent_usd || 0;
                const max = b.limits?.max_budget_usd || 1;
                const pct = Math.min(100, (spent / max) * 100);
                const isHalted = b.status === 'HALTED' || b.status === 'EXHAUSTED';

                return (
                  <div
                    key={b.budget_id}
                    className={`p-4 rounded-xl border transition-all ${
                      isHalted
                        ? 'bg-rose-950/20 border-rose-800/60'
                        : `bg-zinc-900/60 border-zinc-800 hover:${bgSubtle}`
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          {b.scope_type}: {b.scope_id}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">{b.budget_id}</span>
                      </div>
                      <div>
                        {isHalted ? (
                          <span className="flex items-center gap-1 text-xs font-bold text-rose-400">
                            <XCircle className="w-3.5 h-3.5" /> {b.status}
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs font-semibold text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVE
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div className="mt-3 space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground">Spent: ${spent.toFixed(4)}</span>
                        <span className="font-semibold text-zinc-300">
                          ${(max - spent).toFixed(4)} remaining of ${max.toFixed(2)}
                        </span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className={`h-full transition-all duration-300 ${
                            pct >= 90 ? 'bg-rose-500' : pct >= 70 ? 'bg-amber-500' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>

                    {/* Sub Counters */}
                    <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                      <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/80">
                        <div className="text-muted-foreground text-[11px]">Model Calls</div>
                        <div className="font-semibold mt-0.5">
                          {b.usage?.model_calls || 0} / {b.limits?.max_model_calls}
                        </div>
                      </div>
                      <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/80">
                        <div className="text-muted-foreground text-[11px]">Tool Calls</div>
                        <div className="font-semibold mt-0.5">
                          {b.usage?.tool_calls || 0} / {b.limits?.max_tool_calls}
                        </div>
                      </div>
                      <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/80">
                        <div className="text-muted-foreground text-[11px]">Timeout</div>
                        <div className="font-semibold mt-0.5">
                          {(b.limits?.max_execution_timeout_ms || 30000) / 1000}s max
                        </div>
                      </div>
                    </div>

                    {/* Halt Reason or Actions */}
                    <div className="mt-3 pt-2 border-t border-zinc-800/50 flex items-center justify-between">
                      {b.halt_reason ? (
                        <div className="text-xs text-rose-300 font-medium truncate max-w-[380px]">
                          Reason: {b.halt_reason}
                        </div>
                      ) : (
                        <div className="text-xs text-muted-foreground">Normal consumption pace.</div>
                      )}

                      <button
                        onClick={() => handleResetBudget(b.budget_id)}
                        className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 font-medium px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 transition-colors"
                      >
                        <RotateCcw className="w-3 h-3" /> Reset / Top Up
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Pre-Call Cost Calculator Panel */}
        <div className={`rounded-xl border ${borderSubtle} ${bgCard} p-5 space-y-4`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <Calculator className="w-4 h-4 text-amber-400" />
              Pre-Call Cost Estimator
            </h3>
            <span className="text-xs text-muted-foreground">Catalog V2</span>
          </div>
          <p className="text-xs text-muted-foreground">
            Calculate projected model & tool execution costs before dispatching requests to external foundation models.
          </p>

          <form onSubmit={handleEstimate} className="space-y-3 text-xs">
            <div>
              <label className="block text-muted-foreground mb-1">Target Model</label>
              <select
                value={estForm.model_id}
                onChange={(e) => setEstForm({ ...estForm, model_id: e.target.value })}
                className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
              >
                <option value="gemini-1.5-flash">Google Gemini 1.5 Flash ($0.075 / $0.30 per 1M)</option>
                <option value="gemini-2.0-flash">Google Gemini 2.0 Flash ($0.10 / $0.40 per 1M)</option>
                <option value="gemini-1.5-pro">Google Gemini 1.5 Pro ($1.25 / $5.00 per 1M)</option>
                <option value="gpt-4o">OpenAI GPT-4o ($2.50 / $10.00 per 1M)</option>
                <option value="gpt-4o-mini">OpenAI GPT-4o Mini ($0.15 / $0.60 per 1M)</option>
                <option value="claude-3-5-sonnet">Anthropic Claude 3.5 Sonnet ($3.00 / $15.00 per 1M)</option>
              </select>
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Estimated Input Tokens</label>
              <input
                type="number"
                value={estForm.input_tokens}
                onChange={(e) => setEstForm({ ...estForm, input_tokens: Number(e.target.value) })}
                className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Estimated Output Tokens</label>
              <input
                type="number"
                value={estForm.output_tokens}
                onChange={(e) => setEstForm({ ...estForm, output_tokens: Number(e.target.value) })}
                className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Tool Executions Count</label>
              <input
                type="number"
                value={estForm.tool_calls}
                onChange={(e) => setEstForm({ ...estForm, tool_calls: Number(e.target.value) })}
                className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
              />
            </div>

            <button
              type="submit"
              disabled={estimating}
              className="w-full py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5" />
              {estimating ? 'Calculating...' : 'Calculate Cost'}
            </button>
          </form>

          {estimateResult && (
            <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Model:</span>
                <span className="font-mono font-semibold">{estimateResult.model_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Projected Cost:</span>
                <span className="font-mono text-amber-400 font-bold text-sm">
                  ${estimateResult.estimated_cost_usd.toFixed(6)} USD
                </span>
              </div>
              <div className="text-[11px] text-zinc-500 pt-1 border-t border-zinc-800">
                Action Gate pre-checks this projected cost against remaining wallet limit prior to mutation dispatch.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Set Budget Policy */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className={`w-full max-w-lg rounded-xl border ${borderSubtle} ${bgCard} p-6 space-y-4`}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold">Configure Budget Policy</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted-foreground hover:text-white">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateBudget} className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Scope Type</label>
                  <select
                    value={createForm.scope_type}
                    onChange={(e) => setCreateForm({ ...createForm, scope_type: e.target.value as any })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  >
                    <option value="AGENT">Agent Scope</option>
                    <option value="TASK">Task Scope</option>
                    <option value="TENANT">Tenant Scope</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Scope Target ID</label>
                  <input
                    type="text"
                    required
                    value={createForm.scope_id}
                    onChange={(e) => setCreateForm({ ...createForm, scope_id: e.target.value })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max Budget Ceiling ($)</label>
                  <input
                    type="number"
                    step="0.01"
                    required
                    value={createForm.max_budget_usd}
                    onChange={(e) => setCreateForm({ ...createForm, max_budget_usd: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max Model Calls</label>
                  <input
                    type="number"
                    required
                    value={createForm.max_model_calls}
                    onChange={(e) => setCreateForm({ ...createForm, max_model_calls: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max Tool Calls</label>
                  <input
                    type="number"
                    value={createForm.max_tool_calls}
                    onChange={(e) => setCreateForm({ ...createForm, max_tool_calls: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Max Retries</label>
                  <input
                    type="number"
                    value={createForm.max_retries}
                    onChange={(e) => setCreateForm({ ...createForm, max_retries: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-lg border ${borderSubtle} ${bgSubtle}`}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Concurrent Runs</label>
                  <input
                    type="number"
                    value={createForm.max_concurrent_runs}
                    onChange={(e) => setCreateForm({ ...createForm, max_concurrent_runs: Number(e.target.value) })}
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
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
