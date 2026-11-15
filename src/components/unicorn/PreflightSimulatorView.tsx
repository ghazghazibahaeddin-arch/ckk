import React, { useEffect, useState } from 'react';
import { Play, ShieldAlert, DollarSign, GitCompare, PlusCircle, CheckCircle2, ArrowRight, RefreshCw } from 'lucide-react';
import type { SimulationRunRecord } from '../../assurance/unicorn_engine';

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  agents: Array<{ agent_id: string; name: string }>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
  onPolicyPromoted?: () => void;
}

export const PreflightSimulatorView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  agents,
  onNotification,
  onPolicyPromoted,
}) => {
  const fetcher = apiFetch || fetch;
  const [runs, setRuns] = useState<SimulationRunRecord[]>([]);
  const [activeRun, setActiveRun] = useState<SimulationRunRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  // Override Configuration
  const [simName, setSimName] = useState('Pre-Deploy Financial & Drift What-If');
  const [maxAmountUsd, setMaxAmountUsd] = useState<string>('200');
  const [blockedCaps, setBlockedCaps] = useState<string>('shell.exec, payments.wire');
  const [blockedTargets, setBlockedTargets] = useState<string>('api.unverified-vendor.io');
  const [driftedEntities, setDriftedEntities] = useState<string>('order:1099');
  const [strictPrompt, setStrictPrompt] = useState(true);
  const [strictSsrf, setStrictSsrf] = useState(true);

  // Candidate scenario actions included automatically so empty workspaces see immediate counterfactual diffs
  const [candidateCapability, setCandidateCapability] = useState('payments.transfer');
  const [candidateTarget, setCandidateTarget] = useState('api.stripe.com');
  const [candidateAmount, setCandidateAmount] = useState('450');
  const [candidateCommand, setCandidateCommand] = useState('transfer 450 USD for order:1099');

  const cardCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-xs';
  const subCls = isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';

  const loadRuns = async () => {
    setLoading(true);
    try {
      const res = await fetcher('/api/v1/simulator/runs');
      if (res.ok) {
        const data: SimulationRunRecord[] = await res.json();
        setRuns(data);
        if (data.length > 0 && !activeRun) setActiveRun(data[0]);
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRuns();
  }, [tenantId]);

  const handleRunSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    setRunning(true);
    try {
      const overrides = {
        max_amount_usd: Number(maxAmountUsd) > 0 ? Number(maxAmountUsd) : undefined,
        blocked_capabilities: blockedCaps
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        blocked_targets: blockedTargets
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        simulated_drifted_entities: driftedEntities
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        enforce_strict_prompt_guard: strictPrompt,
        enforce_ssrf_guard: strictSsrf,
      };

      const candidateActions = [
        {
          action_id: 'cand-custom-1',
          agent_id: agents[0]?.agent_id || 'agt-sim',
          capability: candidateCapability,
          target: candidateTarget,
          entity_id: 'order:1099',
          command: candidateCommand,
          amount_usd: Number(candidateAmount) || 0,
          baseline_decision: 'ALLOW',
        },
        {
          action_id: 'cand-safe-read',
          agent_id: agents[0]?.agent_id || 'agt-sim',
          capability: 'orders.read',
          target: 'db.orders.readonly',
          entity_id: 'order:5021',
          command: 'read order:5021 status',
          amount_usd: 0,
          baseline_decision: 'ALLOW',
        },
        {
          action_id: 'cand-high-wire',
          agent_id: agents[0]?.agent_id || 'agt-sim',
          capability: 'payments.wire',
          target: 'api.unverified-vendor.io',
          entity_id: 'inv:8890',
          command: 'wire 2500 USD to external treasury',
          amount_usd: 2500,
          baseline_decision: 'ALLOW',
        },
      ];

      const res = await fetcher('/api/v1/simulator/preflight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: simName,
          tenant_id: tenantId,
          overrides,
          candidate_actions: candidateActions,
        }),
      });
      if (res.ok) {
        const result: SimulationRunRecord = await res.json();
        setActiveRun(result);
        setRuns((prev) => [result, ...prev]);
        onNotification(
          `Simulation completed: ${result.summary.flipped_to_block} risky actions caught ($${result.summary.blast_radius_usd_saved.toLocaleString()} protected).`,
          'success'
        );
      } else {
        onNotification('Failed to execute pre-flight simulation.', 'error');
      }
    } catch {
      onNotification('Network error running pre-flight simulation.', 'error');
    } finally {
      setRunning(false);
    }
  };

  const handlePromoteCeilingRule = async () => {
    const cap = Number(maxAmountUsd);
    if (!cap || cap <= 0) return;
    try {
      const res = await fetcher('/api/v1/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Sim-Promoted Ceiling ($${cap})`,
          description: `Promoted directly from Pre-Flight Time-Machine simulation (${activeRun?.sim_id || 'dry-run'})`,
          capability_pattern: candidateCapability || '*',
          target_pattern: '*',
          action_effect: 'BLOCK',
          rollout_mode: 'ENFORCE',
          max_amount_usd: cap,
          risk_level: 'HIGH',
        }),
      });
      if (res.ok) {
        onNotification(`Promoted $${cap} Policy Ceiling to Live Production Firewall.`, 'success');
        onPolicyPromoted?.();
      } else {
        onNotification('Could not promote policy rule.', 'error');
      }
    } catch {
      onNotification('Error promoting policy rule.', 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-cyan-400" />
            <span>Pre-Flight Time-Machine &amp; Blast-Radius Simulator</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            اختبر أي سياسة جديدة أو تدهور في الحقائق على قراراتك التاريخية وعمليات الوكيل المرشحة قبل النشر الفعلي — دون أي آثار جانبية.
          </p>
        </div>
        <button
          onClick={loadRuns}
          className="px-3 py-2 rounded-xl border border-slate-700 hover:bg-slate-800 text-xs font-medium flex items-center gap-1.5 whitespace-nowrap shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>تحديث السجل</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Counterfactual Configuration Form */}
        <form onSubmit={handleRunSimulation} className={`lg:col-span-5 p-5 rounded-2xl border space-y-4 ${cardCls}`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold">إعدادات المحاكاة الافتراضية (What-If)</h3>
            <span className="text-[11px] font-mono text-cyan-400">Zero Side-Effects</span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block font-medium text-slate-400 mb-1">اسم السيناريو</label>
              <input
                type="text"
                value={simName}
                onChange={(e) => setSimName(e.target.value)}
                className={`w-full px-3 py-2 rounded-xl border focus:outline-hidden ${inputCls}`}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block font-medium text-slate-400 mb-1">سقف المبلغ الأقصى ($ USD)</label>
                <input
                  type="number"
                  min={0}
                  value={maxAmountUsd}
                  onChange={(e) => setMaxAmountUsd(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl border font-mono focus:outline-hidden ${inputCls}`}
                />
              </div>
              <div>
                <label className="block font-medium text-slate-400 mb-1">كيانات محاكاة التدهور (Drift)</label>
                <input
                  type="text"
                  value={driftedEntities}
                  onChange={(e) => setDriftedEntities(e.target.value)}
                  placeholder="order:1099"
                  className={`w-full px-3 py-2 rounded-xl border font-mono focus:outline-hidden ${inputCls}`}
                />
              </div>
            </div>

            <div>
              <label className="block font-medium text-slate-400 mb-1">صلاحيات محظورة افتراضياً (Capabilities)</label>
              <input
                type="text"
                value={blockedCaps}
                onChange={(e) => setBlockedCaps(e.target.value)}
                className={`w-full px-3 py-2 rounded-xl border font-mono focus:outline-hidden ${inputCls}`}
              />
            </div>

            <div>
              <label className="block font-medium text-slate-400 mb-1">أهداف/واجهات محظورة (Targets)</label>
              <input
                type="text"
                value={blockedTargets}
                onChange={(e) => setBlockedTargets(e.target.value)}
                className={`w-full px-3 py-2 rounded-xl border font-mono focus:outline-hidden ${inputCls}`}
              />
            </div>

            <div className="flex flex-wrap gap-4 pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={strictPrompt} onChange={(e) => setStrictPrompt(e.target.checked)} className="rounded" />
                <span>تشديد حارس Prompt Injection</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={strictSsrf} onChange={(e) => setStrictSsrf(e.target.checked)} className="rounded" />
                <span>حارس SSRF للمنافذ الداخلية</span>
              </label>
            </div>

            <div className={`p-3 rounded-xl border space-y-2.5 ${subCls}`}>
              <div className="font-semibold text-[11px] text-slate-300">عملية وكيل مرشحة للاختبار (Candidate Action)</div>
              <div className="grid grid-cols-2 gap-2">
                <input
                  type="text"
                  value={candidateCapability}
                  onChange={(e) => setCandidateCapability(e.target.value)}
                  placeholder="capability"
                  className={`px-2.5 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                />
                <input
                  type="text"
                  value={candidateTarget}
                  onChange={(e) => setCandidateTarget(e.target.value)}
                  placeholder="target"
                  className={`px-2.5 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                />
              </div>
              <div className="grid grid-cols-3 gap-2">
                <input
                  type="number"
                  value={candidateAmount}
                  onChange={(e) => setCandidateAmount(e.target.value)}
                  placeholder="USD"
                  className={`px-2.5 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                />
                <input
                  type="text"
                  value={candidateCommand}
                  onChange={(e) => setCandidateCommand(e.target.value)}
                  placeholder="command"
                  className={`col-span-2 px-2.5 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              type="submit"
              disabled={running}
              className="flex-1 py-2.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{running ? 'جاري تشغيل المحاكاة...' : 'تشغيل المحاكاة (Dry-Run)'}</span>
            </button>
            <button
              type="button"
              onClick={handlePromoteCeilingRule}
              className="py-2.5 px-3.5 rounded-xl border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-300 font-semibold text-xs flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>اعتماد السقف كسياسة حية</span>
            </button>
          </div>
        </form>

        {/* Right: Blast-Radius Diff Results */}
        <div className={`lg:col-span-7 p-5 rounded-2xl border space-y-5 ${cardCls}`}>
          {loading ? (
            <div className="py-12 text-center text-xs text-slate-400 font-mono">Loading counterfactual simulations...</div>
          ) : !activeRun ? (
            <div className="py-12 text-center space-y-3">
              <GitCompare className="w-10 h-10 text-cyan-400/70 mx-auto" />
              <div className="text-sm font-semibold">لا توجد محاكاة مسجلة بعد</div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                اضغط "تشغيل المحاكاة (Dry-Run)" لقياس تأثير السياسات المقترحة وحساب المخاطر المالية التي يتم منعها قبل تطبيقها على الإنتاج.
              </p>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-bold">{activeRun.name}</h3>
                  <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                    {activeRun.sim_id} · {new Date(activeRun.created_at).toLocaleString()}
                  </div>
                </div>
                {runs.length > 1 && (
                  <select
                    value={activeRun.sim_id}
                    onChange={(e) => {
                      const found = runs.find((r) => r.sim_id === e.target.value);
                      if (found) setActiveRun(found);
                    }}
                    className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono ${inputCls}`}
                  >
                    {runs.map((r) => (
                      <option key={r.sim_id} value={r.sim_id}>
                        {r.sim_id} ({r.summary.flipped_to_block} flipped)
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* 4 KPI Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">إجمالي المختبر</div>
                  <div className="text-lg font-bold font-mono tabular-nums mt-1">{activeRun.summary.total_evaluated}</div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">تحول من ALLOW ← BLOCK</div>
                  <div className="text-lg font-bold font-mono tabular-nums text-amber-400 mt-1">
                    {activeRun.summary.flipped_to_block}
                  </div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">معدل الحظر المحاكى</div>
                  <div className="text-lg font-bold font-mono tabular-nums text-rose-400 mt-1">
                    {activeRun.summary.simulated_blocks} / {activeRun.summary.total_evaluated}
                  </div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400 flex items-center gap-1">
                    <DollarSign className="w-3 h-3 text-emerald-400" />
                    <span>مخاطر مالية محمية</span>
                  </div>
                  <div className="text-lg font-bold font-mono tabular-nums text-emerald-400 mt-1">
                    ${activeRun.summary.blast_radius_usd_saved.toLocaleString()}
                  </div>
                </div>
              </div>

              {/* Action Diff Table */}
              <div className="overflow-x-auto border border-slate-800 rounded-xl">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-mono text-[11px]">
                      <th className="py-2.5 px-3">Action / Capability</th>
                      <th className="py-2.5 px-3">Exposure</th>
                      <th className="py-2.5 px-3">Baseline → Simulated</th>
                      <th className="py-2.5 px-3">Triggered Policy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {activeRun.diffs.slice(0, 15).map((d) => (
                      <tr key={d.item_id} className={d.changed ? 'bg-amber-950/15' : 'hover:bg-slate-800/30'}>
                        <td className="py-2.5 px-3">
                          <div className="font-mono font-semibold text-slate-200">{d.capability}</div>
                          <div className="text-[11px] font-mono text-slate-400 truncate max-w-[200px]">{d.target}</div>
                        </td>
                        <td className="py-2.5 px-3 font-mono tabular-nums">
                          {d.amount_usd > 0 ? `$${d.amount_usd.toLocaleString()}` : '—'}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-1.5 font-mono text-[11px]">
                            <span className={d.baseline_decision === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'}>
                              {d.baseline_decision}
                            </span>
                            <ArrowRight className="w-3 h-3 text-slate-500" />
                            <span className={d.simulated_decision === 'ALLOW' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                              {d.simulated_decision}
                            </span>
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-1 font-mono text-[11px]">
                            {d.changed ? (
                              <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                            ) : (
                              <CheckCircle2 className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                            )}
                            <span className="truncate max-w-[190px]" title={d.reason}>
                              {d.triggered_rule}
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
