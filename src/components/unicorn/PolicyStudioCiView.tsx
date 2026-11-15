import React, { useEffect, useState } from 'react';
import { Shield, Plus, Trash2, GitPullRequest, Copy, CheckCircle2, AlertTriangle, Play } from 'lucide-react';
import type { CiGateCheckReport } from '../../assurance/unicorn_engine';

interface PolicyRuleItem {
  rule_id: string;
  tenant_id?: string;
  name: string;
  description: string;
  capability_pattern: string;
  target_pattern: string;
  action_effect: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  rollout_mode?: 'ENFORCE' | 'SHADOW';
  max_amount_usd?: number;
  blocked_keywords?: string[];
  risk_level: string;
  is_active: boolean;
  is_custom?: boolean;
}

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  agents: Array<{ agent_id: string; name: string }>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const PolicyStudioCiView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  agents,
  onNotification,
}) => {
  const fetcher = apiFetch || fetch;
  const [policies, setPolicies] = useState<PolicyRuleItem[]>([]);
  const [ciReport, setCiReport] = useState<CiGateCheckReport | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.agent_id || '');
  const [runningCi, setRunningCi] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);

  // Create Rule Form
  const [name, setName] = useState('Block High-Value Vendor Payouts');
  const [description, setDescription] = useState('Require human approval or block unverified vendor transfers over $500');
  const [capPattern, setCapPattern] = useState('payments.*');
  const [targetPattern, setTargetPattern] = useState('*');
  const [effect, setEffect] = useState<'BLOCK' | 'REQUIRE_APPROVAL'>('BLOCK');
  const [rolloutMode, setRolloutMode] = useState<'ENFORCE' | 'SHADOW'>('ENFORCE');
  const [maxAmountUsd, setMaxAmountUsd] = useState('500');
  const [blockedKeywords, setBlockedKeywords] = useState('');

  // Quick Firewall Test
  const [testCap, setTestCap] = useState('payments.transfer');
  const [testTarget, setTestTarget] = useState('api.vendor.io');
  const [testAmount, setTestAmount] = useState('750');
  const [testResult, setTestResult] = useState<any>(null);

  const cardCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-xs';
  const subCls = isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';

  const loadData = async () => {
    try {
      const [polRes, ciRes] = await Promise.all([
        fetcher('/api/v1/policies'),
        fetcher('/api/v1/ci/reports'),
      ]);
      if (polRes.ok) setPolicies(await polRes.json());
      if (ciRes.ok) {
        const reports: CiGateCheckReport[] = await ciRes.json();
        if (reports.length > 0 && !ciReport) setCiReport(reports[0]);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadData();
  }, [tenantId]);

  useEffect(() => {
    if (!selectedAgentId && agents.length > 0) setSelectedAgentId(agents[0].agent_id);
  }, [agents, selectedAgentId]);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: tenantId,
          name,
          description,
          capability_pattern: capPattern,
          target_pattern: targetPattern,
          action_effect: effect,
          rollout_mode: rolloutMode,
          max_amount_usd: Number(maxAmountUsd) > 0 ? Number(maxAmountUsd) : undefined,
          blocked_keywords: blockedKeywords,
          risk_level: 'HIGH',
        }),
      });
      if (res.ok) {
        onNotification('Custom Firewall Policy created and synced with Action Gate.', 'success');
        loadData();
      } else {
        onNotification('Failed to create custom policy rule.', 'error');
      }
    } catch {
      onNotification('Error creating policy rule.', 'error');
    }
  };

  const handleToggleRule = async (rule: PolicyRuleItem, patch: Partial<PolicyRuleItem>) => {
    try {
      const res = await fetcher(`/api/v1/policies/${rule.rule_id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      if (res.ok) {
        loadData();
      }
    } catch {
      onNotification('Failed to update policy rule.', 'error');
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    try {
      const res = await fetcher(`/api/v1/policies/${ruleId}`, { method: 'DELETE' });
      if (res.ok) {
        onNotification('Custom policy deleted.', 'info');
        loadData();
      }
    } catch {
      onNotification('Failed to delete policy.', 'error');
    }
  };

  const handleTestFirewall = async () => {
    try {
      const res = await fetcher('/api/v1/gate/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent: selectedAgentId || agents[0]?.agent_id || 'agt-console',
          tenant_id: tenantId,
          capability: testCap,
          target: testTarget,
          amount_usd: Number(testAmount) || 0,
          command: `execute ${testCap} $${testAmount} on ${testTarget}`,
          parameters: { amount_usd: Number(testAmount) || 0 },
        }),
      });
      if (res.ok) setTestResult(await res.json());
    } catch {
      onNotification('Firewall test failed.', 'error');
    }
  };

  const handleRunCiGate = async () => {
    setRunningCi(true);
    try {
      const res = await fetcher('/api/v1/ci/gate-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: tenantId,
          agent_id: selectedAgentId || agents[0]?.agent_id,
          origin: typeof window !== 'undefined' ? window.location.origin : '',
        }),
      });
      if (res.ok) {
        const report: CiGateCheckReport = await res.json();
        setCiReport(report);
        onNotification(`CI/CD Release Gate completed: ${report.status}`, report.status === 'PASS' ? 'success' : 'error');
      }
    } catch {
      onNotification('Error running CI/CD release gate.', 'error');
    } finally {
      setRunningCi(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span>Programmable Policy Firewall &amp; CI/CD Release Gate</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          أنشئ قواعد جدار حماية برمجية لوكلائك (مع وضع Shadow Canary قبل الإلزام)، وادمج بوابة الفحص التلقائي في GitHub Actions قبل كل نشر برمجي.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Rule Studio */}
        <form onSubmit={handleCreateRule} className={`lg:col-span-5 p-5 rounded-2xl border space-y-3 text-xs ${cardCls}`}>
          <h3 className="text-sm font-bold">إنشاء قاعدة جدار حماية جديدة (Policy Rule)</h3>

          <div>
            <label className="block text-slate-400 mb-1">اسم القاعدة</label>
            <input type="text" required value={name} onChange={(e) => setName(e.target.value)} className={`w-full px-3 py-2 rounded-xl border ${inputCls}`} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">نمط الصلاحية (Wildcard)</label>
              <input type="text" required value={capPattern} onChange={(e) => setCapPattern(e.target.value)} className={`w-full px-3 py-2 rounded-xl border font-mono ${inputCls}`} />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">نمط الهدف (Target)</label>
              <input type="text" value={targetPattern} onChange={(e) => setTargetPattern(e.target.value)} className={`w-full px-3 py-2 rounded-xl border font-mono ${inputCls}`} />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">الإجراء</label>
              <select value={effect} onChange={(e) => setEffect(e.target.value as any)} className={`w-full px-2.5 py-2 rounded-xl border font-mono ${inputCls}`}>
                <option value="BLOCK">BLOCK</option>
                <option value="REQUIRE_APPROVAL">APPROVAL</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">الوضع</label>
              <select value={rolloutMode} onChange={(e) => setRolloutMode(e.target.value as any)} className={`w-full px-2.5 py-2 rounded-xl border font-mono ${inputCls}`}>
                <option value="ENFORCE">ENFORCE</option>
                <option value="SHADOW">SHADOW</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">الحد ($ USD)</label>
              <input type="number" min={0} value={maxAmountUsd} onChange={(e) => setMaxAmountUsd(e.target.value)} className={`w-full px-2.5 py-2 rounded-xl border font-mono ${inputCls}`} />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">كلمات محظورة إضافية (اختياري، مفصولة بفاصلة)</label>
            <input type="text" value={blockedKeywords} onChange={(e) => setBlockedKeywords(e.target.value)} placeholder="drop table, offshore" className={`w-full px-3 py-2 rounded-xl border font-mono ${inputCls}`} />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">الوصف</label>
            <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} className={`w-full px-3 py-2 rounded-xl border ${inputCls}`} />
          </div>

          <button type="submit" className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5">
            <Plus className="w-4 h-4" />
            <span>إضافة القاعدة إلى بوابة القرار</span>
          </button>

          {/* Live Firewall Sandbox Tester */}
          <div className={`p-3.5 rounded-xl border space-y-2.5 mt-3 ${subCls}`}>
            <div className="font-semibold text-[11px] text-slate-300">اختبار فوري ضد القواعد النشطة</div>
            <div className="grid grid-cols-3 gap-2">
              <input type="text" value={testCap} onChange={(e) => setTestCap(e.target.value)} className={`px-2 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`} />
              <input type="text" value={testTarget} onChange={(e) => setTestTarget(e.target.value)} className={`px-2 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`} />
              <input type="number" value={testAmount} onChange={(e) => setTestAmount(e.target.value)} className={`px-2 py-1.5 rounded-lg border font-mono text-[11px] ${inputCls}`} />
            </div>
            <button type="button" onClick={handleTestFirewall} className="w-full py-1.5 rounded-lg border border-cyan-500/40 text-cyan-300 hover:bg-cyan-950/40 font-semibold text-xs">
              فحص الآن عبر Action Gate
            </button>
            {testResult && (
              <div className="text-[11px] font-mono pt-1">
                <span className={testResult.decision === 'ALLOW' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                  {testResult.decision}
                </span>
                <span className="text-slate-400 ml-2">{testResult.reason}</span>
              </div>
            )}
          </div>
        </form>

        {/* Right: Active Rules List */}
        <div className={`lg:col-span-7 p-5 rounded-2xl border space-y-3 ${cardCls}`}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold">القواعد النشطة في مساحة عملك ({policies.length})</h3>
            <span className="text-[11px] font-mono text-slate-400">ENFORCE / SHADOW Canary</span>
          </div>

          <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-1">
            {policies.map((rule) => (
              <div key={rule.rule_id} className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${subCls}`}>
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-mono font-bold text-cyan-300">{rule.rule_id}</span>
                    <span className="font-bold">{rule.name}</span>
                    {rule.is_custom && (
                      <span className="text-[10px] font-mono text-indigo-300">Custom Rule</span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    Capability: {rule.capability_pattern} · Target: {rule.target_pattern}
                    {rule.max_amount_usd ? ` · Max $${rule.max_amount_usd}` : ''}
                    {' · '}Effect: {rule.action_effect}
                  </div>
                  <div className="text-xs text-slate-400">{rule.description}</div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {rule.is_custom && (
                    <button
                      onClick={() =>
                        handleToggleRule(rule, {
                          rollout_mode: rule.rollout_mode === 'SHADOW' ? 'ENFORCE' : 'SHADOW',
                        })
                      }
                      className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono ${
                        rule.rollout_mode === 'SHADOW'
                          ? 'border-amber-500/40 text-amber-300'
                          : 'border-emerald-500/40 text-emerald-300'
                      }`}
                    >
                      {rule.rollout_mode || 'ENFORCE'}
                    </button>
                  )}
                  <button
                    onClick={() => handleToggleRule(rule, { is_active: !rule.is_active })}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono ${
                      rule.is_active ? 'border-cyan-500/40 text-cyan-300' : 'border-slate-700 text-slate-500'
                    }`}
                  >
                    {rule.is_active ? 'ACTIVE' : 'PAUSED'}
                  </button>
                  {rule.is_custom && (
                    <button
                      onClick={() => handleDeleteRule(rule.rule_id)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400"
                      title="Delete rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CI/CD Pre-Deploy Release Gate */}
      <div className={`p-5 rounded-2xl border space-y-4 ${cardCls}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold flex items-center gap-2">
              <GitPullRequest className="w-4 h-4 text-emerald-400" />
              <span>CI/CD Agent Release Gate (GitHub Actions Integration)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              امنع نشر أي نسخة وكيل إذا كان هناك Kill Switch نشط أو حوادث حرجة غير محلولة أو مهارات غير موثقة.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {agents.length > 0 && (
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                className={`px-3 py-2 rounded-xl border text-xs font-mono ${inputCls}`}
              >
                {agents.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.name}
                  </option>
                ))}
              </select>
            )}
            <button
              onClick={handleRunCiGate}
              disabled={runningCi}
              className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{runningCi ? 'جاري الفحص...' : 'تشغيل فحص CI Gate الآن'}</span>
            </button>
          </div>
        </div>

        {ciReport && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
            <div className={`p-4 rounded-xl border space-y-2.5 ${subCls}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">
                  Agent: {ciReport.agent_name} · {ciReport.report_id}
                </span>
                <span
                  className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-lg ${
                    ciReport.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                  }`}
                >
                  CI STATUS: {ciReport.status}
                </span>
              </div>

              <div className="space-y-2">
                {ciReport.checks.map((c) => (
                  <div key={c.check_id} className="flex items-start gap-2 text-xs">
                    {c.status === 'PASS' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    )}
                    <div>
                      <div className="font-semibold">
                        {c.title} <span className="font-mono text-[11px] text-slate-400">({c.status})</span>
                      </div>
                      <div className="text-[11px] text-slate-400">{c.details}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className={`p-4 rounded-xl border space-y-2 ${subCls}`}>
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono font-semibold text-slate-300">.github/workflows/cck-gate.yml</span>
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(ciReport.github_actions_yaml);
                    setCopiedYaml(true);
                    setTimeout(() => setCopiedYaml(false), 2000);
                  }}
                  className="px-2.5 py-1 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copiedYaml ? 'تم النسخ!' : 'نسخ YAML'}</span>
                </button>
              </div>
              <pre className="text-[11px] font-mono text-cyan-200 overflow-x-auto leading-relaxed">
                {ciReport.github_actions_yaml}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
