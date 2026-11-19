import React, { useEffect, useState } from 'react';
import {
  GitCompare,
  RefreshCw,
  KeyRound,
  ShieldCheck,
  Globe,
  Activity,
  Lock,
  Plus,
  Play,
  Ban,
} from 'lucide-react';
import type {
  BehaviorDriftEventRecord,
  ConflictResolutionPolicy,
  DataClassificationRule,
  DataFlowEvaluationResult,
  DataFlowPolicyRecord,
  EgressDecisionReceipt,
  EphemeralSecretLease,
  FactSourceObservation,
  InvocationContextSnapshot,
  MultiSourceConflictEvaluation,
  NetworkEgressPolicyRecord,
  RevalidationPlanRecord,
  SafeReplayPackRecord,
  SecretAccessAuditRecord,
  ToolBehaviorBaselineRecord,
} from '../../intelligence/types';

interface SecretSummaryRow {
  secret_ref: string;
  tenant_id: string;
  principal_id: string;
  provider: string;
  allowed_tools: string[];
  allowed_scopes: string[];
  fingerprint_prefix: string;
  version: number;
  revoked: boolean;
  vault_encrypted: boolean;
  expires_at?: string;
  created_at: string;
}

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  agents: Array<{ agent_id: string; name: string }>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const SecureRuntimeProtectionView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  agents,
  onNotification,
}) => {
  const fetcher = apiFetch || fetch;
  const effTenant = tenantId || 'tenant_default';

  const [subTab, setSubTab] = useState<'conflicts' | 'revalidation' | 'secrets' | 'data_flow' | 'egress' | 'baseline_replay'>('conflicts');

  // Feature 5 state
  const [observations, setObservations] = useState<FactSourceObservation[]>([]);
  const [conflictPolicies, setConflictPolicies] = useState<ConflictResolutionPolicy[]>([]);
  const [conflictEvals, setConflictEvals] = useState<MultiSourceConflictEvaluation[]>([]);
  const [confEntity, setConfEntity] = useState('order:501');
  const [confField, setConfField] = useState('payment_status');
  const [confSource, setConfSource] = useState('stripe-official');
  const [confAuth, setConfAuth] = useState<'OFFICIAL' | 'CONTRACTED' | 'TRUSTED' | 'THIRD_PARTY'>('OFFICIAL');
  const [confVal, setConfVal] = useState('settled');

  // Feature 6 state
  const [revalPlans, setRevalPlans] = useState<RevalidationPlanRecord[]>([]);
  const [revalMode, setRevalMode] = useState<'DELTA' | 'FULL'>('DELTA');
  const [revalEntity, setRevalEntity] = useState('order:501');
  const [revalField, setRevalField] = useState('payment_status');

  // Feature 13 & 14 state
  const [vaultSecrets, setVaultSecrets] = useState<SecretSummaryRow[]>([]);
  const [leases, setLeases] = useState<EphemeralSecretLease[]>([]);
  const [secretAudits, setSecretAudits] = useState<SecretAccessAuditRecord[]>([]);
  const [isolationSnapshots, setIsolationSnapshots] = useState<InvocationContextSnapshot[]>([]);
  const [secRefInput, setSecRefInput] = useState('sec_stripe_prod');
  const [secRawInput, setSecRawInput] = useState('');
  const [secAllowedTools, setSecAllowedTools] = useState('stripe.refund');
  const [secAllowedScopes, setSecAllowedScopes] = useState('refund:write, orders:read');

  // Feature 15 state
  const [classifications, setClassifications] = useState<DataClassificationRule[]>([]);
  const [dataFlowPolicies, setDataFlowPolicies] = useState<DataFlowPolicyRecord[]>([]);
  const [dataFlowEvals, setDataFlowEvals] = useState<DataFlowEvaluationResult[]>([]);
  const [dfDest, setDfDest] = useState('https://external-analytics.example.com');
  const [dfTestPayload, setDfTestPayload] = useState('{"order_id":"ord-1","customer_ssn":"123-45-6789"}');

  // Feature 16 state
  const [egressPolicies, setEgressPolicies] = useState<NetworkEgressPolicyRecord[]>([]);
  const [egressReceipts, setEgressReceipts] = useState<EgressDecisionReceipt[]>([]);
  const [egressHostAllow, setEgressHostAllow] = useState('api.stripe.com');
  const [egressCheckUrl, setEgressCheckUrl] = useState('https://api.stripe.com/v1/refunds');

  // Feature 17 state
  const [baselines, setBaselines] = useState<ToolBehaviorBaselineRecord[]>([]);
  const [behaviorDrifts, setBehaviorDrifts] = useState<BehaviorDriftEventRecord[]>([]);
  const [safePacks, setSafePacks] = useState<SafeReplayPackRecord[]>([]);
  const [packName, setPackName] = useState('Safe Guardrail Regression Pack');

  const cardBg = isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-white border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 placeholder-slate-500'
    : 'bg-slate-50 border-slate-300 text-slate-900';

  const loadAll = async () => {
    const h = { 'x-tenant-id': effTenant };
    try {
      const [
        obsRes, cpRes, ceRes, rvRes,
        secRes, lsRes, saRes, isoRes,
        dcRes, dfpRes, dfeRes,
        egpRes, egrRes,
        bbRes, bdRes, spRes,
      ] = await Promise.all([
        fetcher(`/api/v1/conflicts/observations?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/conflicts/policies?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/conflicts/evaluations?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/revalidation/plans?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/secrets?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/secrets/leases?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/secrets/audit?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/isolation/invocations?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/data-flow/classifications?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/data-flow/policies?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/data-flow/evaluations?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/egress/policies?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/egress/receipts?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/behavior/baselines?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/behavior/drifts?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
        fetcher(`/api/v1/replay-packs/safe?tenant_id=${encodeURIComponent(effTenant)}`, { headers: h }),
      ]);
      if (obsRes.ok) setObservations(await obsRes.json());
      if (cpRes.ok) setConflictPolicies(await cpRes.json());
      if (ceRes.ok) setConflictEvals(await ceRes.json());
      if (rvRes.ok) setRevalPlans(await rvRes.json());
      if (secRes.ok) setVaultSecrets(await secRes.json());
      if (lsRes.ok) setLeases(await lsRes.json());
      if (saRes.ok) setSecretAudits(await saRes.json());
      if (isoRes.ok) setIsolationSnapshots(await isoRes.json());
      if (dcRes.ok) setClassifications(await dcRes.json());
      if (dfpRes.ok) setDataFlowPolicies(await dfpRes.json());
      if (dfeRes.ok) setDataFlowEvals(await dfeRes.json());
      if (egpRes.ok) setEgressPolicies(await egpRes.json());
      if (egrRes.ok) setEgressReceipts(await egrRes.json());
      if (bbRes.ok) setBaselines(await bbRes.json());
      if (bdRes.ok) setBehaviorDrifts(await bdRes.json());
      if (spRes.ok) setSafePacks(await spRes.json());
    } catch {
      // Keep quiet on transient poll
    }
  };

  useEffect(() => {
    loadAll();
  }, [effTenant]);

  const handleRecordObservation = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetcher('/api/v1/conflicts/observations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({
        tenant_id: effTenant,
        entity_id: confEntity,
        field_name: confField,
        source_id: confSource,
        source_authority: confAuth,
        value: confVal,
        data_quality: 0.92,
      }),
    });
    const data = await res.json();
    if (res.ok) {
      onNotification(`Conflict check: ${data.evaluation?.status} -> ${data.evaluation?.recommended_action}`, 'success');
      loadAll();
    } else {
      onNotification(data.error || 'Failed recording observation', 'error');
    }
  };

  const handleRegisterSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secRawInput.trim()) {
      onNotification('Enter a secret value to encrypt in vault.', 'error');
      return;
    }
    const rawVal = secRawInput;
    setSecRawInput(''); // Immediately clear sensitive input from component state
    const res = await fetcher('/api/v1/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({
        tenant_id: effTenant,
        secret_ref: secRefInput,
        provider: 'tenant-secret-vault',
        secret_value: rawVal,
        allowed_tools: secAllowedTools.split(',').map((s) => s.trim()).filter(Boolean),
        allowed_scopes: secAllowedScopes.split(',').map((s) => s.trim()).filter(Boolean),
      }),
    });
    if (res.ok) {
      onNotification(`Encrypted secret stored under ref ${secRefInput} (plaintext discarded from UI).`, 'success');
      loadAll();
    } else {
      onNotification('Failed registering vault secret.', 'error');
    }
  };

  const handleRevokeSecret = async (secretRef: string) => {
    const res = await fetcher('/api/v1/secrets/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({ tenant_id: effTenant, secret_ref: secretRef }),
    });
    if (res.ok) {
      onNotification(`Revoked secret ${secretRef} and all active leases.`, 'info');
      loadAll();
    }
  };

  const handleEvaluateDataFlow = async () => {
    let parsed: Record<string, unknown> = {};
    try {
      parsed = JSON.parse(dfTestPayload);
    } catch {
      onNotification('Invalid JSON payload for Data Flow check.', 'error');
      return;
    }
    const res = await fetcher('/api/v1/data-flow/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({ tenant_id: effTenant, destination: dfDest, payload: parsed }),
    });
    const data = await res.json();
    onNotification(`Data Flow decision: ${data.decision} (${data.highest_tier})`, data.decision === 'BLOCK' ? 'error' : 'success');
    loadAll();
  };

  const handleCreateEgressPolicy = async () => {
    const res = await fetcher('/api/v1/egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({
        tenant_id: effTenant,
        tool_id: '*',
        hostname_allowlist: egressHostAllow.split(',').map((s) => s.trim()).filter(Boolean),
        redirect_policy: 'BLOCK',
      }),
    });
    if (res.ok) {
      onNotification('Created fail-closed Network Egress Policy.', 'success');
      loadAll();
    }
  };

  const handleCheckEgress = async () => {
    const res = await fetcher('/api/v1/egress/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({ tenant_id: effTenant, tool_id: '*', url: egressCheckUrl, method: 'POST' }),
    });
    const data = await res.json();
    onNotification(`Egress Check: ${data.receipt?.decision} (${data.receipt?.reason})`, data.allowed ? 'success' : 'error');
    loadAll();
  };

  const handleRunSmartRevalidation = async () => {
    const res = await fetcher('/api/v1/revalidation/plan-and-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({
        tenant_id: effTenant,
        mode: revalMode,
        entity_id: revalEntity,
        field_name: revalField,
        refresh_budget: 10,
      }),
    });
    const data = await res.json();
    onNotification(`Revalidation status: ${data.plan?.status || 'UNKNOWN'}`, res.ok ? 'success' : 'error');
    loadAll();
  };

  const handleCreateAndRunSafePack = async () => {
    const createRes = await fetcher('/api/v1/replay-packs/safe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
      body: JSON.stringify({
        tenant_id: effTenant,
        name: packName,
        tool_id: 'stripe.refund',
        agent_id: agents[0]?.agent_id || 'agt-console',
        mode: 'DRY_RUN',
        sanitized_actions: [
          {
            step_id: 'step-1',
            capability: 'security.ssrf_probe',
            target: 'http://169.254.169.254/latest/meta-data',
            sanitized_parameters: { token: '[SANITIZED]' },
            expected_decision: 'BLOCK',
          },
        ],
      }),
    });
    const pack = await createRes.json();
    if (createRes.ok && pack.replay_pack_id) {
      const runRes = await fetcher(`/api/v1/replay-packs/safe/${pack.replay_pack_id}/run`, {
        method: 'POST',
        headers: { 'x-tenant-id': effTenant },
      });
      const runData = await runRes.json();
      onNotification(`Safe Replay: ${runData.run_result?.status} — ${runData.run_result?.summary}`, runData.run_result?.status === 'PASSED' ? 'success' : 'error');
      loadAll();
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Secure Tool Execution, Conflict Resolution & Data Protection
          </h2>
          <p className="text-xs text-slate-400">
            Batch 2 Runtime Enforcers — Conflict Resolver, Smart Delta Revalidation, Ephemeral Secret Broker, Per-Call Isolation, Data Flow Guard, Network Egress & Behavior Replay
          </p>
        </div>
        <button
          onClick={loadAll}
          className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-800 text-xs flex items-center gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh State
        </button>
      </div>

      {/* Sub-Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'conflicts', label: 'Conflict Resolver', icon: GitCompare, count: conflictEvals.length },
          { id: 'revalidation', label: 'Smart Revalidation', icon: RefreshCw, count: revalPlans.length },
          { id: 'secrets', label: 'Secret Broker & Isolation', icon: KeyRound, count: leases.filter((l) => !l.revoked).length },
          { id: 'data_flow', label: 'Data Flow & Leakage', icon: Lock, count: dataFlowEvals.length },
          { id: 'egress', label: 'Network Egress Control', icon: Globe, count: egressReceipts.length },
          { id: 'baseline_replay', label: 'Behavior & Safe Replay', icon: Activity, count: behaviorDrifts.length },
        ].map((t) => {
          const Icon = t.icon;
          const active = subTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setSubTab(t.id as any)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition ${
                active
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono">{t.count}</span>
            </button>
          );
        })}
      </div>

      {subTab === 'conflicts' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <form onSubmit={handleRecordObservation} className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Record Multi-Source Fact Observation</h3>
            <div className="grid grid-cols-2 gap-2">
              <input value={confEntity} onChange={(e) => setConfEntity(e.target.value)} placeholder="Entity ID" className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
              <input value={confField} onChange={(e) => setConfField(e.target.value)} placeholder="Field Name" className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
              <input value={confSource} onChange={(e) => setConfSource(e.target.value)} placeholder="Source ID" className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
              <select value={confAuth} onChange={(e) => setConfAuth(e.target.value as any)} className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`}>
                <option value="OFFICIAL">OFFICIAL</option>
                <option value="CONTRACTED">CONTRACTED</option>
                <option value="TRUSTED">TRUSTED</option>
                <option value="THIRD_PARTY">THIRD_PARTY</option>
              </select>
            </div>
            <input value={confVal} onChange={(e) => setConfVal(e.target.value)} placeholder="Observed Value" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <button type="submit" className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1">
              <Plus className="w-3.5 h-3.5" /> Record Observation & Evaluate
            </button>
          </form>

          <div className={`rounded-xl border p-4 space-y-2 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Conflict Evaluations ({conflictEvals.length}) — {conflictPolicies.length} Policies</h3>
            {conflictEvals.map((ev) => (
              <div key={ev.evaluation_id} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span className="text-cyan-300">{ev.entity_id}.{ev.field_name}</span>
                  <span className={ev.status === 'UNRESOLVED' ? 'text-amber-400' : 'text-emerald-400'}>
                    {ev.status} → {ev.recommended_action}
                  </span>
                </div>
                <p className="text-slate-400">{ev.explanation}</p>
                <p className="text-[11px] text-slate-500">Retained non-winning records: {ev.retained_non_winning.length}</p>
              </div>
            ))}
            {observations.length === 0 && conflictEvals.length === 0 && (
              <p className="text-xs text-slate-500">No multi-source conflict evaluations recorded yet.</p>
            )}
          </div>
        </div>
      )}

      {subTab === 'revalidation' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Smart Revalidation & Delta Refresh Planner</h3>
            <div className="grid grid-cols-3 gap-2">
              <select value={revalMode} onChange={(e) => setRevalMode(e.target.value as any)} className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`}>
                <option value="DELTA">DELTA</option>
                <option value="FULL">FULL</option>
              </select>
              <input value={revalEntity} onChange={(e) => setRevalEntity(e.target.value)} placeholder="Entity ID" className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
              <input value={revalField} onChange={(e) => setRevalField(e.target.value)} placeholder="Field Name" className={`px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            </div>
            <button onClick={handleRunSmartRevalidation} className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium flex items-center gap-1">
              <Play className="w-3.5 h-3.5" /> Plan & Execute Smart Revalidation
            </button>
          </div>
          <div className={`rounded-xl border p-4 space-y-2 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Revalidation Plans ({revalPlans.length})</h3>
            {revalPlans.map((pl) => (
              <div key={pl.plan_id} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span>{pl.plan_id} ({pl.mode})</span>
                  <span className={pl.status === 'SUCCEEDED' ? 'text-emerald-400' : 'text-rose-400'}>{pl.status}</span>
                </div>
                <p className="text-slate-400">{pl.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {subTab === 'secrets' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <form onSubmit={handleRegisterSecret} className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Encrypted Secret Vault Registration (Zero Plaintext Retention in UI)</h3>
            <input value={secRefInput} onChange={(e) => setSecRefInput(e.target.value)} placeholder="Secret Reference ID" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <input type="password" value={secRawInput} onChange={(e) => setSecRawInput(e.target.value)} placeholder="Raw Secret Token (AES-256-GCM wrapped immediately)" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <input value={secAllowedTools} onChange={(e) => setSecAllowedTools(e.target.value)} placeholder="Allowed tools (comma-separated)" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <input value={secAllowedScopes} onChange={(e) => setSecAllowedScopes(e.target.value)} placeholder="Allowed scopes (comma-separated)" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <button type="submit" className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium">
              Store Encrypted Secret Ref
            </button>
          </form>

          <div className={`rounded-xl border p-4 space-y-3 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Vault Secrets ({vaultSecrets.length}), Active Leases ({leases.filter((l) => !l.revoked).length}), Isolated Calls ({isolationSnapshots.length})</h3>
            {vaultSecrets.map((s) => (
              <div key={s.secret_ref} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs flex justify-between items-center">
                <div>
                  <div className="font-mono text-cyan-300">{s.secret_ref} (v{s.version}) — {s.fingerprint_prefix}</div>
                  <div className="text-slate-400">Tools: {s.allowed_tools.join(', ')} | Scopes: {s.allowed_scopes.join(', ')}</div>
                </div>
                <button
                  onClick={() => handleRevokeSecret(s.secret_ref)}
                  disabled={s.revoked}
                  className="px-2 py-1 rounded bg-rose-600/20 text-rose-300 border border-rose-500/30 text-[11px] disabled:opacity-40"
                >
                  {s.revoked ? 'REVOKED' : 'Revoke'}
                </button>
              </div>
            ))}
            {secretAudits.slice(0, 5).map((a) => (
              <div key={a.access_id} className="text-[11px] font-mono text-slate-400 border-t border-slate-800 pt-1">
                [{a.outcome}] {a.secret_ref} → tool={a.tool_id}: {a.reason}
              </div>
            ))}
          </div>
        </div>
      )}

      {subTab === 'data_flow' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Data Flow & Leakage Inspector</h3>
            <input value={dfDest} onChange={(e) => setDfDest(e.target.value)} placeholder="Destination URL or Tool ID" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <textarea rows={3} value={dfTestPayload} onChange={(e) => setDfTestPayload(e.target.value)} className={`w-full px-2.5 py-1.5 rounded border text-xs font-mono ${inputCls}`} />
            <button onClick={handleEvaluateDataFlow} className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-medium">
              Evaluate Data Flow & Redaction ({classifications.length} Rules, {dataFlowPolicies.length} Policies)
            </button>
          </div>
          <div className={`rounded-xl border p-4 space-y-2 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Recent Data Flow Decisions ({dataFlowEvals.length})</h3>
            {dataFlowEvals.map((ev) => (
              <div key={ev.evaluation_id} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span className="truncate max-w-xs">{ev.destination}</span>
                  <span className={ev.decision === 'BLOCK' ? 'text-rose-400' : 'text-emerald-400'}>
                    {ev.decision} ({ev.highest_tier})
                  </span>
                </div>
                <p className="text-slate-400">{ev.reason}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {subTab === 'egress' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Network Egress Policy & DNS/Redirect Validator</h3>
            <input value={egressHostAllow} onChange={(e) => setEgressHostAllow(e.target.value)} placeholder="Allowed hostnames (comma-separated)" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <button onClick={handleCreateEgressPolicy} className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium">
              Add Strict Hostname Allowlist Policy ({egressPolicies.length})
            </button>
            <div className="border-t border-slate-800 pt-3 space-y-2">
              <input value={egressCheckUrl} onChange={(e) => setEgressCheckUrl(e.target.value)} placeholder="Destination URL to verify" className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
              <button onClick={handleCheckEgress} className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1">
                <Ban className="w-3.5 h-3.5" /> Test Egress Controller (DNS & IP Check)
              </button>
            </div>
          </div>
          <div className={`rounded-xl border p-4 space-y-2 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Network Egress Receipts ({egressReceipts.length})</h3>
            {egressReceipts.map((r) => (
              <div key={r.egress_receipt_id} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span className="truncate max-w-xs">{r.method} {r.hostname}:{r.port}</span>
                  <span className={r.decision === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'}>{r.decision}</span>
                </div>
                <p className="text-slate-400">{r.reason}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {subTab === 'baseline_replay' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className={`rounded-xl border p-4 space-y-3 ${cardBg}`}>
            <h3 className="text-sm font-semibold">Safe Declarative Replay Pack (Zero Real Side Effects)</h3>
            <input value={packName} onChange={(e) => setPackName(e.target.value)} className={`w-full px-2.5 py-1.5 rounded border text-xs ${inputCls}`} />
            <button onClick={handleCreateAndRunSafePack} className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center gap-1">
              <Play className="w-3.5 h-3.5" /> Create & Run Dry-Run Replay Pack ({safePacks.length})
            </button>
            <div className="space-y-1 pt-2">
              {safePacks.map((p) => (
                <div key={p.replay_pack_id} className="p-2 rounded border border-slate-800 text-xs font-mono">
                  <div>{p.name} — {p.mode} | {p.last_run?.status || 'NOT_RUN'}</div>
                  {p.last_run && <div className="text-slate-400">{p.last_run.summary}</div>}
                </div>
              ))}
            </div>
          </div>
          <div className={`rounded-xl border p-4 space-y-2 max-h-96 overflow-y-auto ${cardBg}`}>
            <h3 className="text-sm font-semibold">Runtime Tool Baselines ({baselines.length}) & Drifts ({behaviorDrifts.length})</h3>
            {baselines.map((b) => (
              <div key={b.baseline_id} className="p-2.5 rounded-lg border border-slate-800 bg-slate-950/50 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span>{b.tool_id}@{b.tool_version}</span>
                  <span className={b.deviation_status === 'NORMAL' ? 'text-emerald-400' : 'text-amber-400'}>{b.deviation_status}</span>
                </div>
                <div className="text-slate-400">
                  Calls: {b.observed_stats.total_calls} | Error Rate: {(b.observed_stats.error_rate * 100).toFixed(1)}%
                </div>
              </div>
            ))}
            {behaviorDrifts.map((d) => (
              <div key={d.event_id} className="p-2 rounded border border-rose-500/30 bg-rose-950/20 text-xs text-rose-200">
                [{d.severity}] {d.category}: {d.detail}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
