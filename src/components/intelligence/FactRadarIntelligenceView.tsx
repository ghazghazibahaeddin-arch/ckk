import React, { useEffect, useState } from 'react';
import {
  Clock,
  Radio,
  GitCompare,
  GitBranch,
  RefreshCw,
  Play,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Plus,
  RotateCcw,
} from 'lucide-react';
import type {
  FreshnessPolicyRecord,
  FreshnessEvaluationResult,
  ChangeSourceRecord,
  ChangeEventRecord,
  FailedChangeEventRecord,
  SemanticDiffResult,
  DependencyNodeRecord,
  DependencyEdgeRecord,
  InvalidationCascadeRecord,
  DependencyNodeType,
} from '../../intelligence/types';

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const FactRadarIntelligenceView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  onNotification,
}) => {
  const fetcher = apiFetch || fetch;
  const effTenant = tenantId || 'tenant_default';

  const [subTab, setSubTab] = useState<'freshness' | 'radar' | 'semantic' | 'cascade'>('freshness');

  // Feature 1: Freshness State
  const [policies, setPolicies] = useState<FreshnessPolicyRecord[]>([]);
  const [polEntityPattern, setPolEntityPattern] = useState('order:*');
  const [polFactType, setPolFactType] = useState('payment_status');
  const [polRiskClass, setPolRiskClass] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('CRITICAL');
  const [polDefaultTtl, setPolDefaultTtl] = useState('60');
  const [polFailMode, setPolFailMode] = useState<'REVALIDATE_ON_STALE' | 'BLOCK_ON_STALE' | 'BLOCK_ON_EXPIRED'>('BLOCK_ON_EXPIRED');

  const [evalEntityId, setEvalEntityId] = useState('order:1099');
  const [evalFieldName, setEvalFieldName] = useState('payment_status');
  const [evalResult, setEvalResult] = useState<FreshnessEvaluationResult | null>(null);

  // Feature 2: Radar State
  const [sources, setSources] = useState<ChangeSourceRecord[]>([]);
  const [events, setEvents] = useState<ChangeEventRecord[]>([]);
  const [failedEvents, setFailedEvents] = useState<FailedChangeEventRecord[]>([]);
  const [srcName, setSrcName] = useState('Stripe Order Webhook');
  const [srcType, setSrcType] = useState<'WEBHOOK' | 'HTTP_POLL'>('WEBHOOK');
  const [srcEndpoint, setSrcEndpoint] = useState('');
  const [pollingId, setPollingId] = useState<string | null>(null);

  // Feature 3: Semantic Diff State
  const [diffSubject, setDiffSubject] = useState('order:1099:snapshot');
  const [beforeJson, setBeforeJson] = useState(
    JSON.stringify({ status: 'paid', amount_cents: 12000, display_name: 'Order A', notes: 'initial' }, null, 2)
  );
  const [afterJson, setAfterJson] = useState(
    JSON.stringify({ status: 'refunded', amount_cents: 12000, display_name: 'Order A (VIP)', notes: 'updated' }, null, 2)
  );
  const [diffResult, setDiffResult] = useState<SemanticDiffResult | null>(null);
  const [diffHistory, setDiffHistory] = useState<SemanticDiffResult[]>([]);

  // Feature 4: Dependency Cascade State
  const [nodes, setNodes] = useState<DependencyNodeRecord[]>([]);
  const [edges, setEdges] = useState<DependencyEdgeRecord[]>([]);
  const [cascades, setCascades] = useState<InvalidationCascadeRecord[]>([]);
  const [fromType, setFromType] = useState<DependencyNodeType>('FACT');
  const [fromRef, setFromRef] = useState('order:1099:payment_status');
  const [toType, setToType] = useState<DependencyNodeType>('PROTECTED_ACTION');
  const [toRef, setToRef] = useState('logistics.ship_order');
  const [cascadeReason, setCascadeReason] = useState('Chargeback webhook invalidated payment evidence');

  const cardCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-xs';
  const subCls = isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';
  const mutedCls = isDark ? 'text-slate-400' : 'text-slate-600';

  const loadAll = async () => {
    try {
      const q = `?tenant_id=${encodeURIComponent(effTenant)}`;
      const [polRes, srcRes, evtRes, dlqRes, diffRes, depRes] = await Promise.all([
        fetcher(`/api/v1/freshness/policies${q}`),
        fetcher(`/api/v1/radar/sources${q}`),
        fetcher(`/api/v1/radar/events${q}`),
        fetcher(`/api/v1/radar/failed-events${q}`),
        fetcher(`/api/v1/semantic-diff/history${q}`),
        fetcher(`/api/v1/dependency-graph${q}`),
      ]);
      if (polRes.ok) setPolicies(await polRes.json());
      if (srcRes.ok) setSources(await srcRes.json());
      if (evtRes.ok) setEvents(await evtRes.json());
      if (dlqRes.ok) setFailedEvents(await dlqRes.json());
      if (diffRes.ok) setDiffHistory(await diffRes.json());
      if (depRes.ok) {
        const dg = await depRes.json();
        setNodes(dg.nodes || []);
        setEdges(dg.edges || []);
        setCascades(dg.cascades || []);
      }
    } catch {
      // ignore transient network errors
    }
  };

  useEffect(() => {
    loadAll();
  }, [effTenant]);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const ttl = Math.max(5, Number(polDefaultTtl) || 60);
      const res = await fetcher('/api/v1/freshness/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          entity_pattern: polEntityPattern,
          fact_type: polFactType,
          risk_class: polRiskClass,
          default_ttl_seconds: ttl,
          max_ttl_seconds: ttl * 2,
          fail_mode: polFailMode,
        }),
      });
      if (res.ok) {
        onNotification('Adaptive Freshness policy registered.', 'success');
        loadAll();
      } else {
        const err = await res.json();
        onNotification(err.error || 'Failed to create freshness policy.', 'error');
      }
    } catch {
      onNotification('Error creating freshness policy.', 'error');
    }
  };

  const handleEvaluateFreshness = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/freshness/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          entity_id: evalEntityId,
          field_name: evalFieldName,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setEvalResult(data);
        onNotification(`Freshness check: ${data.freshness_status} (${data.recommended_action})`, 'info');
      } else {
        onNotification(data.error || 'Evaluation failed.', 'error');
      }
    } catch {
      onNotification('Error evaluating freshness.', 'error');
    }
  };

  const handleCreateSource = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/radar/sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          name: srcName,
          source_type: srcType,
          endpoint_url: srcType === 'HTTP_POLL' && srcEndpoint ? srcEndpoint : undefined,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification('Live Change Radar source created.', 'success');
        loadAll();
      } else {
        onNotification(data.error || 'Failed to register radar source.', 'error');
      }
    } catch {
      onNotification('Error registering radar source.', 'error');
    }
  };

  const handlePollSource = async (sourceId: string) => {
    setPollingId(sourceId);
    try {
      const res = await fetcher(`/api/v1/radar/sources/${sourceId}/poll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({ tenant_id: effTenant }),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification(`Polled source: ${data.ingested_count || 0} event(s) processed.`, 'success');
      } else {
        onNotification(data.error || 'Source poll failed and recorded in Dead-Letter Queue.', 'error');
      }
      loadAll();
    } catch {
      onNotification('Error polling source.', 'error');
    } finally {
      setPollingId(null);
    }
  };

  const handleReplayDlq = async (deadLetterId: string) => {
    try {
      const res = await fetcher(`/api/v1/radar/failed-events/${deadLetterId}/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification(`Dead-letter event replayed (${data.dead_letter?.status}).`, 'success');
      } else {
        onNotification(data.error || 'Replay failed — event requires valid entity_id & field_name.', 'error');
      }
      loadAll();
    } catch {
      onNotification('Error replaying failed event.', 'error');
    }
  };

  const handleComputeDiff = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const parsedBefore = JSON.parse(beforeJson);
      const parsedAfter = JSON.parse(afterJson);
      const res = await fetcher('/api/v1/semantic-diff/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          subject_id: diffSubject,
          before: parsedBefore,
          after: parsedAfter,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setDiffResult(data);
        onNotification(`Semantic classification: ${data.classification}`, 'info');
        loadAll();
      } else {
        onNotification(data.error || 'Diff failed.', 'error');
      }
    } catch {
      onNotification('Invalid JSON in before/after payload.', 'error');
    }
  };

  const handleAddEdge = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetcher('/api/v1/dependency-graph/edges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({
          tenant_id: effTenant,
          from_type: fromType,
          from_ref: fromRef,
          to_type: toType,
          to_ref: toRef,
          relation: 'GATES',
        }),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification('Dependency link added to DAG.', 'success');
        loadAll();
      } else {
        onNotification(data.error || 'Failed to add dependency edge.', 'error');
      }
    } catch {
      onNotification('Error creating dependency edge.', 'error');
    }
  };

  const handleTriggerCascade = async (nodeId?: string) => {
    try {
      const payload = nodeId
        ? { tenant_id: effTenant, trigger_node_id: nodeId, reason: cascadeReason }
        : { tenant_id: effTenant, node_type: fromType, ref_id: fromRef, reason: cascadeReason };
      const res = await fetcher('/api/v1/dependency-graph/cascade', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok) {
        onNotification(
          `Cascade executed: ${data.direct_dependents?.length || 0} direct, ${data.indirect_dependents?.length || 0} indirect dependents affected.`,
          'info'
        );
        loadAll();
      } else {
        onNotification(data.error || 'Cascade execution failed.', 'error');
      }
    } catch {
      onNotification('Error running cascade.', 'error');
    }
  };

  const handleRevalidateNode = async (nodeId: string) => {
    try {
      const res = await fetcher('/api/v1/dependency-graph/revalidate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-tenant-id': effTenant },
        body: JSON.stringify({ tenant_id: effTenant, node_id: nodeId }),
      });
      if (res.ok) {
        onNotification('Dependency branch revalidated to VALID.', 'success');
        loadAll();
      }
    } catch {
      onNotification('Error revalidating dependency node.', 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className={`rounded-2xl border p-6 ${cardCls}`}>
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
              <Radio className="w-4 h-4" />
              <span>Decision Integrity Intelligence</span>
            </div>
            <h2 className="text-xl font-bold">Fact Freshness, Live Change Radar & Invalidation Cascade</h2>
            <p className={`text-sm mt-1 ${mutedCls}`}>
              Enforce risk-bounded TTLs, ingest real-time webhook/poll deltas with semantic diffing, and propagate fail-closed invalidations across dependent agent actions.
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

        {/* Sub-navigation */}
        <div className="flex flex-wrap gap-2 mt-5 pt-4 border-t border-slate-800/60">
          {[
            { id: 'freshness' as const, label: '1. Adaptive Freshness', icon: Clock, count: policies.length },
            { id: 'radar' as const, label: '2. Live Change Radar & DLQ', icon: Radio, count: events.length },
            { id: 'semantic' as const, label: '3. Semantic Change Diff', icon: GitCompare, count: diffHistory.length },
            { id: 'cascade' as const, label: '4. Dependency Cascade DAG', icon: GitBranch, count: nodes.length },
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

      {/* PANEL 1: ADAPTIVE FRESHNESS */}
      {subTab === 'freshness' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Register Risk-Bounded Freshness Policy</span>
            </h3>
            <form onSubmit={handleCreatePolicy} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Entity Pattern</label>
                  <input
                    value={polEntityPattern}
                    onChange={(e) => setPolEntityPattern(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Fact Field / Type</label>
                  <input
                    value={polFactType}
                    onChange={(e) => setPolFactType(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Risk Class</label>
                  <select
                    value={polRiskClass}
                    onChange={(e) => setPolRiskClass(e.target.value as any)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="CRITICAL">CRITICAL (&lt;=120s)</option>
                    <option value="HIGH">HIGH (&lt;=600s)</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Default TTL (sec)</label>
                  <input
                    type="number"
                    value={polDefaultTtl}
                    onChange={(e) => setPolDefaultTtl(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Fail Mode</label>
                  <select
                    value={polFailMode}
                    onChange={(e) => setPolFailMode(e.target.value as any)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="BLOCK_ON_EXPIRED">BLOCK_ON_EXPIRED</option>
                    <option value="BLOCK_ON_STALE">BLOCK_ON_STALE</option>
                    <option value="REVALIDATE_ON_STALE">REVALIDATE_ON_STALE</option>
                  </select>
                </div>
              </div>
              <button
                type="submit"
                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Save Policy (Bounds Auto-Enforced)</span>
              </button>
            </form>

            <div className="pt-3 border-t border-slate-800/60 space-y-2 max-h-64 overflow-y-auto">
              {policies.map((p) => (
                <div key={p.policy_id} className={`p-3 rounded-xl border text-xs ${subCls}`}>
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-cyan-400">{p.policy_id}</span>
                    <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      {p.risk_class}
                    </span>
                  </div>
                  <div className={`mt-1 ${mutedCls}`}>
                    Pattern: <span className="font-mono text-slate-200">{p.entity_pattern}</span> &bull; Field:{' '}
                    <span className="font-mono text-slate-200">{p.fact_type}</span> &bull; TTL [{p.min_ttl_seconds}s – {p.max_ttl_seconds}s] &bull; {p.fail_mode}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm flex items-center space-x-2">
              <Play className="w-4 h-4 text-emerald-400" />
              <span>Live Freshness Evaluator</span>
            </h3>
            <form onSubmit={handleEvaluateFreshness} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Entity ID</label>
                  <input
                    value={evalEntityId}
                    onChange={(e) => setEvalEntityId(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Field Name</label>
                  <input
                    value={evalFieldName}
                    onChange={(e) => setEvalFieldName(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
              </div>
              <button
                type="submit"
                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Evaluate Fact Freshness</span>
              </button>
            </form>

            {evalResult && (
              <div className={`p-4 rounded-xl border text-xs space-y-2 ${subCls}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold">
                    {evalResult.entity_id}.{evalResult.field_name}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded font-mono font-bold ${
                      evalResult.freshness_status === 'FRESH'
                        ? 'bg-emerald-500/15 text-emerald-400'
                        : evalResult.freshness_status === 'STALE'
                        ? 'bg-amber-500/15 text-amber-400'
                        : 'bg-rose-500/15 text-rose-400'
                    }`}
                  >
                    {evalResult.freshness_status} &rarr; {evalResult.recommended_action}
                  </span>
                </div>
                <div className={`grid grid-cols-3 gap-2 font-mono text-[11px] ${mutedCls}`}>
                  <div>Age: {evalResult.age_seconds}s</div>
                  <div>Effective TTL: {evalResult.effective_ttl_seconds}s</div>
                  <div>Adaptive Factor: {evalResult.adaptive_factor}x</div>
                </div>
                <p className="text-slate-300">{evalResult.explanation}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* PANEL 2: LIVE CHANGE RADAR & DLQ */}
      {subTab === 'radar' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm">Register Change Radar Source</h3>
              <form onSubmit={handleCreateSource} className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <input
                    value={srcName}
                    onChange={(e) => setSrcName(e.target.value)}
                    placeholder="Source name"
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  />
                  <select
                    value={srcType}
                    onChange={(e) => setSrcType(e.target.value as any)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="WEBHOOK">WEBHOOK</option>
                    <option value="HTTP_POLL">HTTP_POLL</option>
                  </select>
                </div>
                {srcType === 'HTTP_POLL' && (
                  <input
                    value={srcEndpoint}
                    onChange={(e) => setSrcEndpoint(e.target.value)}
                    placeholder="https://api.example.com/changes"
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                )}
                <button
                  type="submit"
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Radar Source</span>
                </button>
              </form>

              <div className="space-y-2 max-h-64 overflow-y-auto">
                {sources.length === 0 && (
                  <p className={`text-xs ${mutedCls}`}>No radar sources registered for {effTenant} yet.</p>
                )}
                {sources.map((s) => (
                  <div key={s.source_id} className={`p-3 rounded-xl border text-xs flex items-center justify-between ${subCls}`}>
                    <div>
                      <div className="font-semibold flex items-center space-x-2">
                        <span>{s.name}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            s.status === 'ACTIVE'
                              ? 'bg-emerald-500/15 text-emerald-400'
                              : 'bg-rose-500/15 text-rose-400'
                          }`}
                        >
                          {s.status}
                        </span>
                      </div>
                      <div className={`font-mono text-[11px] mt-1 ${mutedCls}`}>
                        {s.source_id} &bull; {s.source_type} &bull; Failures: {s.consecutive_failures}
                        {s.cursor ? ` • Cursor: ${s.cursor}` : ''}
                      </div>
                    </div>
                    <button
                      onClick={() => handlePollSource(s.source_id)}
                      disabled={pollingId === s.source_id}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                    >
                      {pollingId === s.source_id ? 'Polling...' : 'Poll'}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
              <h3 className="font-semibold text-sm flex items-center justify-between">
                <span>Dead-Letter Queue (Failed / Rejected Webhooks & Polls)</span>
                <span className="font-mono text-xs text-rose-400">{failedEvents.length}</span>
              </h3>
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {failedEvents.length === 0 && (
                  <p className={`text-xs ${mutedCls}`}>Zero failed events in Dead-Letter Queue.</p>
                )}
                {failedEvents.map((dlq) => (
                  <div key={dlq.dead_letter_id} className={`p-3 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-rose-400">{dlq.error_code}</span>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800">{dlq.status}</span>
                        <button
                          onClick={() => handleReplayDlq(dlq.dead_letter_id)}
                          className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px]"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Replay</span>
                        </button>
                      </div>
                    </div>
                    <p className={mutedCls}>{dlq.error_message}</p>
                    <div className="font-mono text-[10px] text-slate-500">
                      Trace: {dlq.trace_id} &bull; Retries: {dlq.retry_count}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className={`rounded-2xl border p-5 space-y-3 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Ingested Change Events Stream</h3>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {events.length === 0 && <p className={`text-xs ${mutedCls}`}>No change events ingested yet.</p>}
              {events.map((ev) => (
                <div key={ev.event_id} className={`p-3 rounded-xl border text-xs flex flex-wrap items-center justify-between gap-2 ${subCls}`}>
                  <div className="font-mono">
                    <span className="text-cyan-400 font-bold">{ev.entity_id}.{ev.field_name}</span>
                    <span className={mutedCls}> &rarr; {JSON.stringify(ev.new_value)}</span>
                  </div>
                  <div className="flex items-center space-x-2 font-mono text-[11px]">
                    <span
                      className={`px-2 py-0.5 rounded ${
                        ev.status === 'APPLIED'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-amber-500/15 text-amber-400'
                      }`}
                    >
                      {ev.status}
                    </span>
                    <span className={mutedCls}>{ev.ingested_at}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PANEL 3: SEMANTIC CHANGE DETECTION */}
      {subTab === 'semantic' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Analyze Semantic Diff (With Secret Redaction)</h3>
            <form onSubmit={handleComputeDiff} className="space-y-3 text-xs">
              <div>
                <label className={`block mb-1 ${mutedCls}`}>Subject ID</label>
                <input
                  value={diffSubject}
                  onChange={(e) => setDiffSubject(e.target.value)}
                  className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Before JSON</label>
                  <textarea
                    rows={6}
                    value={beforeJson}
                    onChange={(e) => setBeforeJson(e.target.value)}
                    className={`w-full p-2.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                  />
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>After JSON</label>
                  <textarea
                    rows={6}
                    value={afterJson}
                    onChange={(e) => setAfterJson(e.target.value)}
                    className={`w-full p-2.5 rounded-lg border font-mono text-[11px] ${inputCls}`}
                  />
                </div>
              </div>
              <button
                type="submit"
                className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
              >
                <GitCompare className="w-3.5 h-3.5" />
                <span>Compute Semantic Classification</span>
              </button>
            </form>
          </div>

          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Classification Output & Redacted History</h3>
            {diffResult && (
              <div className={`p-4 rounded-xl border text-xs space-y-2 ${subCls}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-cyan-400">{diffResult.subject_id}</span>
                  <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 font-mono font-bold">
                    {diffResult.classification}
                  </span>
                </div>
                <p>{diffResult.summary}</p>
                <div className="space-y-1">
                  {diffResult.diffs.map((d, idx) => (
                    <div key={idx} className="font-mono text-[11px] flex items-center justify-between">
                      <span>{d.path} ({d.change_kind})</span>
                      <span className={d.is_material ? 'text-rose-400' : mutedCls}>
                        {d.is_security_sensitive ? 'SECURITY' : d.is_material ? 'MATERIAL' : 'NON-MATERIAL'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2 max-h-56 overflow-y-auto">
              {diffHistory.map((h) => (
                <div key={h.diff_id} className={`p-3 rounded-xl border text-xs flex items-center justify-between ${subCls}`}>
                  <div>
                    <div className="font-mono font-semibold">{h.subject_id}</div>
                    <div className={`text-[11px] ${mutedCls}`}>{h.summary}</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-800 font-mono text-[10px]">{h.classification}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PANEL 4: IMPACT & INVALIDATION CASCADE */}
      {subTab === 'cascade' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Link Dependency & Trigger Cascade</h3>
            <form onSubmit={handleAddEdge} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Upstream Type</label>
                  <select
                    value={fromType}
                    onChange={(e) => setFromType(e.target.value as DependencyNodeType)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="SOURCE">SOURCE</option>
                    <option value="FACT">FACT</option>
                    <option value="EVIDENCE">EVIDENCE</option>
                    <option value="ENTITY">ENTITY</option>
                    <option value="AGENT_TASK">AGENT_TASK</option>
                    <option value="CONTRACT">CONTRACT</option>
                    <option value="TOOL">TOOL</option>
                  </select>
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Upstream Ref ID</label>
                  <input
                    value={fromRef}
                    onChange={(e) => setFromRef(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Downstream Type</label>
                  <select
                    value={toType}
                    onChange={(e) => setToType(e.target.value as DependencyNodeType)}
                    className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}
                  >
                    <option value="ENTITY">ENTITY</option>
                    <option value="AGENT_TASK">AGENT_TASK</option>
                    <option value="PLAN">PLAN</option>
                    <option value="CONTRACT">CONTRACT</option>
                    <option value="TOOL">TOOL</option>
                    <option value="PROTECTED_ACTION">PROTECTED_ACTION</option>
                  </select>
                </div>
                <div>
                  <label className={`block mb-1 ${mutedCls}`}>Downstream Ref ID</label>
                  <input
                    value={toRef}
                    onChange={(e) => setToRef(e.target.value)}
                    className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`}
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="submit"
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add DAG Edge</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleTriggerCascade()}
                  className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium"
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Trigger Cascade Invalidation</span>
                </button>
              </div>
            </form>

            <div className="space-y-2 max-h-60 overflow-y-auto pt-2 border-t border-slate-800/60">
              {nodes.map((n) => (
                <div key={n.node_id} className={`p-2.5 rounded-xl border text-xs flex items-center justify-between ${subCls}`}>
                  <div>
                    <div className="font-mono font-semibold">
                      [{n.node_type}] {n.ref_id}
                    </div>
                    <div className={`text-[10px] font-mono ${mutedCls}`}>{n.node_id}</div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                        n.state === 'VALID'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-rose-500/15 text-rose-400'
                      }`}
                    >
                      {n.state}
                    </span>
                    {n.state !== 'VALID' && (
                      <button
                        onClick={() => handleRevalidateNode(n.node_id)}
                        className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px]"
                      >
                        Revalidate
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className={`rounded-2xl border p-5 space-y-4 ${cardCls}`}>
            <h3 className="font-semibold text-sm">Cascade Attribution & Outbox History ({edges.length} edges)</h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {cascades.length === 0 && (
                <p className={`text-xs ${mutedCls}`}>No invalidation cascades triggered yet.</p>
              )}
              {cascades.map((c) => (
                <div key={c.cascade_id} className={`p-3 rounded-xl border text-xs space-y-1.5 ${subCls}`}>
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-rose-400">{c.cascade_id}</span>
                    <span>Depth: {c.max_depth_reached}</span>
                  </div>
                  <p>{c.trigger_reason}</p>
                  <div className={`font-mono text-[11px] ${mutedCls}`}>
                    Direct: {c.direct_dependents.length} &bull; Indirect: {c.indirect_dependents.length} &bull; Protected Actions Blocked: {c.affected_protected_actions.length}
                  </div>
                  <div className="flex items-center space-x-2 text-[10px] font-mono">
                    {c.partial_failure ? (
                      <span className="text-amber-400 inline-flex items-center space-x-1">
                        <XCircle className="w-3 h-3" />
                        <span>OUTBOX PARTIAL FAILURE</span>
                      </span>
                    ) : (
                      <span className="text-emerald-400 inline-flex items-center space-x-1">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>OUTBOX DELIVERED</span>
                      </span>
                    )}
                    <span className={mutedCls}>Trace: {c.trace_id}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
