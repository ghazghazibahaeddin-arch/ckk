import React, { useState } from 'react';
import {
  GitBranch,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  ShieldAlert,
  ArrowRight,
  Database,
  History,
  FileText,
  Clock,
} from 'lucide-react';
import type {
  ConflictRecord,
  FactVersionHistoryRecord,
  RevalidationNoticeRecord,
} from '../../assurance/types';

interface ConflictsViewProps {
  conflicts: ConflictRecord[];
  factHistory: FactVersionHistoryRecord[];
  revalidations: RevalidationNoticeRecord[];
  onRefresh: () => void;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const ConflictsView: React.FC<ConflictsViewProps> = ({
  conflicts,
  factHistory,
  revalidations,
  onRefresh,
  tenantId: _tenantId,
  apiFetch,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [selectedConflict, setSelectedConflict] = useState<ConflictRecord | null>(null);
  const [resolving, setResolving] = useState(false);
  const [strategy, setStrategy] = useState<'AUTHORITATIVE_SOURCE' | 'LATEST_WINS' | 'MANUAL_SUPERVISOR'>('AUTHORITATIVE_SOURCE');
  const [overrideValue, setOverrideValue] = useState('');
  const [supervisorNotes, setSupervisorNotes] = useState('Adjudicated by production supervisor via console');

  const activeConflicts = conflicts.filter((c) => c.status === 'ACTIVE_CONFLICT');
  const resolvedConflicts = conflicts.filter((c) => c.status === 'RESOLVED');

  const handleResolveConflict = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedConflict) return;
    setResolving(true);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/conflicts/${selectedConflict.conflict_id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          strategy,
          override_value: strategy === 'MANUAL_SUPERVISOR' ? overrideValue : undefined,
          supervisor_notes: supervisorNotes,
          note: supervisorNotes,
        }),
      });
      if (res.ok) {
        setSelectedConflict(null);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to resolve conflict:', err);
    } finally {
      setResolving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className={`rounded-2xl border p-6 ${bgCard}`}>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-1">
              <GitBranch className="w-4 h-4" />
              <span>Assurance Module — CASCADE + Crossflow</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold">Evidence Change & Conflict Intelligence</h2>
            <p className={`text-xs mt-1 ${textMuted}`}>
              Multi-source observation provenance, zero silent overwrites, automated revalidation notices, and authoritative conflict adjudication.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={onRefresh}
              className={`p-2 rounded-xl border text-xs font-medium hover:bg-slate-800 transition-colors ${borderSubtle}`}
              title="Refresh Conflicts"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Status Ribbon */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Active Conflicts:</span>
            <span className={`px-2 py-0.5 rounded-full font-bold ${activeConflicts.length > 0 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-300'}`}>
              {activeConflicts.length}
            </span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Pending Revalidations:</span>
            <span className={`px-2 py-0.5 rounded-full font-bold ${revalidations.length > 0 ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-300'}`}>
              {revalidations.length}
            </span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Tracked Version Snapshots:</span>
            <span className="px-2 py-0.5 rounded-full font-bold bg-slate-800 text-slate-300 font-mono">
              {factHistory.length}
            </span>
          </div>
        </div>
      </div>

      {/* Active Conflicts Panel */}
      <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-sm flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>Active Contradictions & Conflict Adjudication ({activeConflicts.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Never Silently Overwrite</span>
        </div>

        {activeConflicts.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs font-sans">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
            <p className="font-bold text-slate-300">All Observations in Consensual Alignment</p>
            <p className="text-[11px] text-slate-500 mt-1">
              Zero active contradictions across connected webhook, sensor, and ERP sources.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {activeConflicts.map((c) => (
              <div key={c.conflict_id} className="p-4 hover:bg-slate-800/30 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-3">
                  <div>
                    <span className="font-mono text-xs font-bold text-cyan-300">{c.conflict_id}</span>
                    <h4 className="font-bold text-sm text-slate-200 mt-0.5">
                      Contradiction on <span className="font-mono text-amber-300">{c.entity_id}.{c.field_name}</span>
                    </h4>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedConflict(c);
                      setOverrideValue(String(c.conflicting_value));
                    }}
                    className="px-3 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-colors self-start sm:self-auto"
                  >
                    Adjudicate Conflict
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className={`p-3 rounded-xl border ${borderSubtle} ${bgSubtle}`}>
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">Existing State</div>
                    <div className="text-slate-200 font-bold">Value: {JSON.stringify(c.existing_value)}</div>
                    <div className="text-slate-400 text-[11px] mt-0.5">Source: {c.existing_source}</div>
                  </div>
                  <div className={`p-3 rounded-xl border border-amber-500/30 bg-amber-950/20`}>
                    <div className="text-[10px] text-amber-400 uppercase tracking-wider mb-1">Conflicting Inbound Observation</div>
                    <div className="text-amber-200 font-bold">Value: {JSON.stringify(c.conflicting_value)}</div>
                    <div className="text-amber-400/80 text-[11px] mt-0.5">Source: {c.conflicting_source}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pending Revalidation Notices */}
      {revalidations.length > 0 && (
        <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-bold text-sm flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-cyan-400" />
              <span>Pending Revalidation Notices ({revalidations.length})</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Automated Decision Invalidation</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className={`border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 ${bgSubtle}`}>
                <tr>
                  <th className="py-2.5 px-4">Notice ID</th>
                  <th className="py-2.5 px-4">Fact Key</th>
                  <th className="py-2.5 px-4">Reason</th>
                  <th className="py-2.5 px-4">Affected Decisions</th>
                  <th className="py-2.5 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                {revalidations.map((r) => (
                  <tr key={r.revalidation_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyan-300">{r.revalidation_id}</td>
                    <td className="py-3 px-4 text-amber-300">{r.fact_key}</td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate">{r.reason}</td>
                    <td className="py-3 px-4 text-slate-400">{r.affected_receipt_ids?.length || 0} Receipts</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                        {r.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Version History Table */}
      <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-sm flex items-center space-x-2">
            <History className="w-4 h-4 text-cyan-400" />
            <span>Fact Version History & Provenance Ledger ({factHistory.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Cryptographic Version Auditing</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 ${bgSubtle}`}>
              <tr>
                <th className="py-2.5 px-4">Entity</th>
                <th className="py-2.5 px-4">Field</th>
                <th className="py-2.5 px-4">Version</th>
                <th className="py-2.5 px-4">Value</th>
                <th className="py-2.5 px-4">Source Provenance</th>
                <th className="py-2.5 px-4">Change Type</th>
                <th className="py-2.5 px-4">Payload Hash</th>
                <th className="py-2.5 px-4">Observed At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {factHistory.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 font-sans">
                    No version snapshots recorded yet. Updates to facts create immutable version entries.
                  </td>
                </tr>
              ) : (
                factHistory.map((h) => (
                  <tr key={h.history_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyan-300">{h.entity_id}</td>
                    <td className="py-3 px-4 text-slate-300">{h.field_name}</td>
                    <td className="py-3 px-4 text-emerald-400 font-bold">v{h.version}</td>
                    <td className="py-3 px-4 font-semibold text-slate-200">{JSON.stringify(h.value)}</td>
                    <td className="py-3 px-4 text-slate-400">{h.source}</td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                        {h.change_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500 truncate max-w-[120px]" title={h.provenance?.payload_hash}>
                      {h.provenance?.payload_hash ? `${h.provenance.payload_hash.slice(0, 12)}...` : 'n/a'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[10px]">
                      {new Date(h.observed_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Adjudication Modal */}
      {selectedConflict && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Adjudicate Contradiction</h3>
            <p className={`text-xs ${textMuted}`}>
              Resolve conflicting observations on <span className="font-mono text-cyan-400">{selectedConflict.entity_id}.{selectedConflict.field_name}</span>.
            </p>

            <form onSubmit={handleResolveConflict} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-2 font-mono">Resolution Strategy</label>
                <div className="space-y-2">
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="strategy"
                      value="AUTHORITATIVE_SOURCE"
                      checked={strategy === 'AUTHORITATIVE_SOURCE'}
                      onChange={() => setStrategy('AUTHORITATIVE_SOURCE')}
                      className="text-cyan-500"
                    />
                    <div>
                      <span className="font-bold">Authoritative Source</span>
                      <p className="text-[10px] text-slate-500">Prefers designated primary source of truth (Stripe for payment, ERP for inventory).</p>
                    </div>
                  </label>
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="strategy"
                      value="LATEST_WINS"
                      checked={strategy === 'LATEST_WINS'}
                      onChange={() => setStrategy('LATEST_WINS')}
                      className="text-cyan-500"
                    />
                    <div>
                      <span className="font-bold">Latest Wins</span>
                      <p className="text-[10px] text-slate-500">Adopts the most recently observed timestamp observation.</p>
                    </div>
                  </label>
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="strategy"
                      value="MANUAL_SUPERVISOR"
                      checked={strategy === 'MANUAL_SUPERVISOR'}
                      onChange={() => setStrategy('MANUAL_SUPERVISOR')}
                      className="text-cyan-500"
                    />
                    <div>
                      <span className="font-bold">Manual Supervisor Override</span>
                      <p className="text-[10px] text-slate-500">Explicitly specify the adjudicated value with audit sign-off.</p>
                    </div>
                  </label>
                </div>
              </div>

              {strategy === 'MANUAL_SUPERVISOR' && (
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Adjudicated Value</label>
                  <input
                    type="text"
                    value={overrideValue}
                    onChange={(e) => setOverrideValue(e.target.value)}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
              )}

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Supervisor Notes / Audit Justification</label>
                <input
                  type="text"
                  value={supervisorNotes}
                  onChange={(e) => setSupervisorNotes(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedConflict(null)}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={resolving}
                  className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold"
                >
                  {resolving ? 'Resolving...' : 'Commit Adjudication'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
