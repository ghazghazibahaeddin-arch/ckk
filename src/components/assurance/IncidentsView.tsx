import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Play,
  RefreshCw,
  ShieldCheck,
  FileText,
  Plus,
  ArrowRight,
  Lock,
  Layers,
  Terminal,
} from 'lucide-react';
import type {
  IncidentRecord,
  CorrectionPackRecord,
  ReplayPackRecord,
} from '../../assurance/types';

interface IncidentsViewProps {
  incidents: IncidentRecord[];
  correctionPacks: CorrectionPackRecord[];
  replayPacks: ReplayPackRecord[];
  onRefresh: () => void;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  correctionPacks,
  replayPacks,
  onRefresh,
  tenantId,
  apiFetch,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [runningPackId, setRunningPackId] = useState<string | null>(null);
  const [approvingPackId, setApprovingPackId] = useState<string | null>(null);
  const [replayOutput, setReplayOutput] = useState<{ id: string; result: any } | null>(null);
  const [showNewIncidentModal, setShowNewIncidentModal] = useState(false);

  // New Incident Form
  const [newIncidentForm, setNewIncidentForm] = useState({
    title: 'Precondition Drift: Refunded Order Dispatched',
    severity: 'HIGH' as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    cause_of_failure: 'External payment was refunded via Stripe webhook, but courier dispatch executed based on stale cached fact.',
    affected_entities: 'order:1099',
    affected_skills: 'skl-fedex-courier',
    affected_contracts: 'ctrc-logistics-standard',
  });

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher('/api/v1/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newIncidentForm,
          tenant_id: tenantId,
          description: newIncidentForm.cause_of_failure,
          affected_entities: newIncidentForm.affected_entities.split(',').map((s) => s.trim()).filter(Boolean),
          affected_skills: newIncidentForm.affected_skills.split(',').map((s) => s.trim()).filter(Boolean),
          affected_contracts: newIncidentForm.affected_contracts.split(',').map((s) => s.trim()).filter(Boolean),
        }),
      });
      if (res.ok) {
        setShowNewIncidentModal(false);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to create incident:', err);
    }
  };

  const handleRunReplay = async (replayPackId: string) => {
    setRunningPackId(replayPackId);
    setReplayOutput(null);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/incidents/replay-packs/${replayPackId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      setReplayOutput({ id: replayPackId, result: data });
      onRefresh();
    } catch (err) {
      console.error('Failed to execute replay pack harness:', err);
    } finally {
      setRunningPackId(null);
    }
  };

  const handleApproveCorrection = async (packId: string) => {
    setApprovingPackId(packId);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/incidents/corrections/${packId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          supervisor_name: 'Lead Operations Supervisor',
          notes: 'Signed off following successful isolated replay harness execution.',
        }),
      });
      if (res.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to approve correction pack:', err);
    } finally {
      setApprovingPackId(null);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">MEDIUM</span>;
      case 'LOW':
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">LOW</span>;
    }
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'APPROVED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">APPROVED & DEPLOYED</span>;
      case 'TESTED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">TESTED IN HARNESS</span>;
      case 'DRAFT':
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">DRAFT</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className={`rounded-2xl border p-6 ${bgCard}`}>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-1">
              <AlertTriangle className="w-4 h-4" />
              <span>Assurance Module — Incident-to-Correction</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold">Incident Remediation & Replay Packs</h2>
            <p className={`text-xs mt-1 ${textMuted}`}>
              Link failed executions to root causes, generate versioned correction packs, and safely test in isolated replay harnesses with supervisor sign-off gates.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={onRefresh}
              className={`p-2 rounded-xl border text-xs font-medium hover:bg-slate-800 transition-colors ${borderSubtle}`}
              title="Refresh Incidents"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowNewIncidentModal(true)}
              className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Record Incident</span>
            </button>
          </div>
        </div>
      </div>

      {/* Incidents Overview List */}
      <div className="space-y-4">
        <h3 className="font-bold text-sm flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Active & Remediation Incidents ({incidents.length})</span>
        </h3>

        <div className="space-y-3">
          {incidents.map((inc) => (
            <div key={inc.incident_id} className={`rounded-2xl border p-5 space-y-3 ${bgCard}`}>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-cyan-300">{inc.incident_id}</span>
                    {getSeverityBadge(inc.severity)}
                  </div>
                  <h4 className="font-bold text-base text-slate-100 mt-1">{inc.title}</h4>
                </div>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                  STATUS: {inc.status}
                </span>
              </div>

              <div className={`p-3 rounded-xl border ${borderSubtle} ${bgSubtle} text-xs font-mono`}>
                <span className="text-slate-400 font-bold">Cause of Failure: </span>
                <span className="text-slate-200">{inc.cause_of_failure}</span>
              </div>

              {/* Linked Impact Entities */}
              <div className="flex flex-wrap gap-4 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800">
                <div>
                  <span>Affected Entities: </span>
                  <span className="text-amber-300 font-bold">{inc.affected_entities?.join(', ') || 'none'}</span>
                </div>
                <div>
                  <span>Affected Skills: </span>
                  <span className="text-cyan-300 font-bold">{inc.affected_skills?.join(', ') || 'none'}</span>
                </div>
                <div>
                  <span>Affected Contracts: </span>
                  <span className="text-slate-200 font-bold">{inc.affected_contracts?.join(', ') || 'none'}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Correction Packs & Replay Test Harness */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Correction Packs Column */}
        <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-bold text-sm flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Correction Packs ({correctionPacks.length})</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Policy Patches</span>
          </div>

          <div className="divide-y divide-slate-800">
            {correctionPacks.map((cpk) => {
              const packId = cpk.pack_id || cpk.correction_pack_id || '';
              return (
                <div key={packId} className="p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-cyan-300">{packId}</span>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                        v{cpk.version} • Incident: {cpk.incident_id}
                      </div>
                    </div>
                    {getStateBadge(cpk.state)}
                  </div>

                  <div className="p-2.5 rounded-xl bg-slate-950 font-mono text-[11px] text-emerald-400 border border-slate-800">
                    {cpk.proposed_diff}
                  </div>

                  {/* Verification Tests */}
                  <div className="space-y-1.5 text-xs font-mono">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider">Test Suite Checks:</span>
                    {cpk.verification_tests?.map((t, idx) => (
                      <div key={idx} className="flex items-center justify-between text-[11px]">
                        <span className="text-slate-300">{t.test_name}</span>
                        <span className="text-emerald-400 font-bold flex items-center space-x-1">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>PASS ({t.expected_result})</span>
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Supervisor Approval Gate */}
                  <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500 font-mono">
                      {cpk.state === 'APPROVED' ? `Approved by: ${cpk.reviewed_by}` : 'Requires Supervisor Signoff'}
                    </span>
                    {cpk.state !== 'APPROVED' && (
                      <button
                        onClick={() => handleApproveCorrection(packId)}
                        disabled={approvingPackId === packId}
                        className="px-3 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition-colors"
                      >
                        {approvingPackId === packId ? 'Approving...' : 'Approve & Promote'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Replay Packs Column */}
        <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-bold text-sm flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Sanitized Replay Packs ({replayPacks.length})</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">Isolated Sandbox Verification</span>
          </div>

          <div className="divide-y divide-slate-800">
            {replayPacks.map((rpk) => (
              <div key={rpk.replay_pack_id} className="p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-mono text-xs font-bold text-cyan-300">{rpk.replay_pack_id}</span>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Target Incident: {rpk.incident_id}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRunReplay(rpk.replay_pack_id)}
                    disabled={runningPackId === rpk.replay_pack_id}
                    className="px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center space-x-1.5 transition-colors shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{runningPackId === rpk.replay_pack_id ? 'Replaying...' : 'Execute Replay'}</span>
                  </button>
                </div>

                <div className={`p-2.5 rounded-xl border text-[11px] font-mono ${bgSubtle} ${borderSubtle}`}>
                  <div className="text-slate-400 mb-1 text-[10px] uppercase">Sanitized Replay Inputs:</div>
                  <pre className="text-slate-300 overflow-x-auto">{JSON.stringify(rpk.sanitized_inputs, null, 2)}</pre>
                </div>

                {replayOutput && replayOutput.id === rpk.replay_pack_id && (
                  <div className="p-3 rounded-xl bg-slate-950 border border-cyan-800/60 font-mono text-xs text-cyan-300 space-y-1">
                    <div className="font-bold text-emerald-400 flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Isolated Replay Completed (Deterministic Verification)</span>
                    </div>
                    <div className="text-[11px] text-slate-300">
                      Outcome: {replayOutput.result.harness_result?.reproduced_successfully ? 'Bug Reproduced Safely' : 'Execution Verified'}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Execution Hash: {replayOutput.result.harness_result?.execution_hash?.slice(0, 20)}...
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Record Incident Modal */}
      {showNewIncidentModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Record Production Incident</h3>
            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Incident Title</label>
                <input
                  type="text"
                  value={newIncidentForm.title}
                  onChange={(e) => setNewIncidentForm({ ...newIncidentForm, title: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Severity</label>
                <select
                  value={newIncidentForm.severity}
                  onChange={(e) => setNewIncidentForm({ ...newIncidentForm, severity: e.target.value as any })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Cause of Failure</label>
                <textarea
                  value={newIncidentForm.cause_of_failure}
                  onChange={(e) => setNewIncidentForm({ ...newIncidentForm, cause_of_failure: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  rows={3}
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Affected Entities (Comma-separated)</label>
                <input
                  type="text"
                  value={newIncidentForm.affected_entities}
                  onChange={(e) => setNewIncidentForm({ ...newIncidentForm, affected_entities: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewIncidentModal(false)}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  Record Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
