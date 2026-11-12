import React, { useState } from 'react';
import {
  Lock,
  ShieldCheck,
  Plus,
  RefreshCw,
  CheckCircle2,
  DollarSign,
  Globe,
  Key,
  Shield,
  Layers,
  Clock,
} from 'lucide-react';
import type { AgentMandateRecord, BusinessInvariantRule } from '../../assurance/types';

interface MandatesViewProps {
  mandates: AgentMandateRecord[];
  invariants: BusinessInvariantRule[];
  onRefresh: () => void;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const MandatesView: React.FC<MandatesViewProps> = ({
  mandates,
  invariants,
  onRefresh,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [showNewModal, setShowNewModal] = useState(false);
  const [newForm, setNewForm] = useState({
    agent_id: 'agt-console',
    total_budget: 2000,
    single_action_limit: 300,
    currency: 'USD',
    allowed_domains: '*.stripe.com, *.fedex.com, *.acme.internal, courier.fedex',
    valid_until_days: 30,
  });

  const handleCreateMandate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/mandates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: newForm.agent_id,
          spending_limits: {
            total_budget: Number(newForm.total_budget),
            single_action_limit: Number(newForm.single_action_limit),
            currency: newForm.currency,
          },
          destination_restrictions: {
            allowed_domains: newForm.allowed_domains.split(',').map((s) => s.trim()).filter(Boolean),
          },
          time_limit: {
            valid_from: new Date().toISOString(),
            valid_until: new Date(Date.now() + 86400000 * Number(newForm.valid_until_days)).toISOString(),
          },
        }),
      });
      if (res.ok) {
        setShowNewModal(false);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to create mandate:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className={`rounded-2xl border p-6 ${bgCard}`}>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-1">
              <Lock className="w-4 h-4" />
              <span>Assurance Module — Mandate OS + INVARIANT</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold">Delegated Authority & Invariant Rules</h2>
            <p className={`text-xs mt-1 ${textMuted}`}>
              Cryptographically signed agent mandates with spending ceilings, egress domain restrictions, and inviolable business invariants.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={onRefresh}
              className={`p-2 rounded-xl border text-xs font-medium hover:bg-slate-800 transition-colors ${borderSubtle}`}
              title="Refresh Mandates"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowNewModal(true)}
              className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Delegated Mandate</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mandates Cards */}
      <div className="space-y-4">
        <h3 className="font-bold text-sm flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Active Agent Mandates ({mandates.length})</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {mandates.length === 0 ? (
            <div className={`col-span-2 p-8 text-center text-slate-400 text-xs font-sans rounded-2xl border ${bgCard}`}>
              No mandates created yet. Click &ldquo;New Delegated Mandate&rdquo; to establish bound authority.
            </div>
          ) : (
            mandates.map((m) => {
              const spentPct = Math.min(100, Math.round((m.spending_limits.current_spent / m.spending_limits.total_budget) * 100));
              return (
                <div key={m.mandate_id} className={`rounded-2xl border p-5 space-y-4 ${bgCard}`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-cyan-300">{m.mandate_id}</span>
                      <h4 className="font-bold text-sm text-slate-200 mt-0.5">
                        Agent: <span className="font-mono text-slate-100">{m.agent_id}</span>
                      </h4>
                    </div>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      {m.status}
                    </span>
                  </div>

                  {/* Spending Progress */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-400">Budget Consumed:</span>
                      <span className="font-bold text-slate-200">
                        ${m.spending_limits.current_spent} / ${m.spending_limits.total_budget} {m.spending_limits.currency} ({spentPct}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${spentPct > 80 ? 'bg-amber-500' : 'bg-cyan-500'}`}
                        style={{ width: `${spentPct}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Single-Action Ceiling:</span>
                      <span className="font-mono font-semibold text-emerald-400">${m.spending_limits.single_action_limit}</span>
                    </div>
                  </div>

                  {/* Egress Restrictions */}
                  <div className="pt-3 border-t border-slate-800 space-y-1.5">
                    <div className="flex items-center space-x-1 text-[11px] text-slate-400 font-mono">
                      <Globe className="w-3.5 h-3.5" />
                      <span>Authorized Egress Destinations:</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {m.destination_restrictions?.allowed_domains?.map((d) => (
                        <span key={d} className="px-2 py-0.5 rounded-lg bg-slate-800 text-[10px] font-mono text-slate-300 border border-slate-700">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Cryptographic Signature Footer */}
                  <div className={`pt-3 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono ${textMuted}`}>
                    <div className="flex items-center space-x-1 text-emerald-400">
                      <Key className="w-3 h-3" />
                      <span>HMAC-SHA256 Signed</span>
                    </div>
                    <span className="truncate max-w-[140px]" title={m.signature}>
                      {m.signature.slice(0, 16)}...
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Invariants Catalog */}
      <div className={`rounded-2xl border overflow-hidden ${bgCard}`}>
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-sm flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Business Invariant Rules Catalog ({invariants.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-400">Zero-Bypass Policy Enforcement</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 ${bgSubtle}`}>
              <tr>
                <th className="py-2.5 px-4">Invariant ID</th>
                <th className="py-2.5 px-4">Invariant Rule Name</th>
                <th className="py-2.5 px-4">Description</th>
                <th className="py-2.5 px-4">Rule Type</th>
                <th className="py-2.5 px-4">Enforcement</th>
                <th className="py-2.5 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {invariants.map((inv) => (
                <tr key={inv.invariant_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 font-bold text-cyan-300">{inv.invariant_id}</td>
                  <td className="py-3 px-4 font-bold text-slate-200">{inv.name}</td>
                  <td className="py-3 px-4 text-slate-300 max-w-sm truncate">{inv.description}</td>
                  <td className="py-3 px-4">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                      {inv.rule_type}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      {inv.enforcement_effect}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-emerald-400 flex items-center space-x-1 font-sans text-xs">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Active</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* New Mandate Modal */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Issue Delegated Agent Mandate</h3>
            <p className={`text-xs ${textMuted}`}>
              Issue cryptographically signed authority boundaries and financial limit ceilings for an agent.
            </p>

            <form onSubmit={handleCreateMandate} className="space-y-3 text-xs">
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
                  <label className="block text-slate-400 mb-1 font-mono">Total Budget ($)</label>
                  <input
                    type="number"
                    value={newForm.total_budget}
                    onChange={(e) => setNewForm({ ...newForm, total_budget: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Single-Action Ceiling ($)</label>
                  <input
                    type="number"
                    value={newForm.single_action_limit}
                    onChange={(e) => setNewForm({ ...newForm, single_action_limit: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Allowed Egress Domains (Comma-separated)</label>
                <input
                  type="text"
                  value={newForm.allowed_domains}
                  onChange={(e) => setNewForm({ ...newForm, allowed_domains: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Validity Window (Days)</label>
                <input
                  type="number"
                  value={newForm.valid_until_days}
                  onChange={(e) => setNewForm({ ...newForm, valid_until_days: Number(e.target.value) })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
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
                  Issue Mandate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
