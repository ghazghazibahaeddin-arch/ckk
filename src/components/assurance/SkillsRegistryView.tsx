import React, { useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Plus,
  RefreshCw,
  Award,
  Key,
  Clock,
  Layers,
  Trash2,
} from 'lucide-react';
import type { SkillRecord } from '../../assurance/types';

interface SkillsRegistryViewProps {
  skills: SkillRecord[];
  onRefresh: () => void;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  isDark: boolean;
  bgCard: string;
  bgSubtle: string;
  textMuted: string;
  borderSubtle: string;
}

export const SkillsRegistryView: React.FC<SkillsRegistryViewProps> = ({
  skills,
  onRefresh,
  tenantId: _tenantId,
  apiFetch,
  isDark,
  bgCard,
  bgSubtle,
  textMuted,
  borderSubtle,
}) => {
  const [selectedSkill, setSelectedSkill] = useState<SkillRecord | null>(null);
  const [showNewModal, setShowNewModal] = useState(false);
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [confirmRevokeSkillId, setConfirmRevokeSkillId] = useState<string | null>(null);

  // New Skill Form
  const [newForm, setNewForm] = useState({
    name: 'FedEx Smart Dispatcher',
    version: '1.2.0',
    publisher_name: 'Logistics Core Inc',
    publisher_domain: 'fedex.partner.com',
    domain: 'logistics',
    reviewer_name: 'ACME Security Audit Bureau',
    verified_credential: true,
    credential_details: 'ISO-27001 / SOC-2 Accredited Auditor Certification',
    valid_days: 90,
  });

  // Review Form
  const [reviewForm, setReviewForm] = useState({
    reviewer_name: 'Lead Compliance Auditor',
    reviewer_id: 'rev-lead-01',
    verified_credential: true,
    credential_details: 'Accredited SOC-2 Type II Independent Reviewer',
    review_notes: 'Verified code package against supply-chain integrity standards.',
  });

  const handleRegisterSkill = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher('/api/v1/skills', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newForm.name,
          version: newForm.version,
          publisher: {
            name: newForm.publisher_name,
            domain: newForm.publisher_domain,
            verified: true,
          },
          domain: newForm.domain,
          review_info: {
            reviewer_name: newForm.reviewer_name,
            reviewer_id: `rev-${Date.now()}`,
            verified_credential: newForm.verified_credential,
            credential_details: newForm.credential_details,
            review_notes: 'Initial registration audit',
          },
          expires_at: new Date(Date.now() + 86400000 * Number(newForm.valid_days)).toISOString(),
        }),
      });
      if (res.ok) {
        setShowNewModal(false);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to register skill:', err);
    }
  };

  const handlePromoteReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSkill) return;
    setReviewing(true);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/skills/${selectedSkill.skill_id}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reviewForm),
      });
      if (res.ok) {
        setShowReviewModal(false);
        setSelectedSkill(null);
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to review skill:', err);
    } finally {
      setReviewing(false);
    }
  };

  const executeRevokeSkill = async (skillId: string) => {
    setRevokingId(skillId);
    try {
      const fetcher = apiFetch || fetch;
      const res = await fetcher(`/api/v1/skills/${skillId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Revoked via security operations console' }),
      });
      if (res.ok) {
        onRefresh();
      }
    } catch (err) {
      console.error('Failed to revoke skill:', err);
    } finally {
      setRevokingId(null);
      setConfirmRevokeSkillId(null);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'VALID':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">VALID</span>;
      case 'UNVERIFIED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">UNVERIFIED ATTESTATION</span>;
      case 'REVIEW_REQUIRED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">REVIEW REQUIRED</span>;
      case 'EXPIRED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">EXPIRED</span>;
      case 'REVOKED':
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">REVOKED</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className={`rounded-2xl border p-6 ${bgCard}`}>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-1">
              <Sparkles className="w-4 h-4" />
              <span>Assurance Module — Skill Trust & Lifecycle</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold">Skill Registry & Integrity Gate</h2>
            <p className={`text-xs mt-1 ${textMuted}`}>
              Distinguish verified reviewer credentials from unverified peer attestations. Enforce cryptographic bundle hashes and automated expiry.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={onRefresh}
              className={`p-2 rounded-xl border text-xs font-medium hover:bg-slate-800 transition-colors ${borderSubtle}`}
              title="Refresh Skills"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowNewModal(true)}
              className="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-xs"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Skill</span>
            </button>
          </div>
        </div>
      </div>

      {/* Skills Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {skills.map((s) => (
          <div key={s.skill_id} className={`rounded-2xl border p-5 space-y-4 ${bgCard}`}>
            <div className="flex items-start justify-between">
              <div>
                <span className="font-mono text-xs font-bold text-cyan-300">{s.skill_id}</span>
                <h4 className="font-bold text-base text-slate-100 mt-0.5">{s.name}</h4>
                <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                  v{s.version} • Publisher: {s.publisher.name} ({s.publisher.domain})
                </div>
              </div>
              <div>{getStatusBadge(s.status)}</div>
            </div>

            {/* Review Credentials Box */}
            <div className={`p-3 rounded-xl border ${s.review_info?.verified_credential ? 'border-emerald-500/30 bg-emerald-950/20' : 'border-amber-500/30 bg-amber-950/20'} space-y-1.5`}>
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Review Credential:</span>
                {s.review_info?.verified_credential ? (
                  <span className="text-emerald-400 font-bold flex items-center space-x-1">
                    <Award className="w-3.5 h-3.5" />
                    <span>Accredited Auditor</span>
                  </span>
                ) : (
                  <span className="text-amber-400 font-bold flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Unverified Peer Attestation</span>
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-300 font-medium">
                Reviewer: {s.review_info?.reviewer_name || 'Anonymous Community Reviewer'}
              </div>
              {s.review_info?.credential_details && (
                <div className="text-[11px] text-slate-400 font-sans">{s.review_info.credential_details}</div>
              )}
            </div>

            {/* Cryptographic Hash */}
            <div className={`p-2.5 rounded-xl border text-[10px] font-mono ${bgSubtle} ${borderSubtle} flex items-center justify-between`}>
              <span className="text-slate-400">Bundle SHA-256:</span>
              <span className="text-slate-200 truncate max-w-[200px]" title={s.cryptographic_hash}>
                {s.cryptographic_hash.slice(0, 18)}...
              </span>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">
                Expires: {new Date(s.expires_at).toLocaleDateString()}
              </span>
              <div className="space-x-2">
                {s.status === 'UNVERIFIED' && (
                  <button
                    onClick={() => {
                      setSelectedSkill(s);
                      setShowReviewModal(true);
                    }}
                    className="px-2.5 py-1 rounded-lg bg-cyan-900/40 hover:bg-cyan-800/60 text-cyan-300 border border-cyan-700/50 text-[10px] font-bold transition-colors"
                  >
                    Accredited Review
                  </button>
                )}
                {s.status !== 'REVOKED' && (
                  <button
                    onClick={() => setConfirmRevokeSkillId(s.skill_id)}
                    disabled={revokingId === s.skill_id}
                    className="px-2.5 py-1 rounded-lg bg-rose-900/30 hover:bg-rose-800/50 text-rose-300 border border-rose-800/40 text-[10px] font-bold transition-colors"
                  >
                    {revokingId === s.skill_id ? 'Revoking...' : 'Revoke Skill'}
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Review Modal */}
      {showReviewModal && selectedSkill && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Accredited Review & Verification</h3>
            <p className={`text-xs ${textMuted}`}>
              Promote skill <span className="font-mono text-cyan-400">{selectedSkill.name}</span> to VALID with verified auditor credentials.
            </p>

            <form onSubmit={handlePromoteReview} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Reviewer Name</label>
                <input
                  type="text"
                  value={reviewForm.reviewer_name}
                  onChange={(e) => setReviewForm({ ...reviewForm, reviewer_name: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Auditor Credential Details</label>
                <input
                  type="text"
                  value={reviewForm.credential_details}
                  onChange={(e) => setReviewForm({ ...reviewForm, credential_details: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Audit Review Notes</label>
                <textarea
                  value={reviewForm.review_notes}
                  onChange={(e) => setReviewForm({ ...reviewForm, review_notes: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  rows={3}
                  required
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowReviewModal(false)}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={reviewing}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  {reviewing ? 'Verifying...' : 'Approve & Promote to VALID'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Skill Modal */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`max-w-md w-full rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <h3 className="text-lg font-bold">Register Agent Skill</h3>
            <form onSubmit={handleRegisterSkill} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Skill Name</label>
                <input
                  type="text"
                  value={newForm.name}
                  onChange={(e) => setNewForm({ ...newForm, name: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Publisher Name</label>
                  <input
                    type="text"
                    value={newForm.publisher_name}
                    onChange={(e) => setNewForm({ ...newForm, publisher_name: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Domain / Category</label>
                  <input
                    type="text"
                    value={newForm.domain}
                    onChange={(e) => setNewForm({ ...newForm, domain: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Reviewer Name</label>
                <input
                  type="text"
                  value={newForm.reviewer_name}
                  onChange={(e) => setNewForm({ ...newForm, reviewer_name: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Credential Details</label>
                <input
                  type="text"
                  value={newForm.credential_details}
                  onChange={(e) => setNewForm({ ...newForm, credential_details: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${bgSubtle} ${borderSubtle}`}
                  required
                />
              </div>
              <div>
                <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newForm.verified_credential}
                    onChange={(e) => setNewForm({ ...newForm, verified_credential: e.target.checked })}
                    className="rounded border-slate-700 text-cyan-500"
                  />
                  <span>Reviewer possesses verified formal accreditation</span>
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
                  Register Skill
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Skill Revocation */}
      {confirmRevokeSkillId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fadeIn">
          <div className={`w-full max-w-md rounded-xl ${bgCard} border ${borderSubtle} p-6 space-y-4 shadow-2xl`}>
            <div className="flex items-center gap-3 text-rose-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="font-bold text-lg text-white">Confirm Skill Revocation</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Are you sure you want to revoke skill <span className="font-mono font-bold text-rose-300">{confirmRevokeSkillId}</span>?
              All future execution attempts citing this skill will be immediately blocked fail-closed by CCK Action Gate.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeSkillId(null)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle} text-slate-300 hover:text-white transition-colors`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => executeRevokeSkill(confirmRevokeSkillId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Revoke Skill Now
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
