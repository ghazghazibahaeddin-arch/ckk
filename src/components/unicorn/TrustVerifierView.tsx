import React, { useEffect, useState } from 'react';
import { Award, FileCheck2, ShieldAlert, CheckCircle2, Copy, Search } from 'lucide-react';
import type { AgentTrustPassport, ReceiptProofVerification } from '../../assurance/unicorn_engine';

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  agents: Array<{ agent_id: string; name: string }>;
  receipts: Array<{ receipt_id: string; status: string; action: { capability: string; target: string }; timestamp: string }>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export const TrustVerifierView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  agents,
  receipts,
  onNotification,
}) => {
  const fetcher = apiFetch || fetch;
  const [selectedReceiptId, setSelectedReceiptId] = useState(receipts[0]?.receipt_id || '');
  const [verification, setVerification] = useState<ReceiptProofVerification | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.agent_id || '');
  const [passport, setPassport] = useState<AgentTrustPassport | null>(null);
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);

  const cardCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-xs';
  const subCls = isDark ? 'bg-slate-950/70 border-slate-800' : 'bg-slate-50 border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';

  useEffect(() => {
    if (!selectedReceiptId && receipts.length > 0) setSelectedReceiptId(receipts[0].receipt_id);
  }, [receipts, selectedReceiptId]);

  useEffect(() => {
    if (!selectedAgentId && agents.length > 0) setSelectedAgentId(agents[0].agent_id);
  }, [agents, selectedAgentId]);

  const loadPassport = async (agentId: string) => {
    if (!agentId) return;
    try {
      const res = await fetcher(`/api/v1/agents/${agentId}/passport`);
      if (res.ok) setPassport(await res.json());
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (selectedAgentId) loadPassport(selectedAgentId);
  }, [selectedAgentId, tenantId]);

  const handleVerifyReceipt = async (simulateTamper: boolean) => {
    if (!selectedReceiptId) {
      onNotification('اختر إيصال قرار أو شغّل إجراء عبر Action Gate أولاً.', 'info');
      return;
    }
    try {
      const res = await fetcher(`/api/v1/receipts/${selectedReceiptId}/verify-proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          simulateTamper
            ? {
                tamper_simulation: {
                  status: 'ALLOW',
                  target: 'attacker.exfiltrate.io',
                },
              }
            : {}
        ),
      });
      if (res.ok) {
        const data: ReceiptProofVerification = await res.json();
        setVerification(data);
        onNotification(
          data.verified
            ? 'Signature VALID & Audit Hash Chain Verified.'
            : `TAMPER DETECTED on fields: ${data.tampered_fields.join(', ')}`,
          data.verified ? 'success' : 'error'
        );
      } else {
        onNotification('Receipt not found or inaccessible.', 'error');
      }
    } catch {
      onNotification('Error verifying cryptographic receipt.', 'error');
    }
  };

  const liveOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const markdownBadge = passport
    ? `[![CCK Verified ${passport.grade}](${liveOrigin}/api/v1/agents/${passport.agent_id}/badge.svg)](${liveOrigin})`
    : '';

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <Award className="w-5 h-5 text-emerald-400" />
          <span>Cryptographic Receipt Verifier &amp; Agent Trust Passport</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          تحقق رياضياً من صحة التوقيع المشفر HMAC-SHA256 لأي سند قرار وارتباطه بسلسلة التدقيق، واستخرج شهادة ثقة حية (Trust Passport) لوكلائك.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Zero-Trust Receipt Verifier */}
        <div className={`p-5 rounded-2xl border space-y-4 ${cardCls}`}>
          <h3 className="text-sm font-bold flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-cyan-400" />
            <span>المدقق التشفيري لسندات القرار (Zero-Trust Proof Verifier)</span>
          </h3>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">اختر إيصال قرار (Receipt ID)</label>
              {receipts.length > 0 ? (
                <select
                  value={selectedReceiptId}
                  onChange={(e) => setSelectedReceiptId(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${inputCls}`}
                >
                  {receipts.map((r) => (
                    <option key={r.receipt_id} value={r.receipt_id}>
                      {r.receipt_id} · {r.status} · {r.action.capability}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  value={selectedReceiptId}
                  onChange={(e) => setSelectedReceiptId(e.target.value)}
                  placeholder="rcpt-..."
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${inputCls}`}
                />
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => handleVerifyReceipt(false)}
                className="flex-1 py-2.5 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                <Search className="w-3.5 h-3.5" />
                <span>تحقق من التوقيع والسلسلة</span>
              </button>
              <button
                onClick={() => handleVerifyReceipt(true)}
                className="py-2.5 px-3.5 rounded-xl border border-rose-500/40 bg-rose-950/30 hover:bg-rose-900/40 text-rose-300 font-semibold text-xs flex items-center gap-1.5 whitespace-nowrap"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>محاكاة تزوير (Tamper Test)</span>
              </button>
            </div>
          </div>

          {verification && (
            <div
              className={`p-4 rounded-xl border space-y-2.5 text-xs ${
                verification.verified
                  ? 'border-emerald-500/40 bg-emerald-950/20'
                  : 'border-rose-500/50 bg-rose-950/30'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold">
                  {verification.verified ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  )}
                  <span>
                    {verification.verified
                      ? 'CRYPTOGRAPHIC PROOF VALID'
                      : 'INTEGRITY FAILURE / TAMPER DETECTED'}
                  </span>
                </div>
                <span className="font-mono text-[11px] text-slate-400">{verification.receipt_id}</span>
              </div>

              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div>Signature Valid: {String(verification.signature_valid)}</div>
                <div>Chain Linked: {String(verification.chain_linked)}</div>
              </div>

              {verification.tampered_fields.length > 0 && (
                <div className="text-[11px] font-mono text-rose-300">
                  Tampered Fields: {verification.tampered_fields.join(', ')}
                </div>
              )}

              <div className="space-y-1 pt-1 border-t border-slate-800/80 font-mono text-[10px] text-slate-400 break-all">
                <div>Stored Digest: {verification.stored_digest}</div>
                <div>Computed Digest: {verification.computed_digest}</div>
                <div>HMAC Proof: {verification.hmac_signature}</div>
              </div>
            </div>
          )}
        </div>

        {/* Right: Agent Trust Passport */}
        <div className={`p-5 rounded-2xl border space-y-4 ${cardCls}`}>
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <Award className="w-4 h-4 text-amber-400" />
              <span>جواز موثوقية الوكيل (Agent Trust Passport)</span>
            </h3>
            {agents.length > 0 && (
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono ${inputCls}`}
              >
                {agents.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          {!passport ? (
            <div className="text-xs text-slate-400 py-8 text-center">سجّل وكيلاً لعرض جواز الموثوقية الحي والشارة الموثقة.</div>
          ) : (
            <div className="space-y-4">
              <div className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${subCls}`}>
                <div>
                  <div className="text-xs text-slate-400">{passport.agent_name} · {passport.framework}</div>
                  <div className="text-2xl font-extrabold font-mono tabular-nums mt-1">
                    Grade {passport.grade}{' '}
                    <span className="text-sm font-normal text-slate-400">({passport.trust_score}/100)</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 mt-1">
                    Passport Hash: {passport.passport_hash}
                  </div>
                </div>
                <img
                  src={`${liveOrigin}/api/v1/agents/${passport.agent_id}/badge.svg`}
                  alt={`CCK Trust Badge ${passport.grade}`}
                  className="h-8 shrink-0"
                />
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">إجمالي التقييمات</div>
                  <div className="text-base font-bold font-mono tabular-nums mt-1">{passport.total_evaluations}</div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">مخاطر تم منعها</div>
                  <div className="text-base font-bold font-mono tabular-nums text-rose-400 mt-1">{passport.blocked_count}</div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">قيمة مالية محمية</div>
                  <div className="text-base font-bold font-mono tabular-nums text-emerald-400 mt-1">
                    ${passport.estimated_usd_protected.toLocaleString()}
                  </div>
                </div>
                <div className={`p-3 rounded-xl border ${subCls}`}>
                  <div className="text-[11px] text-slate-400">حوادث مفتوحة</div>
                  <div className="text-base font-bold font-mono tabular-nums mt-1">{passport.open_incidents}</div>
                </div>
              </div>

              <div className={`p-3 rounded-xl border space-y-2 ${subCls}`}>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-semibold">Embeddable Trust Badge (Markdown for GitHub / Docs)</span>
                  <button
                    onClick={() => {
                      navigator.clipboard?.writeText(markdownBadge);
                      setCopiedMarkdown(true);
                      setTimeout(() => setCopiedMarkdown(false), 2000);
                    }}
                    className="px-2.5 py-1 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs flex items-center gap-1"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copiedMarkdown ? 'تم النسخ!' : 'نسخ'}</span>
                  </button>
                </div>
                <pre className="text-[11px] font-mono text-cyan-200 overflow-x-auto">{markdownBadge}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
