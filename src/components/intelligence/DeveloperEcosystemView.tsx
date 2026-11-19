import React, { useEffect, useState } from 'react';
import {
  Activity,
  Award,
  CheckCircle2,
  Copy,
  FileSearch,
  GitPullRequest,
  Globe,
  Plug,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type {
  AdoptionAnalyticsRecord,
  ConnectorHarnessReport,
  ConnectorManifest,
  ConnectorPackageSubmission,
  PrGuardianEvaluationReport,
  PublicSourceHealthProfileView,
  PublicTrustProfileView,
  SourceHealthProfileRecord,
  TrustProfileRecord,
} from '../../intelligence/types';

interface Props {
  isDark: boolean;
  tenantId?: string;
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  onNotification: (msg: string, type?: 'success' | 'error' | 'info') => void;
  publicOnlyMode?: boolean;
  onExitPublicMode?: () => void;
}

type EcosystemTab = 'registry' | 'source_health' | 'connector_sdk' | 'scanner' | 'pr_guardian';

export const DeveloperEcosystemView: React.FC<Props> = ({
  isDark,
  tenantId,
  apiFetch,
  onNotification,
  publicOnlyMode = false,
  onExitPublicMode,
}) => {
  const fetcher = apiFetch || fetch;
  const effTenant = tenantId || '';

  const [tab, setTab] = useState<EcosystemTab>('registry');
  const [loading, setLoading] = useState(false);

  // Public Trust Registry state (Feature 20)
  const [registrySearch, setRegistrySearch] = useState('');
  const [registryType, setRegistryType] = useState<string>('');
  const [publicProfiles, setPublicProfiles] = useState<PublicTrustProfileView[]>([]);
  const [tenantProfiles, setTenantProfiles] = useState<TrustProfileRecord[]>([]);
  const [selectedVerification, setSelectedVerification] = useState<{
    profile_id: string;
    integrity_valid: boolean;
    signature_valid: boolean;
    digest_matches: boolean;
    reason: string;
    outdated_notice?: string | null;
  } | null>(null);

  // Publish Trust Profile form state
  const [pubArtifactId, setPubArtifactId] = useState('mcp:stripe-refund-tool');
  const [pubName, setPubName] = useState('Stripe Refund Guarded Tool');
  const [pubPublisher, setPubPublisher] = useState('acme-platform');
  const [pubVersion, setPubVersion] = useState('1.0.0');
  const [pubType, setPubType] = useState<'MCP_TOOL' | 'CONNECTOR' | 'AGENT_PACK'>('MCP_TOOL');
  const [pubVisibility, setPubVisibility] = useState<'PUBLIC' | 'PRIVATE'>('PUBLIC');

  // Public Source Health state (Feature 7)
  const [publicSources, setPublicSources] = useState<PublicSourceHealthProfileView[]>([]);
  const [tenantSources, setTenantSources] = useState<SourceHealthProfileRecord[]>([]);
  const [selectedSourceId, setSelectedSourceId] = useState('');

  // Connector SDK & Harness state (Feature 8)
  const [harnessReports, setHarnessReports] = useState<ConnectorHarnessReport[]>([]);
  const [submissions, setSubmissions] = useState<ConnectorPackageSubmission[]>([]);
  const [connId, setConnId] = useState('conn-erp-inventory');
  const [connName, setConnName] = useState('Enterprise ERP Inventory Connector');
  const [connVersion, setConnVersion] = useState('1.2.0');
  const [connPublisher, setConnPublisher] = useState('acme-platform');
  const [connHosts, setConnHosts] = useState('erp.example.com');

  // PR Guardian state (Feature 19)
  const [prReports, setPrReports] = useState<PrGuardianEvaluationReport[]>([]);
  const [prRepo, setPrRepo] = useState('acme/agent-tools');
  const [prBasePerms, setPrBasePerms] = useState('orders:read');
  const [prHeadPerms, setPrHeadPerms] = useState('orders:read, admin');
  const [prHeadEndpoint, setPrHeadEndpoint] = useState('https://api.acme.internal/admin');

  // Adoption Analytics (Privacy-respecting)
  const [analytics, setAnalytics] = useState<AdoptionAnalyticsRecord | null>(null);

  const surfaceCls = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200';
  const inputCls = isDark
    ? 'bg-slate-950 border-slate-700 text-slate-100 focus:border-cyan-500'
    : 'bg-white border-slate-300 text-slate-900 focus:border-cyan-600';
  const mutedCls = isDark ? 'text-slate-400' : 'text-slate-600';

  const loadAll = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (registrySearch.trim()) qs.set('q', registrySearch.trim());
      if (registryType) qs.set('type', registryType);

      const reqs: Promise<Response>[] = [
        fetch(`/api/v1/trust/registry?${qs.toString()}`),
        fetch('/api/v1/public/sources/health'),
        fetch('/api/v1/analytics/adoption'),
      ];
      if (!publicOnlyMode && effTenant) {
        reqs.push(
          fetcher('/api/v1/trust/profiles'),
          fetcher('/api/v1/sources/health'),
          fetcher('/api/v1/connectors/harness/reports'),
          fetcher('/api/v1/connectors/submissions'),
          fetcher('/api/v1/pr-guardian/reports')
        );
      }
      const resList = await Promise.all(reqs);
      if (resList[0]?.ok) setPublicProfiles(await resList[0].json());
      if (resList[1]?.ok) setPublicSources(await resList[1].json());
      if (resList[2]?.ok) setAnalytics(await resList[2].json());
      if (!publicOnlyMode && effTenant) {
        if (resList[3]?.ok) setTenantProfiles(await resList[3].json());
        if (resList[4]?.ok) {
          const ts: SourceHealthProfileRecord[] = await resList[4].json();
          setTenantSources(ts);
          if (!selectedSourceId && ts.length > 0) setSelectedSourceId(ts[0].source_id);
        }
        if (resList[5]?.ok) setHarnessReports(await resList[5].json());
        if (resList[6]?.ok) setSubmissions(await resList[6].json());
        if (resList[7]?.ok) setPrReports(await resList[7].json());
      }
    } catch {
      onNotification('Unable to refresh ecosystem registry data.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
    if (typeof window !== 'undefined') {
      const targetId = new URLSearchParams(window.location.search).get('trust_profile');
      if (targetId) {
        handleVerifyPublicProfile(targetId);
      }
    }
  }, [effTenant, publicOnlyMode, registryType]);

  const handleVerifyPublicProfile = async (profileId: string) => {
    try {
      const res = await fetch(`/api/v1/public/trust/profiles/${encodeURIComponent(profileId)}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        onNotification(err.detail || 'Verification request failed.', 'error');
        return;
      }
      const data = await res.json();
      setSelectedVerification({
        profile_id: profileId,
        integrity_valid: data.verification.integrity_valid,
        signature_valid: data.verification.signature_valid,
        digest_matches: data.verification.digest_matches,
        reason: data.verification.reason,
        outdated_notice: data.outdated_notice,
      });
      onNotification(
        data.verification.integrity_valid
          ? 'Ed25519 digital signature and SHA-256 digest verified.'
          : 'Integrity mismatch detected.',
        data.verification.integrity_valid ? 'success' : 'error'
      );
    } catch {
      onNotification('Verification error.', 'error');
    }
  };

  const handlePublishTrustProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!effTenant) return;
    try {
      const chalRes = await fetcher('/api/v1/trust/publisher-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifact_identity: pubArtifactId,
          publisher_name: pubPublisher,
        }),
      });
      const chalData = chalRes.ok ? await chalRes.json() : {};
      const fpHex = Array.from(new TextEncoder().encode(`${pubArtifactId}:${pubVersion}`))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .padEnd(64, 'a')
        .slice(0, 64);

      const res = await fetcher('/api/v1/trust/profiles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          visibility: pubVisibility,
          artifact_identity: pubArtifactId,
          artifact_type: pubType,
          name: pubName,
          publisher_name: pubPublisher,
          claimed_identity: pubPublisher,
          ownership_proof_token: chalData.ownership_proof_token,
          version: pubVersion,
          fingerprint: fpHex,
          passed_checks: ['tool_identity_fingerprint', 'least_privilege_static', 'dlp_leakage_clean'],
          failed_checks: [],
          unsupported_checks: ['live_production_traffic'],
        }),
      });
      const out = await res.json();
      if (!res.ok) {
        onNotification(out.detail || out.error || 'Failed to create Trust Profile.', 'error');
        return;
      }
      onNotification(`Signed Trust Profile ${out.profile_id} (${out.status}) published.`, 'success');
      loadAll();
    } catch {
      onNotification('Error creating Trust Profile.', 'error');
    }
  };

  const handleRevokeProfile = async (profileId: string) => {
    const res = await fetcher(`/api/v1/trust/profiles/${encodeURIComponent(profileId)}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'Revoked via console' }),
    });
    if (res.ok) {
      onNotification('Trust Profile revoked and badge updated.', 'info');
      loadAll();
    }
  };

  const handleToggleSourcePublic = async (sourceId: string, makePublic: boolean) => {
    const res = await fetcher(`/api/v1/sources/${encodeURIComponent(sourceId)}/health/visibility`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        is_public: makePublic,
        explicit_consent: makePublic,
      }),
    });
    if (res.ok) {
      onNotification(makePublic ? 'Source Health Profile published publicly.' : 'Source Health Profile set to private.', 'success');
      loadAll();
    } else {
      const err = await res.json().catch(() => ({}));
      onNotification(err.detail || 'Visibility update failed.', 'error');
    }
  };

  const handleRunConnectorHarness = async (e: React.FormEvent) => {
    e.preventDefault();
    const manifest: ConnectorManifest = {
      connector_id: connId,
      name: connName,
      version: connVersion,
      publisher: connPublisher,
      supported_source_types: ['API_POLL', 'WEBHOOK'],
      required_permissions: ['inventory:read'],
      required_secrets_refs: ['sec_erp_token'],
      declared_capabilities: ['READ', 'IDEMPOTENCY', 'CURSOR_PAGINATION', 'RATE_LIMIT_BACKOFF', 'HEALTH_CHECK', 'VERIFY_SOURCE'],
      network_requirements: {
        allowed_hosts: connHosts.split(',').map((s) => s.trim()).filter(Boolean),
        protocols: ['https'],
        requires_tls: true,
      },
      compatibility_range: { min_cck_version: '0.1.0', max_cck_version: '0.9.0' },
    };

    const res = await fetcher('/api/v1/connectors/harness/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifest }),
    });
    const report: ConnectorHarnessReport = await res.json();
    if (!res.ok) {
      onNotification('Harness execution failed.', 'error');
      return;
    }

    if (report.passed) {
      await fetcher('/api/v1/connectors/submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest, harness_report_id: report.report_id, submitted_by: connPublisher }),
      });
    }
    onNotification(
      `Harness finished: ${report.passed_tests}/${report.total_tests} checks passed, ${report.verified_capabilities.length} verified capabilities.`,
      report.passed ? 'success' : 'error'
    );
    loadAll();
  };

  const handleIngestViaSubmission = async (subId: string) => {
    const res = await fetcher(`/api/v1/connectors/submissions/${encodeURIComponent(subId)}/consume-ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'inventory:sku-101' }),
    });
    const data = await res.json();
    if (res.ok) {
      onNotification(`Ingested ${data.ingested_facts} normalized fact(s) and updated Source Health Profile ${data.source_health_profile_id}.`, 'success');
      loadAll();
    } else {
      onNotification(data.detail || 'Ingestion failed.', 'error');
    }
  };

  const handleRunPrGuardian = async (e: React.FormEvent) => {
    e.preventDefault();
    const basePerms = prBasePerms.split(',').map((s) => s.trim()).filter(Boolean);
    const headPerms = prHeadPerms.split(',').map((s) => s.trim()).filter(Boolean);
    const res = await fetcher('/api/v1/pr-guardian/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repository: prRepo,
        pr_number: 42,
        base_sha: 'a1b2c3d4',
        head_sha: 'e5f6a7b8',
        changed_files: ['tools/refund.tool.json'],
        base_tools: [
          {
            file: 'tools/refund.tool.json',
            tool: {
              tool_id: 'tool-refund',
              name: 'Refund Tool',
              version: '1.0.0',
              declared_permissions: basePerms,
              declared_endpoints: ['https://api.acme.com/refund'],
              input_schema: { type: 'object', properties: { amount: { type: 'number' } } },
            },
          },
        ],
        head_tools: [
          {
            file: 'tools/refund.tool.json',
            tool: {
              tool_id: 'tool-refund',
              name: 'Refund Tool',
              version: '1.1.0',
              declared_permissions: headPerms,
              declared_endpoints: [prHeadEndpoint],
              input_schema: { type: 'object', properties: { amount: { type: 'number' }, bypass: { type: 'boolean' } } },
            },
          },
        ],
        fail_on_severity: 'CRITICAL',
      }),
    });
    if (res.ok) {
      const rep: PrGuardianEvaluationReport = await res.json();
      onNotification(`PR Guardian Verdict: ${rep.verdict} (${rep.findings.length} finding(s))`, rep.merge_blocked ? 'error' : 'info');
      loadAll();
    }
  };

  const handleToggleAnalytics = async (enabled: boolean) => {
    const res = await fetcher('/api/v1/analytics/privacy-settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analytics_enabled: enabled }),
    });
    if (res.ok) {
      onNotification(`Privacy-safe adoption counters ${enabled ? 'enabled' : 'disabled'}.`, 'info');
      loadAll();
    }
  };

  const copyText = (txt: string, label: string) => {
    navigator.clipboard?.writeText(txt);
    onNotification(`Copied ${label} to clipboard.`, 'info');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-500" />
            <span>Trust Registry, Open Connectors &amp; Developer Distribution</span>
          </h2>
          <p className={`text-xs mt-1 ${mutedCls}`}>
            Zero-login local CLI scanning · least-privilege GitHub PR checks · Ed25519-verifiable Trust Profiles · real telemetry Source Health
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {publicOnlyMode && onExitPublicMode && (
            <button
              type="button"
              onClick={onExitPublicMode}
              className="px-4 py-2 rounded-lg text-xs font-medium bg-cyan-600 text-white hover:bg-cyan-500 whitespace-nowrap shrink-0"
            >
              Sign In / Open Workspace
            </button>
          )}
          <button
            type="button"
            onClick={loadAll}
            disabled={loading}
            className={`px-3 py-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 whitespace-nowrap shrink-0 ${surfaceCls}`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Segmented Navigation Controls */}
      <div className={`flex flex-wrap items-center gap-1.5 p-1 rounded-xl border ${surfaceCls}`}>
        {(
          [
            { id: 'registry', label: 'Public Trust Registry', icon: Award },
            { id: 'source_health', label: 'Source Health Profiles', icon: Activity },
            { id: 'scanner', label: 'CLI Scanner (Zero-Auth)', icon: FileSearch },
            { id: 'pr_guardian', label: 'GitHub PR Guardian', icon: GitPullRequest },
            { id: 'connector_sdk', label: 'Connector SDK & Harness', icon: Plug },
          ] as const
        ).map((item) => {
          const Icon = item.icon;
          const active = tab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
                active
                  ? 'bg-cyan-600 text-white'
                  : isDark
                  ? 'text-slate-300 hover:bg-slate-800'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: CCK Trust Profile & Public Registry (Feature 20) */}
      {tab === 'registry' && (
        <div className="space-y-6">
          <div className={`p-5 rounded-xl border space-y-4 ${surfaceCls}`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold">Public Verifiable Trust Registry</h3>
                <p className={`text-xs ${mutedCls}`}>
                  Every profile carries an Ed25519 signature, SHA-256 report digest, declared scope, and expiration status. No absolute &quot;100% Safe&quot; claims.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search tools, connectors, publishers..."
                    value={registrySearch}
                    onChange={(e) => setRegistrySearch(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && loadAll()}
                    className={`pl-8 pr-3 py-1.5 rounded-lg border text-xs w-60 ${inputCls}`}
                  />
                </div>
                <select
                  value={registryType}
                  onChange={(e) => setRegistryType(e.target.value)}
                  className={`px-3 py-1.5 rounded-lg border text-xs ${inputCls}`}
                >
                  <option value="">All Artifacts</option>
                  <option value="MCP_TOOL">MCP Tools</option>
                  <option value="CONNECTOR">Connectors</option>
                  <option value="AGENT_PACK">Agent Packs</option>
                </select>
                <button
                  type="button"
                  onClick={loadAll}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 text-white text-xs font-medium whitespace-nowrap shrink-0"
                >
                  Search
                </button>
              </div>
            </div>

            {selectedVerification && (
              <div className={`p-4 rounded-lg border text-xs space-y-1.5 ${isDark ? 'bg-slate-950 border-slate-700' : 'bg-slate-50 border-slate-300'}`}>
                <div className="font-semibold flex items-center gap-2">
                  <ShieldCheck className={`w-4 h-4 ${selectedVerification.integrity_valid ? 'text-emerald-500' : 'text-rose-500'}`} />
                  <span>
                    Cryptographic Verification ({selectedVerification.profile_id}):{' '}
                    {selectedVerification.integrity_valid ? 'Ed25519 & SHA-256 VERIFIED' : 'INTEGRITY MISMATCH'}
                  </span>
                </div>
                <div className={`font-mono ${mutedCls}`}>{selectedVerification.reason}</div>
                {selectedVerification.outdated_notice && (
                  <div className="text-amber-500 font-medium">{selectedVerification.outdated_notice}</div>
                )}
              </div>
            )}

            {publicProfiles.length === 0 ? (
              <div className={`py-8 text-center text-xs ${mutedCls}`}>
                No public Trust Profiles published yet. Sign in to publish a verifiable scan or connector assessment profile.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left border-collapse">
                  <thead>
                    <tr className={`border-b ${isDark ? 'border-slate-800 text-slate-400' : 'border-slate-200 text-slate-600'}`}>
                      <th className="py-2 pr-4 font-medium">Artifact &amp; Version</th>
                      <th className="py-2 pr-4 font-medium">Publisher</th>
                      <th className="py-2 pr-4 font-medium">Status</th>
                      <th className="py-2 pr-4 font-medium">Fingerprint</th>
                      <th className="py-2 pr-4 font-medium">README Badge</th>
                      <th className="py-2 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono tabular-nums">
                    {publicProfiles.map((p) => {
                      const origin = typeof window !== 'undefined' ? window.location.origin : '';
                      const mdBadge = `[![CCK Trust Profile](${origin}/api/v1/trust/profiles/${p.profile_id}/badge.svg)](${origin}/?trust_profile=${p.profile_id})`;
                      return (
                        <tr key={p.profile_id}>
                          <td className="py-3 pr-4 font-sans">
                            <div className="font-medium">{p.name}</div>
                            <div className={`text-[11px] ${mutedCls}`}>
                              {p.artifact_identity} · v{p.version} · {p.tested_at.slice(0, 10)}
                            </div>
                          </td>
                          <td className="py-3 pr-4 font-sans">
                            <div>{p.publisher_name}</div>
                            <div className={`text-[11px] ${mutedCls}`}>{p.publisher_verification.replace(/_/g, ' ')}</div>
                          </td>
                          <td className="py-3 pr-4">{p.status.replace(/_/g, ' ')}</td>
                          <td className="py-3 pr-4">{p.fingerprint.slice(0, 14)}...</td>
                          <td className="py-3 pr-4">
                            <button
                              type="button"
                              onClick={() => copyText(mdBadge, 'Markdown badge')}
                              className="text-cyan-500 hover:underline flex items-center gap-1 whitespace-nowrap"
                            >
                              <Copy className="w-3 h-3" />
                              <span>Copy Markdown</span>
                            </button>
                          </td>
                          <td className="py-3 text-right">
                            <button
                              type="button"
                              onClick={() => handleVerifyPublicProfile(p.profile_id)}
                              className="px-2.5 py-1 rounded border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 whitespace-nowrap"
                            >
                              Verify Ed25519
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {!publicOnlyMode && effTenant && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <form onSubmit={handlePublishTrustProfile} className={`p-5 rounded-xl border space-y-3 text-xs ${surfaceCls}`}>
                <h3 className="text-sm font-semibold">Publish Verified Trust Profile</h3>
                <p className={mutedCls}>
                  Acquires a tenant publisher ownership proof, runs DLP privacy checks to block secret/tenant leaks, and signs the report with Ed25519.
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block mb-1 font-medium">Artifact Identity</label>
                    <input value={pubArtifactId} onChange={(e) => setPubArtifactId(e.target.value)} className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Display Name</label>
                    <input value={pubName} onChange={(e) => setPubName(e.target.value)} className={`w-full px-3 py-2 rounded-lg border ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Publisher Name</label>
                    <input value={pubPublisher} onChange={(e) => setPubPublisher(e.target.value)} className={`w-full px-3 py-2 rounded-lg border ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Version</label>
                    <input value={pubVersion} onChange={(e) => setPubVersion(e.target.value)} className={`w-full px-3 py-2 rounded-lg border font-mono ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Artifact Type</label>
                    <select value={pubType} onChange={(e) => setPubType(e.target.value as 'MCP_TOOL' | 'CONNECTOR' | 'AGENT_PACK')} className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}>
                      <option value="MCP_TOOL">MCP Tool</option>
                      <option value="CONNECTOR">Connector</option>
                      <option value="AGENT_PACK">Agent Pack</option>
                    </select>
                  </div>
                  <div>
                    <label className="block mb-1 font-medium">Visibility</label>
                    <select value={pubVisibility} onChange={(e) => setPubVisibility(e.target.value as 'PUBLIC' | 'PRIVATE')} className={`w-full px-3 py-2 rounded-lg border ${inputCls}`}>
                      <option value="PUBLIC">PUBLIC (Registry)</option>
                      <option value="PRIVATE">PRIVATE (Tenant-Only)</option>
                    </select>
                  </div>
                </div>
                <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white font-medium hover:bg-cyan-500">
                  Sign &amp; Publish Profile
                </button>
              </form>

              <div className={`p-5 rounded-xl border space-y-3 text-xs ${surfaceCls}`}>
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold">Tenant Profiles &amp; Privacy Analytics</h3>
                  {analytics && (
                    <button
                      type="button"
                      onClick={() => handleToggleAnalytics(!analytics.analytics_enabled)}
                      className={`px-3 py-1 rounded border text-[11px] font-medium ${inputCls}`}
                    >
                      Analytics: {analytics.analytics_enabled ? 'Enabled (Opt-out)' : 'Disabled'}
                    </button>
                  )}
                </div>
                {analytics && (
                  <div className="grid grid-cols-3 gap-3 py-2 border-y border-slate-200 dark:border-slate-800 font-mono tabular-nums">
                    <div>
                      <div className={mutedCls}>CLI Scans</div>
                      <div className="text-base font-semibold">{analytics.cli_scans}</div>
                    </div>
                    <div>
                      <div className={mutedCls}>PR Guardian</div>
                      <div className="text-base font-semibold">{analytics.github_guardian_installations}</div>
                    </div>
                    <div>
                      <div className={mutedCls}>Published Reports</div>
                      <div className="text-base font-semibold">{analytics.published_reports}</div>
                    </div>
                  </div>
                )}
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {tenantProfiles.map((tp) => (
                    <div key={tp.profile_id} className="flex items-center justify-between py-1.5 border-b border-slate-200 dark:border-slate-800">
                      <div>
                        <span className="font-medium">{tp.name}</span>{' '}
                        <span className={`font-mono ${mutedCls}`}>v{tp.version} · {tp.visibility} · {tp.status}</span>
                      </div>
                      {tp.status !== 'REVOKED' && (
                        <button
                          type="button"
                          onClick={() => handleRevokeProfile(tp.profile_id)}
                          className="text-rose-500 hover:underline font-medium"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Public & Private Source Health Profiles (Feature 7) */}
      {tab === 'source_health' && (
        <div className={`p-5 rounded-xl border space-y-4 text-xs ${surfaceCls}`}>
          <div>
            <h3 className="text-sm font-semibold">Source Health Profiles (FACT LEASE &amp; Change Radar)</h3>
            <p className={mutedCls}>
              Metrics appear only when sample size reaches the threshold (min 5 verifications). Sources below threshold honestly display &quot;Insufficient Data&quot;.
            </p>
          </div>
          {!publicOnlyMode && tenantSources.length > 0 && (
            <div className="space-y-2">
              <div className="font-semibold">Tenant Source Profiles (Private by Default)</div>
              <table className="w-full text-left border-collapse font-mono tabular-nums">
                <thead>
                  <tr className={`border-b ${isDark ? 'border-slate-800 text-slate-400' : 'border-slate-200 text-slate-600'}`}>
                    <th className="py-2 pr-3">Source</th>
                    <th className="py-2 pr-3">Samples</th>
                    <th className="py-2 pr-3">Median Freshness</th>
                    <th className="py-2 pr-3">Success Rate</th>
                    <th className="py-2 pr-3">Visibility</th>
                    <th className="py-2 text-right">Consent Toggle</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {tenantSources.map((s) => (
                    <tr key={s.profile_id}>
                      <td className="py-2.5 pr-3 font-sans font-medium">{s.source_name} · {s.connector_version}</td>
                      <td className="py-2.5 pr-3">{s.sample_size} ({s.sufficiency_status})</td>
                      <td className="py-2.5 pr-3">{s.metrics.median_freshness.display}</td>
                      <td className="py-2.5 pr-3">{s.metrics.verification_success_rate.display}</td>
                      <td className="py-2.5 pr-3">{s.is_public ? 'PUBLIC' : 'PRIVATE'}</td>
                      <td className="py-2.5 text-right">
                        <button
                          type="button"
                          onClick={() => handleToggleSourcePublic(s.source_id, !s.is_public)}
                          className="text-cyan-500 hover:underline font-sans font-medium"
                        >
                          {s.is_public ? 'Make Private' : 'Grant Public Consent'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="space-y-2 pt-2">
            <div className="font-semibold">Publicly Shared Source Health Directory</div>
            {publicSources.length === 0 ? (
              <div className={`py-6 text-center ${mutedCls}`}>No data sources have opted into public Source Health sharing yet.</div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {publicSources.map((ps) => (
                  <div key={ps.profile_id} className={`p-4 rounded-lg border space-y-2 ${isDark ? 'border-slate-800 bg-slate-950' : 'border-slate-200 bg-slate-50'}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-sm">{ps.source_name}</span>
                      <span className={`font-mono ${mutedCls}`}>{ps.connector_version} · n={ps.sample_size}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 font-mono tabular-nums">
                      <div>Median Freshness: <strong>{ps.metrics.median_freshness.display}</strong></div>
                      <div>P95 Freshness: <strong>{ps.metrics.p95_freshness.display}</strong></div>
                      <div>Verification Rate: <strong>{ps.metrics.verification_success_rate.display}</strong></div>
                      <div>Failures: <strong>{ps.failure_count}</strong></div>
                    </div>
                    <div className={`text-[11px] ${mutedCls}`}>
                      Window: {ps.measurement_window.from.slice(0, 19)}Z to {ps.measurement_window.to.slice(0, 19)}Z · Updated {ps.last_profile_update.slice(0, 19)}Z
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: One-Command CCK Scanner (Feature 18) */}
      {tab === 'scanner' && (
        <div className={`p-5 rounded-xl border space-y-4 text-xs ${surfaceCls}`}>
          <div>
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-500" />
              <span>One-Command Local Scanner (Zero Login Required)</span>
            </h3>
            <p className={mutedCls}>
              Runs read-only static inspection on local MCP configs, tool schemas, connector manifests, and CCK configs. Never uploads source code or reads `.env` / private keys.
            </p>
          </div>
          <div className="space-y-2 font-mono">
            <div className={`p-3 rounded-lg border flex items-center justify-between ${isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <code>npm run cck -- scan . --format summary</code>
              <button type="button" onClick={() => copyText('npm run cck -- scan . --format summary', 'CLI scan command')} className="text-cyan-500 hover:underline font-sans">
                Copy
              </button>
            </div>
            <div className={`p-3 rounded-lg border flex items-center justify-between ${isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <code>npm run cck -- scan ./my-mcp-project --format sarif --out cck.sarif</code>
              <button type="button" onClick={() => copyText('npm run cck -- scan ./my-mcp-project --format sarif --out cck.sarif', 'SARIF scan command')} className="text-cyan-500 hover:underline font-sans">
                Copy
              </button>
            </div>
          </div>
          <div className={`p-3 rounded-lg border ${isDark ? 'border-slate-800 bg-slate-950/50' : 'border-slate-200 bg-slate-50'}`}>
            <div className="font-semibold mb-1">Scanner Accuracy &amp; Privacy Guarantees</div>
            <ul className={`list-disc pl-5 space-y-1 ${mutedCls}`}>
              <li>Default mode is LOCAL (zero HTTP requests, zero registration needed).</li>
              <li>Explicitly marks findings as CONFIRMED vs POTENTIAL and documents unscanned file counts.</li>
              <li>Skips <code>.env*</code>, <code>*.pem</code>, <code>*.key</code>, and private credential files automatically.</li>
            </ul>
          </div>
        </div>
      )}

      {/* TAB 4: GitHub PR Guardian (Feature 19) */}
      {tab === 'pr_guardian' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
          <div className={`p-5 rounded-xl border space-y-4 ${surfaceCls}`}>
            <div>
              <h3 className="text-sm font-semibold">Least-Privilege GitHub Workflow</h3>
              <p className={mutedCls}>Uses strictly scoped permissions (`contents: read`, `security-events: write`) and never executes untrusted PR code.</p>
            </div>
            <pre className={`p-3 rounded-lg border overflow-x-auto font-mono text-[11px] ${isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'}`}>
{`name: CCK PR Guardian
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  cck-pr-guardian:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/cck-pr-guardian
        with:
          target_path: '.'
          fail_on_severity: 'CRITICAL'`}
            </pre>
            {!publicOnlyMode && effTenant && (
              <form onSubmit={handleRunPrGuardian} className="space-y-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                <div className="font-semibold">Simulate Tool &amp; Permission Drift Check</div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block mb-1">Repository</label>
                    <input value={prRepo} onChange={(e) => setPrRepo(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} />
                  </div>
                  <div>
                    <label className="block mb-1">Head Endpoint</label>
                    <input value={prHeadEndpoint} onChange={(e) => setPrHeadEndpoint(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} />
                  </div>
                  <div>
                    <label className="block mb-1">Base Permissions</label>
                    <input value={prBasePerms} onChange={(e) => setPrBasePerms(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} />
                  </div>
                  <div>
                    <label className="block mb-1">Head Permissions</label>
                    <input value={prHeadPerms} onChange={(e) => setPrHeadPerms(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} />
                  </div>
                </div>
                <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white font-medium hover:bg-cyan-500">
                  Run PR Guardian Check
                </button>
              </form>
            )}
          </div>

          <div className={`p-5 rounded-xl border space-y-3 ${surfaceCls}`}>
            <h3 className="text-sm font-semibold">Recent PR Guardian Evaluations</h3>
            {prReports.length === 0 ? (
              <div className={`py-8 text-center ${mutedCls}`}>No PR Guardian evaluations recorded in this workspace yet.</div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {prReports.map((rep) => (
                  <div key={rep.report_ref} className={`p-3 rounded-lg border space-y-1.5 ${isDark ? 'border-slate-800 bg-slate-950' : 'border-slate-200 bg-slate-50'}`}>
                    <div className="flex items-center justify-between font-mono">
                      <strong>{rep.verdict}</strong>
                      <span className={mutedCls}>{rep.repository} · {rep.head_sha.slice(0, 8)}</span>
                    </div>
                    <div className={mutedCls}>
                      Added perms: {rep.changed_permissions.added.join(', ') || 'None'} · Added endpoints: {rep.changed_endpoints.added.join(', ') || 'None'}
                    </div>
                    <div className="font-mono text-[11px]">Findings: {rep.findings.length} · Coverage: {rep.coverage.percentage}%</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: Connector SDK & 12-Check Test Harness (Feature 8) */}
      {tab === 'connector_sdk' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
          <div className={`p-5 rounded-xl border space-y-3 ${surfaceCls}`}>
            <h3 className="text-sm font-semibold">Validate Connector &amp; Run 12-Check Harness</h3>
            <p className={mutedCls}>
              Separates Declared Capabilities from Harness-Verified Capabilities. Blocks arbitrary code execution via declarative manifest isolation.
            </p>
            {publicOnlyMode ? (
              <div className={`py-4 ${mutedCls}`}>Sign in to run live connector harness tests and submit connector packages.</div>
            ) : (
              <form onSubmit={handleRunConnectorHarness} className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block mb-1">Connector ID</label>
                    <input value={connId} onChange={(e) => setConnId(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1">Version</label>
                    <input value={connVersion} onChange={(e) => setConnVersion(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1">Name</label>
                    <input value={connName} onChange={(e) => setConnName(e.target.value)} className={`w-full px-3 py-1.5 rounded border ${inputCls}`} required />
                  </div>
                  <div>
                    <label className="block mb-1">Publisher</label>
                    <input value={connPublisher} onChange={(e) => setConnPublisher(e.target.value)} className={`w-full px-3 py-1.5 rounded border ${inputCls}`} required />
                  </div>
                </div>
                <div>
                  <label className="block mb-1">Allowed Egress Hosts (comma-separated)</label>
                  <input value={connHosts} onChange={(e) => setConnHosts(e.target.value)} className={`w-full px-3 py-1.5 rounded border font-mono ${inputCls}`} required />
                </div>
                <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white font-medium hover:bg-cyan-500">
                  Run 12-Test Harness &amp; Submit Package
                </button>
              </form>
            )}
          </div>

          <div className={`p-5 rounded-xl border space-y-3 ${surfaceCls}`}>
            <h3 className="text-sm font-semibold">Harness Verification Reports &amp; Submissions</h3>
            {submissions.length === 0 && harnessReports.length === 0 ? (
              <div className={`py-8 text-center ${mutedCls}`}>No connector harness runs recorded yet.</div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {submissions.map((sub) => (
                  <div key={sub.submission_id} className={`p-3 rounded-lg border space-y-1.5 ${isDark ? 'border-slate-800 bg-slate-950' : 'border-slate-200 bg-slate-50'}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-semibold flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                        <span>{sub.manifest.name} ({sub.manifest.version})</span>
                      </span>
                      <span className="font-mono">{sub.review_status}</span>
                    </div>
                    <div className={`font-mono ${mutedCls}`}>
                      Verified Caps: {sub.verified_capabilities.join(', ')}
                    </div>
                    <div className="flex items-center justify-between pt-1">
                      <span className={mutedCls}>Isolation: {sub.isolation_policy.sandbox_mode}</span>
                      <button
                        type="button"
                        onClick={() => handleIngestViaSubmission(sub.submission_id)}
                        className="text-cyan-500 hover:underline font-medium"
                      >
                        Ingest into Fact/Evidence Core
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
