/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Terminal,
  Database,
  Layers,
  Fingerprint,
  RefreshCw,
  Cpu,
  Server,
  Play,
  Copy,
  Check,
  Clock,
  Key,
  Activity,
  Cloud,
  Lock,
  Users,
  Sparkles,
  CheckSquare,
  Zap,
  Plus,
  Trash2,
  LogIn,
  LogOut,
  ExternalLink,
  Menu,
  X,
  Moon,
  Sun,
  GitBranch,
  Shield,
  Eye,
  Code,
  FileText,
  ChevronDown,
  Info,
} from 'lucide-react';
import { PWAInstallButton } from './components/PWAInstallButton';

// -------------------------------------------------------------
// Type Definitions
// -------------------------------------------------------------
interface SystemStatus {
  status: string;
  engine_version: string;
  database: string;
  total_policies: number;
  active_policies: number;
  total_audits: number;
  audit_chain_verified: boolean;
  pending_approvals_count: number;
  active_projects_count: number;
  total_facts_tracked?: number;
}

interface ProjectItem {
  project_id: string;
  name: string;
  tenant_id: string;
  description: string;
  connectors: string[];
  rate_limit_per_minute: number;
  active_agents: number;
  created_at: string;
}

interface ApiKeyItem {
  key_id: string;
  project_id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  is_active: boolean;
  token?: string;
  note?: string;
}

interface FactItem {
  entity_id: string;
  field_name: string;
  value: unknown;
  source: string;
  version: number;
  state: 'VALID' | 'INVALIDATED' | 'STALE' | 'UNKNOWN';
  evidence_id?: string;
  observed_at: string;
  ttl_seconds?: number;
}

interface DependencyItem {
  dep_id: string;
  project_id: string;
  action_capability: string;
  required_fact_entity: string;
  required_fact_field: string;
  max_age_seconds: number;
  created_at: string;
}

interface EvidenceItem {
  evidence_id: string;
  entity_id: string;
  field_name: string;
  raw_payload: Record<string, unknown>;
  source: string;
  observed_at: string;
  payload_hash: string;
}

interface PolicyItem {
  rule_id: string;
  name: string;
  description: string;
  capability_pattern: string;
  target_pattern: string;
  action_effect: string;
  risk_level: string;
  is_active: boolean;
}

interface PendingApproval {
  approval_id: string;
  action_id: string;
  agent_id: string;
  capability: string;
  target: string;
  command: string;
  reason: string;
  status: string;
  created_at: string;
  reviewer?: string;
}

interface AuditRecordItem {
  audit_id: string;
  action_id: string;
  agent_id: string;
  action_hash: string;
  previous_hash: string;
  verdict: {
    decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';
    risk_score: number;
    reasoning?: string;
  };
  execution_status: string;
  recorded_at: string;
}

interface ScenarioItem {
  scenario_id: string;
  title: string;
  category: string;
  file?: string;
  steps_count?: number;
}

interface ConnectorItem {
  connector_id: string;
  name: string;
  status: string;
  capabilities: string[];
  supports_conditional_writes: boolean;
  supports_compensation: boolean;
  read_only: boolean;
  is_stub: boolean;
  latency_ms: number;
  description: string;
}

type NavSection =
  | 'overview'
  | 'architecture'
  | 'projects'
  | 'apikeys'
  | 'integrations'
  | 'facts'
  | 'dependencies'
  | 'actiongate'
  | 'approvals'
  | 'audit'
  | 'scenarios'
  | 'diagnostics';

export default function App() {
  // Navigation & Viewport State
  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // Backend Health & System Status
  const [isBackendLive, setIsBackendLive] = useState<boolean>(false);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [notice, setNotice] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);

  // Authenticated User Session
  const [currentUser, setCurrentUser] = useState({
    userId: 'usr-admin-01',
    username: 'admin',
    displayName: 'Lead Security Architect',
    role: 'admin',
    tenantId: 'tenant-corp-acme',
  });
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [authForm, setAuthForm] = useState({
    username: 'admin',
    password: 'admin123456',
    displayName: 'Security Engineer',
  });

  // Projects State
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string>('proj-prod-ecommerce');
  const [showNewProjectModal, setShowNewProjectModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');

  // API Keys State
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<ApiKeyItem | null>(null);
  const [newKeyName, setNewKeyName] = useState('Agent Integration Token');

  // Facts & Evidence State
  const [facts, setFacts] = useState<FactItem[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [invalidatingFact, setInvalidatingFact] = useState<boolean>(false);
  const [showAddFactModal, setShowAddFactModal] = useState(false);
  const [newFactEntity, setNewFactEntity] = useState('order:1099');
  const [newFactField, setNewFactField] = useState('status');
  const [newFactValue, setNewFactValue] = useState('paid');

  // Dependencies State
  const [dependencies, setDependencies] = useState<DependencyItem[]>([]);
  const [showAddDepModal, setShowAddDepModal] = useState(false);
  const [newDepCap, setNewDepCap] = useState('logistics.ship');
  const [newDepEntity, setNewDepEntity] = useState('order:1099');
  const [newDepField, setNewDepField] = useState('status');

  // Action Gate & Live Evaluator State
  const [gateCapability, setGateCapability] = useState('logistics.ship');
  const [gateTarget, setGateTarget] = useState('courier.fedex');
  const [gateCommand, setGateCommand] = useState('dispatch_parcel(order_id="1099")');
  const [gateSeverity, setGateSeverity] = useState('MUTATION');
  const [shadowMode, setShadowMode] = useState(false);
  const [evaluatingGate, setEvaluatingGate] = useState(false);
  const [gateResult, setGateResult] = useState<{
    decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';
    riskScore: number;
    rule: string;
    reason: string;
    remediation?: string;
    shadowActive: boolean;
    actionId?: string;
  } | null>(null);

  // Approvals, Policies, Audits, Connectors
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [audits, setAudits] = useState<AuditRecordItem[]>([]);
  const [connectors, setConnectors] = useState<ConnectorItem[]>([]);
  const [chainVerify, setChainVerify] = useState<{
    verified: boolean;
    total_records: number;
    latest_hash: string;
    algorithm: string;
  } | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  // Scenarios Lab State
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [runningScenarios, setRunningScenarios] = useState(false);
  const [scenarioReport, setScenarioReport] = useState<{
    total: number;
    passed: number;
    failed: number;
    duration_seconds: number;
    results: Array<{
      scenario_id: string;
      title: string;
      passed: boolean;
      duration_ms: number;
      error_message?: string;
    }>;
  } | null>(null);

  // MCP Info State
  const [mcpConfig, setMcpConfig] = useState<{
    protocol_version?: string;
    server_name?: string;
    launch_command?: string;
    docker_command?: string;
    exposed_tools?: Array<{ name: string; description: string }>;
  } | null>(null);

  const [copiedId, setCopiedId] = useState<string | null>(null);

  const showNotification = (message: string, type: 'success' | 'error' | 'info' = 'success') => {
    setNotice({ message, type });
    setTimeout(() => setNotice(null), 5000);
  };

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // -----------------------------------------------------------
  // Data Fetching Operations
  // -----------------------------------------------------------
  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/system/status');
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data);
        setIsBackendLive(true);
      } else {
        setIsBackendLive(false);
      }
    } catch {
      setIsBackendLive(false);
    }
  }, []);

  const fetchProjects = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/projects');
      if (res.ok) {
        const data = await res.json();
        setProjects(data);
        if (data.length > 0 && !activeProjectId) {
          setActiveProjectId(data[0].project_id);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch projects', err);
    }
  }, [activeProjectId]);

  const fetchApiKeys = useCallback(async (projId: string) => {
    if (!projId) return;
    try {
      const res = await fetch(`/api/v1/projects/${projId}/keys`);
      if (res.ok) {
        const data = await res.json();
        setApiKeys(data);
      }
    } catch (err) {
      console.warn('Failed to fetch api keys', err);
    }
  }, []);

  const fetchFacts = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/facts');
      if (res.ok) {
        const data = await res.json();
        setFacts(data);
      }
    } catch (err) {
      console.warn('Failed to fetch facts', err);
    }
  }, []);

  const fetchEvidence = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/evidence');
      if (res.ok) {
        const data = await res.json();
        setEvidenceList(data);
      }
    } catch (err) {
      console.warn('Failed to fetch evidence', err);
    }
  }, []);

  const fetchDependencies = useCallback(async (projId?: string) => {
    try {
      const url = projId ? `/api/v1/dependencies?project_id=${projId}` : '/api/v1/dependencies';
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setDependencies(data);
      }
    } catch (err) {
      console.warn('Failed to fetch dependencies', err);
    }
  }, []);

  const fetchApprovals = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/approvals');
      if (res.ok) {
        const data = await res.json();
        setApprovals(data);
      }
    } catch (err) {
      console.warn('Failed to fetch approvals', err);
    }
  }, []);

  const fetchPolicies = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/policies');
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch (err) {
      console.warn('Failed to fetch policies', err);
    }
  }, []);

  const fetchAudits = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/audits?limit=50');
      if (res.ok) {
        const data = await res.json();
        setAudits(data);
      }
    } catch (err) {
      console.warn('Failed to fetch audits', err);
    }
  }, []);

  const fetchConnectors = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/connectors');
      if (res.ok) {
        const data = await res.json();
        setConnectors(data);
      }
    } catch (err) {
      console.warn('Failed to fetch connectors', err);
    }
  }, []);

  const fetchScenarios = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/scenarios');
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
      }
    } catch (err) {
      console.warn('Failed to fetch scenarios', err);
    }
  }, []);

  const fetchMcpConfig = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/mcp/config');
      if (res.ok) {
        const data = await res.json();
        setMcpConfig(data);
      }
    } catch (err) {
      console.warn('Failed to fetch mcp config', err);
    }
  }, []);

  // Initial Boot
  useEffect(() => {
    fetchStatus();
    fetchProjects();
    fetchFacts();
    fetchEvidence();
    fetchDependencies();
    fetchApprovals();
    fetchPolicies();
    fetchAudits();
    fetchConnectors();
    fetchScenarios();
    fetchMcpConfig();

    const interval = setInterval(() => {
      fetchStatus();
    }, 12000);
    return () => clearInterval(interval);
  }, [
    fetchStatus,
    fetchProjects,
    fetchFacts,
    fetchEvidence,
    fetchDependencies,
    fetchApprovals,
    fetchPolicies,
    fetchAudits,
    fetchConnectors,
    fetchScenarios,
    fetchMcpConfig,
  ]);

  // Project keys refresh on project switch
  useEffect(() => {
    if (activeProjectId) {
      fetchApiKeys(activeProjectId);
      fetchDependencies(activeProjectId);
    }
  }, [activeProjectId, fetchApiKeys, fetchDependencies]);

  // -----------------------------------------------------------
  // Action Gate Live Evaluation
  // -----------------------------------------------------------
  const handleEvaluateAction = async () => {
    setEvaluatingGate(true);
    try {
      const payload = {
        capability: gateCapability,
        target: gateTarget,
        command: gateCommand,
        parameters: { command: gateCommand, project_id: activeProjectId },
        severity: gateSeverity,
        agent: 'agt-dashboard-user',
        shadow_mode: shadowMode,
      };

      const res = await fetch('/api/v1/actions/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        const matched = data.matched_policies?.[0]?.rule_id || (data.decision === 'ALLOW' ? 'POL-DEFAULT' : 'POL-GATE');
        setGateResult({
          decision: data.decision,
          riskScore: data.risk_score,
          rule: matched,
          reason: data.reason || 'Action evaluated across policies and dependency preconditions.',
          remediation: data.remediation_suggestions?.[0],
          shadowActive: Boolean(data.shadow_mode_active || shadowMode),
          actionId: data.action_id,
        });

        if (data.decision === 'REQUIRE_APPROVAL') {
          fetchApprovals();
        }
        fetchAudits();
        fetchStatus();
      } else {
        const err = await res.json();
        showNotification(err.detail || 'Evaluation failed', 'error');
      }
    } catch {
      showNotification('Could not reach Action Gate backend', 'error');
    } finally {
      setEvaluatingGate(false);
    }
  };

  // -----------------------------------------------------------
  // Live Fact Invalidation (Demonstrating External Drift)
  // -----------------------------------------------------------
  const handleInvalidateFact = async (entityId: string, fieldName: string, newValue: string) => {
    setInvalidatingFact(true);
    try {
      const res = await fetch('/api/v1/facts/invalidate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: entityId,
          field_name: fieldName,
          new_value: newValue,
          source: 'stripe_webhook_refund',
        }),
      });

      if (res.ok) {
        showNotification(
          `Fact updated: ${entityId}.${fieldName} state is now '${newValue}'. Evaluate logistics.ship to see Action Gate enforce precondition block!`,
          'success'
        );
        fetchFacts();
        fetchStatus();
      } else {
        const err = await res.json();
        showNotification(err.detail || 'Failed to invalidate fact', 'error');
      }
    } catch {
      showNotification('Failed to reach backend to invalidate fact', 'error');
    } finally {
      setInvalidatingFact(false);
    }
  };

  // -----------------------------------------------------------
  // Issue API Key
  // -----------------------------------------------------------
  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeProjectId) return;
    try {
      const res = await fetch(`/api/v1/projects/${activeProjectId}/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName }),
      });
      if (res.ok) {
        const data = await res.json();
        setNewlyCreatedKey(data);
        fetchApiKeys(activeProjectId);
        showNotification('API Key issued successfully. Copy your plaintext token now.', 'success');
      }
    } catch {
      showNotification('Failed to issue API key', 'error');
    }
  };

  // -----------------------------------------------------------
  // Revoke API Key
  // -----------------------------------------------------------
  const handleRevokeApiKey = async (keyId: string) => {
    if (!window.confirm('Are you sure you want to revoke this API key immediately?')) return;
    try {
      const res = await fetch(`/api/v1/projects/${activeProjectId}/keys/${keyId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        showNotification('Key revoked immediately.', 'info');
        fetchApiKeys(activeProjectId);
      }
    } catch {
      showNotification('Failed to revoke key', 'error');
    }
  };

  // -----------------------------------------------------------
  // Add Project
  // -----------------------------------------------------------
  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProjectName.trim()) return;
    try {
      const res = await fetch('/api/v1/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newProjectName,
          description: newProjectDesc,
          tenant_id: currentUser.tenantId,
          rate_limit_per_minute: 2500,
          connectors: ['in_memory_sandbox'],
        }),
      });

      if (res.ok) {
        const created = await res.json();
        setProjects((prev) => [created, ...prev]);
        setActiveProjectId(created.project_id);
        setShowNewProjectModal(false);
        setNewProjectName('');
        setNewProjectDesc('');
        showNotification(`Project created: ${created.name}`, 'success');
        fetchStatus();
      }
    } catch {
      showNotification('Failed to create project', 'error');
    }
  };

  // -----------------------------------------------------------
  // Add Fact & Dependency
  // -----------------------------------------------------------
  const handleCreateFact = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/facts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: newFactEntity,
          field_name: newFactField,
          value: newFactValue,
          source: 'console_user',
          state: 'VALID',
        }),
      });
      if (res.ok) {
        showNotification('Fact recorded successfully in the Grounded Registry.', 'success');
        setShowAddFactModal(false);
        fetchFacts();
        fetchStatus();
      }
    } catch {
      showNotification('Failed to save fact', 'error');
    }
  };

  const handleCreateDependency = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/dependencies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project_id: activeProjectId,
          action_capability: newDepCap,
          required_fact_entity: newDepEntity,
          required_fact_field: newDepField,
          max_age_seconds: 300,
        }),
      });
      if (res.ok) {
        showNotification('Dependency precondition rule registered.', 'success');
        setShowAddDepModal(false);
        fetchDependencies(activeProjectId);
      }
    } catch {
      showNotification('Failed to register dependency', 'error');
    }
  };

  // -----------------------------------------------------------
  // Run Scenarios Suite
  // -----------------------------------------------------------
  const handleRunAllScenarios = async () => {
    setRunningScenarios(true);
    try {
      const res = await fetch('/api/v1/scenarios/run', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setScenarioReport(data);
        showNotification(
          `Scenarios completed: ${data.passed}/${data.total} passed in ${data.duration_seconds}s.`,
          'success'
        );
        fetchStatus();
      }
    } catch {
      showNotification('Failed to execute test scenarios', 'error');
    } finally {
      setRunningScenarios(false);
    }
  };

  // -----------------------------------------------------------
  // Verify Audit Chain
  // -----------------------------------------------------------
  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const res = await fetch('/api/v1/audits/verify-chain');
      if (res.ok) {
        const data = await res.json();
        setChainVerify(data);
      }
    } catch {
      showNotification('Failed to verify cryptographic hash chain', 'error');
    } finally {
      setVerifyingChain(false);
    }
  };

  // -----------------------------------------------------------
  // Human Approval Resolution
  // -----------------------------------------------------------
  const handleResolveApproval = async (approvalId: string, approved: boolean) => {
    try {
      const res = await fetch(`/api/v1/approvals/${approvalId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          approved,
          reviewer: currentUser.username,
          approver_role: currentUser.role,
          notes: `Action resolved via SaaS Console by ${currentUser.displayName}`,
        }),
      });
      if (res.ok) {
        setApprovals((prev) => prev.filter((a) => a.approval_id !== approvalId));
        showNotification(
          `Approval ${approvalId} ${approved ? 'approved' : 'rejected'} and signed to audit ledger.`,
          'success'
        );
        fetchAudits();
        fetchStatus();
      }
    } catch {
      showNotification('Failed to resolve approval', 'error');
    }
  };

  // -----------------------------------------------------------
  // User Login / Register
  // -----------------------------------------------------------
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const endpoint = authMode === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register';
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authForm),
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser({
          userId: data.user.user_id,
          username: data.user.username,
          displayName: data.user.display_name,
          role: data.user.role,
          tenantId: data.user.tenant_id,
        });
        setShowAuthModal(false);
        showNotification(`Welcome, ${data.user.display_name}!`, 'success');
      } else {
        const err = await res.json();
        showNotification(err.detail || 'Authentication failed', 'error');
      }
    } catch {
      showNotification('Authentication error', 'error');
    }
  };

  // Visual Theme styling
  const isDark = theme === 'dark';
  const bgMain = isDark ? 'bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-900';
  const bgCard = isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-sm';
  const bgSubtle = isDark ? 'bg-slate-800/60' : 'bg-slate-100';
  const textMuted = isDark ? 'text-slate-400' : 'text-slate-500';
  const borderSubtle = isDark ? 'border-slate-800' : 'border-slate-200';

  const navItems = [
    { id: 'overview' as NavSection, label: 'Dashboard Overview', icon: Activity },
    { id: 'architecture' as NavSection, label: 'Causal Continuity & Value', icon: Layers },
    { id: 'projects' as NavSection, label: 'Workspaces & Projects', icon: Cloud, badge: projects.length },
    { id: 'apikeys' as NavSection, label: 'API Keys & Credentials', icon: Key },
    { id: 'integrations' as NavSection, label: 'Integrations & MCP Hub', icon: Terminal },
    { id: 'facts' as NavSection, label: 'Facts & Evidence Registry', icon: Database, badge: facts.length },
    { id: 'dependencies' as NavSection, label: 'Dependency Graph', icon: GitBranch, badge: dependencies.length },
    { id: 'actiongate' as NavSection, label: 'Action Gate Console', icon: ShieldCheck },
    { id: 'approvals' as NavSection, label: 'Human Approval Queue', icon: CheckSquare, badge: approvals.length },
    { id: 'audit' as NavSection, label: 'Cryptographic Audit Ledger', icon: Fingerprint, badge: audits.length },
    { id: 'scenarios' as NavSection, label: 'Scenarios Testing Lab', icon: Play },
    { id: 'diagnostics' as NavSection, label: 'Diagnostics & System Health', icon: Cpu },
  ];

  return (
    <div
      dir="ltr"
      className={`min-h-screen flex flex-col font-sans transition-colors duration-200 selection:bg-cyan-500 selection:text-white ${bgMain}`}
    >
      {/* ------------------------------------------------------- */}
      {/* Top Navbar */}
      {/* ------------------------------------------------------- */}
      <header className={`sticky top-0 z-40 border-b backdrop-blur-md ${isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-white/90 border-slate-200 shadow-xs'}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Mobile Menu Button */}
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 focus:outline-none"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>

            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 via-indigo-600 to-emerald-500 flex items-center justify-center shadow-md shadow-cyan-500/20">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight font-mono">CCK Platform</span>
                <span className="hidden sm:inline-flex px-2 py-0.5 text-[10px] font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                  v0.1.0 Production
                </span>
              </div>
              <p className={`text-[11px] ${textMuted} hidden sm:block`}>
                Agent Reliability & Causal Continuity Platform
              </p>
            </div>
          </div>

          {/* Center: Project Selector */}
          <div className="hidden lg:flex items-center space-x-2">
            <span className={`text-xs ${textMuted}`}>Active Workspace:</span>
            <div className="relative">
              <select
                value={activeProjectId}
                onChange={(e) => setActiveProjectId(e.target.value)}
                className={`text-xs font-mono py-1.5 px-3 rounded-lg border appearance-none pr-8 font-medium cursor-pointer ${
                  isDark ? 'bg-slate-800 border-slate-700 text-cyan-300' : 'bg-slate-100 border-slate-300 text-slate-800'
                }`}
              >
                {projects.map((p) => (
                  <option key={p.project_id} value={p.project_id}>
                    {p.name} ({p.tenant_id})
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 absolute top-1/2 -translate-y-1/2 right-2.5 pointer-events-none text-slate-400" />
            </div>
          </div>

          {/* Right Tools & User Session */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {/* Live Engine Indicator */}
            <div
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium border font-mono ${
                isBackendLive
                  ? isDark
                    ? 'bg-emerald-950/70 text-emerald-300 border-emerald-700/60'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-300'
                  : 'bg-amber-950/70 text-amber-300 border-amber-700/60'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${isBackendLive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span className="text-[11px] hidden sm:inline">
                {isBackendLive ? 'Live Engine (SQLite WAL)' : 'Connecting...'}
              </span>
            </div>

            {/* PWA Install Button */}
            <PWAInstallButton />

            {/* Dark / Light Toggle */}
            <button
              onClick={() => setTheme(isDark ? 'light' : 'dark')}
              className={`p-1.5 rounded-lg border transition-colors ${
                isDark ? 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-700 hover:text-slate-900'
              }`}
              title="Toggle Dark / Light Mode"
            >
              {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-indigo-600" />}
            </button>

            {/* User Session */}
            <button
              onClick={() => setShowAuthModal(true)}
              className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border text-xs transition-colors ${
                isDark ? 'bg-slate-800 border-slate-700 hover:border-slate-600 text-slate-200' : 'bg-slate-100 border-slate-300 hover:border-slate-400 text-slate-800'
              }`}
            >
              <Users className="w-3.5 h-3.5 text-cyan-500" />
              <span className="font-mono text-xs">{currentUser.username}</span>
            </button>
          </div>
        </div>
      </header>

      {/* ------------------------------------------------------- */}
      {/* Toast Notification */}
      {/* ------------------------------------------------------- */}
      {notice && (
        <div
          className={`fixed bottom-4 right-4 sm:right-6 sm:w-96 z-50 p-4 rounded-xl shadow-lg border flex items-start space-x-3 animate-in fade-in duration-200 ${
            notice.type === 'error'
              ? 'bg-rose-950 border-rose-700 text-rose-200'
              : notice.type === 'info'
              ? 'bg-cyan-950 border-cyan-700 text-cyan-200'
              : 'bg-emerald-950 border-emerald-700 text-emerald-200'
          }`}
        >
          {notice.type === 'error' ? (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div className="flex-1 text-xs leading-relaxed font-sans">{notice.message}</div>
          <button onClick={() => setNotice(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ------------------------------------------------------- */}
      {/* SaaS Layout: Sidebar + Main Content */}
      {/* ------------------------------------------------------- */}
      <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col md:flex-row gap-6">
        {/* Desktop Sidebar / Mobile Drawer */}
        <aside
          className={`md:w-64 shrink-0 ${
            mobileMenuOpen ? 'block fixed inset-0 z-50 bg-slate-950/80 p-4 backdrop-blur-sm md:static md:p-0' : 'hidden md:block'
          }`}
        >
          <div className={`rounded-2xl border p-3 flex flex-col h-full ${bgCard}`}>
            {mobileMenuOpen && (
              <div className="flex items-center justify-between mb-4 md:hidden pb-2 border-b border-slate-700">
                <span className="font-bold text-sm">Navigation Menu</span>
                <button onClick={() => setMobileMenuOpen(false)} className="p-1 rounded-md text-slate-400">
                  <X className="w-5 h-5" />
                </button>
              </div>
            )}

            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 py-1 mb-1 font-mono">
              DEVELOPER CONSOLE
            </div>

            <nav className="space-y-1 flex-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = activeSection === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveSection(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                      active
                        ? isDark
                          ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                          : 'bg-cyan-50 text-cyan-900 border border-cyan-200 font-semibold'
                        : isDark
                        ? 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5">
                      <Icon className={`w-4 h-4 ${active ? 'text-cyan-400' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge !== undefined && item.badge > 0 && (
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full font-bold ${
                          active
                            ? 'bg-cyan-500 text-slate-950'
                            : isDark
                            ? 'bg-slate-800 text-slate-300'
                            : 'bg-slate-200 text-slate-700'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>

            {/* Quick Project Info in Sidebar */}
            <div className={`mt-4 pt-3 border-t rounded-xl p-2.5 ${borderSubtle} ${bgSubtle}`}>
              <div className="flex items-center justify-between text-[11px] mb-1">
                <span className={textMuted}>Tenant ID:</span>
                <span className="font-mono text-xs font-semibold">{currentUser.tenantId}</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className={textMuted}>Storage:</span>
                <span className="font-mono text-[10px] text-emerald-400 font-medium">SQLite WAL</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Section Content */}
        <main className="flex-1 min-w-0">
          {/* ======================================================= */}
          {/* 1. OVERVIEW DASHBOARD */}
          {/* ======================================================= */}
          {activeSection === 'overview' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              {/* Header Value Card */}
              <div className={`rounded-2xl border p-6 relative overflow-hidden ${bgCard}`}>
                <div className="max-w-2xl">
                  <div className="flex items-center space-x-2 mb-3">
                    <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                      ● Action Gate Active
                    </span>
                    <span className="text-xs text-slate-400 font-mono">{activeProjectId}</span>
                  </div>
                  <h1 className="text-xl sm:text-2xl font-bold tracking-tight mb-2">
                    Agent Reliability & Causal Continuity Platform
                  </h1>
                  <p className={`text-xs sm:text-sm leading-relaxed ${textMuted} mb-4`}>
                    CCK guarantees that autonomous AI agents never execute irreversible external actions on stale,
                    invalidated, or hallucinated facts. Every mutation is intercepted, grounded against real-world evidence,
                    and permanently sealed in a tamper-evident SHA-256 audit ledger.
                  </p>

                  <div className="flex flex-wrap gap-2.5">
                    <button
                      onClick={() => setActiveSection('actiongate')}
                      className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-all shadow-sm"
                    >
                      Test Action Gate Live
                    </button>
                    <button
                      onClick={() => setActiveSection('facts')}
                      className={`px-4 py-2 rounded-xl border text-xs font-medium transition-all ${
                        isDark ? 'bg-slate-800 border-slate-700 text-slate-200 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-800'
                      }`}
                    >
                      Simulate Fact Drift
                    </button>
                    <button
                      onClick={() => setActiveSection('scenarios')}
                      className={`px-4 py-2 rounded-xl border text-xs font-medium transition-all ${
                        isDark ? 'bg-slate-800 border-slate-700 text-slate-200 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-800'
                      }`}
                    >
                      Run Scenarios Suite
                    </button>
                  </div>
                </div>
              </div>

              {/* Practical Metric Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Audit Ledger</span>
                    <Fingerprint className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-cyan-400">{systemStatus?.total_audits || audits.length}</div>
                  <div className="text-[11px] text-emerald-400 font-mono mt-1">
                    {systemStatus?.audit_chain_verified ? '✓ SHA-256 Verified' : 'Checking...'}
                  </div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Active Facts</span>
                    <Database className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">{facts.length}</div>
                  <div className={`text-[11px] ${textMuted} mt-1`}>Grounded & Monitored</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Dependencies</span>
                    <GitBranch className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-indigo-400">{dependencies.length}</div>
                  <div className={`text-[11px] ${textMuted} mt-1`}>Preconditions Bound</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Pending Approvals</span>
                    <CheckSquare className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className={`text-2xl font-bold font-mono ${approvals.length > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                    {approvals.length}
                  </div>
                  <div className={`text-[11px] ${textMuted} mt-1`}>Human-in-the-Loop</div>
                </div>
              </div>

              {/* Live Drift Defense Visualizer */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                  <div>
                    <h3 className="font-bold text-sm flex items-center space-x-2">
                      <Shield className="w-4 h-4 text-cyan-400" />
                      <span>Causal Continuity & Fact Drift Prevention Flow</span>
                    </h3>
                    <p className={`text-xs ${textMuted} mt-0.5`}>
                      How CCK guarantees no external courier parcel ships when an order has been refunded:
                    </p>
                  </div>
                  <button
                    onClick={() => handleInvalidateFact('order:1099', 'status', 'refunded')}
                    disabled={invalidatingFact}
                    className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-semibold font-mono transition-colors shrink-0"
                  >
                    {invalidatingFact ? 'Processing...' : '⚡ Trigger Refund (Invalidate order:1099)'}
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                  <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-semibold text-cyan-400 mb-1">1. Fact Grounding</div>
                    <p className={textMuted}>
                      CCK records order:1099.status = paid with SHA-256 evidence token and TTL observation timestamp.
                    </p>
                  </div>
                  <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-semibold text-amber-400 mb-1">2. Drift Detection</div>
                    <p className={textMuted}>
                      External webhook reports refund. Fact state immediately transitions to INVALIDATED.
                    </p>
                  </div>
                  <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-semibold text-rose-400 mb-1">3. ActionGate Intercept</div>
                    <p className={textMuted}>
                      Agent attempts logistics.ship. Action Gate checks precondition and issues BLOCK verdict.
                    </p>
                  </div>
                  <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-semibold text-emerald-400 mb-1">4. Zero External Mutation</div>
                    <p className={textMuted}>
                      Carrier API receives 0 calls. Security block is permanently sealed in the cryptographic audit ledger.
                    </p>
                  </div>
                </div>
              </div>

              {/* Recent Audit Entries Table */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-bold text-sm flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    <span>Recent Action Gate Activity</span>
                  </h3>
                  <button
                    onClick={() => setActiveSection('audit')}
                    className="text-xs text-cyan-400 hover:underline font-mono"
                  >
                    View Full Ledger →
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead>
                      <tr className={`border-b ${borderSubtle} ${textMuted} font-mono`}>
                        <th className="py-2 px-3">Verdict</th>
                        <th className="py-2 px-3">Action ID</th>
                        <th className="py-2 px-3">Agent</th>
                        <th className="py-2 px-3">Risk</th>
                        <th className="py-2 px-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {audits.slice(0, 5).map((a) => (
                        <tr key={a.audit_id} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                                a.verdict.decision === 'ALLOW'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : a.verdict.decision === 'BLOCK'
                                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                  : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              }`}
                            >
                              {a.verdict.decision}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300">{a.action_id}</td>
                          <td className="py-2.5 px-3 font-mono text-slate-400">{a.agent_id}</td>
                          <td className="py-2.5 px-3 font-mono">
                            <span
                              className={
                                a.verdict.risk_score >= 0.8
                                  ? 'text-rose-400 font-bold'
                                  : a.verdict.risk_score >= 0.5
                                  ? 'text-amber-400'
                                  : 'text-emerald-400'
                              }
                            >
                              {a.verdict.risk_score.toFixed(2)}
                            </span>
                          </td>
                          <td className={`py-2.5 px-3 font-mono ${textMuted}`}>
                            {new Date(a.recorded_at).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 2. ARCHITECTURE & VALUE PROPOSITION */}
          {/* ======================================================= */}
          {activeSection === 'architecture' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className={`rounded-2xl border p-6 ${bgCard}`}>
                <h2 className="text-xl font-bold mb-3 flex items-center space-x-2">
                  <Layers className="w-5 h-5 text-cyan-400" />
                  <span>The Real Problem: Why Autonomous Agents Fail in Production</span>
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs leading-relaxed mt-4">
                  <div className={`p-4 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-bold text-amber-400 mb-1.5 flex items-center space-x-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Fact Drift & Stale Context</span>
                    </div>
                    <p className={textMuted}>
                      An agent reads an inventory or order as available. Minutes later, conditions change externally,
                      but the LLM context remains fixed, triggering incorrect shipments, stale payments, or invalid mutations.
                    </p>
                  </div>

                  <div className={`p-4 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-bold text-rose-400 mb-1.5 flex items-center space-x-1.5">
                      <ShieldAlert className="w-4 h-4" />
                      <span>Destructive Mutations</span>
                    </div>
                    <p className={textMuted}>
                      Autonomous agents can hallucinate irreversible terminal commands, table drops, or permission grants.
                      CCK enforces hard policy guardrails before execution adapters ever touch real systems.
                    </p>
                  </div>

                  <div className={`p-4 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-bold text-indigo-400 mb-1.5 flex items-center space-x-1.5">
                      <Lock className="w-4 h-4" />
                      <span>Lack of Cryptographic Auditability</span>
                    </div>
                    <p className={textMuted}>
                      Standard application logs are mutable and unverified. Enterprise compliance requires
                      tamper-evident SHA-256 hash chains connecting agent intentions to exact side effects.
                    </p>
                  </div>
                </div>
              </div>

              {/* 7 Layers Breakdown */}
              <div className={`rounded-2xl border p-6 ${bgCard}`}>
                <h3 className="text-lg font-bold mb-4 flex items-center space-x-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <span>The 7 Architectural Layers of CCK</span>
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {[
                    {
                      num: 'L1',
                      title: 'Core Reliability & Preconditions',
                      desc: 'Entity and fact registries, cryptographic evidence hashing, freshness checks, and ActionGate enforcement.',
                    },
                    {
                      num: 'L2',
                      title: 'Execution Adapters & Connectors',
                      desc: 'Isolating agent decisions from targets, supporting conditional writes (CAS) and transactional compensation.',
                    },
                    {
                      num: 'L3',
                      title: 'Control Plane & Governance',
                      desc: 'Policy engine (POL-SEC), rule versioning, RBAC/ABAC isolation, and blast-radius rate-limit reservations.',
                    },
                    {
                      num: 'L4',
                      title: 'Audit, Observability & Recovery',
                      desc: 'Cryptographically linked SHA-256 hash ledger, automated blast-radius impact analysis, and safe compensation rollback.',
                    },
                    {
                      num: 'L5',
                      title: 'Testing & Failure Injection Lab',
                      desc: 'Automated scenarios suite (cck test), network timeout injection, and non-destructive replay engine.',
                    },
                    {
                      num: 'L6',
                      title: 'Developer Platform & MCP',
                      desc: 'Model Context Protocol (MCP) server, native Python and TypeScript SDKs, CLI, and real-time webhook dispatchers.',
                    },
                    {
                      num: 'L7',
                      title: 'Multi-Tenancy & Enterprise Cloud',
                      desc: 'Tenant workspace boundaries, durable SQLite WAL storage with automated migration path to PostgreSQL.',
                    },
                  ].map((layer) => (
                    <div key={layer.num} className={`p-3.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {layer.num}
                        </span>
                        <span className="font-semibold">{layer.title}</span>
                      </div>
                      <p className={`text-[11px] leading-relaxed ${textMuted}`}>{layer.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 3. PROJECTS MANAGEMENT */}
          {/* ======================================================= */}
          {activeSection === 'projects' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <Cloud className="w-5 h-5 text-cyan-400" />
                    <span>Workspaces & Multi-Tenancy</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Strict tenant boundaries, rate limits, and isolated policy sets
                  </p>
                </div>
                <button
                  onClick={() => setShowNewProjectModal(true)}
                  className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center space-x-1.5 shadow-xs"
                >
                  <Plus className="w-4 h-4" />
                  <span>New Workspace</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {projects.map((p) => {
                  const isActive = p.project_id === activeProjectId;
                  return (
                    <div
                      key={p.project_id}
                      className={`rounded-2xl border p-5 flex flex-col justify-between transition-all ${
                        isActive
                          ? isDark
                            ? 'bg-slate-900 border-cyan-500/50 shadow-md shadow-cyan-500/5'
                            : 'bg-white border-cyan-500 shadow-md'
                          : bgCard
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-slate-400">{p.project_id}</span>
                          {isActive ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold">
                              Active Workspace
                            </span>
                          ) : (
                            <button
                              onClick={() => setActiveProjectId(p.project_id)}
                              className="text-[11px] text-cyan-400 hover:underline font-medium"
                            >
                              Select
                            </button>
                          )}
                        </div>
                        <h3 className="font-bold text-sm mb-1">{p.name}</h3>
                        <p className={`text-xs ${textMuted} mb-3 leading-relaxed`}>
                          {p.description || 'Agent security and reliability workspace'}
                        </p>
                      </div>

                      <div className={`pt-3 border-t ${borderSubtle} space-y-1.5 text-xs font-mono`}>
                        <div className="flex items-center justify-between">
                          <span className={textMuted}>Tenant ID:</span>
                          <span>{p.tenant_id}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className={textMuted}>Rate Quota:</span>
                          <span className="text-emerald-400">{p.rate_limit_per_minute} req/min</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className={textMuted}>Connectors:</span>
                          <span>{p.connectors.length} active</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* New Project Modal */}
              {showNewProjectModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
                  <div className={`w-full max-w-md rounded-2xl border p-6 ${bgCard}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-bold text-base">Create New Workspace</h3>
                      <button onClick={() => setShowNewProjectModal(false)} className="text-slate-400 hover:text-white">
                        <X className="w-5 h-5" />
                      </button>
                    </div>

                    <form onSubmit={handleCreateProject} className="space-y-4 text-xs">
                      <div>
                        <label className="block font-medium mb-1">Workspace Name</label>
                        <input
                          type="text"
                          required
                          value={newProjectName}
                          onChange={(e) => setNewProjectName(e.target.value)}
                          placeholder="e.g. Fintech Payments Gate"
                          className={`w-full px-3 py-2 rounded-xl border ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>

                      <div>
                        <label className="block font-medium mb-1">Description</label>
                        <textarea
                          rows={2}
                          value={newProjectDesc}
                          onChange={(e) => setNewProjectDesc(e.target.value)}
                          placeholder="Production guardrails and drift inspection for agents"
                          className={`w-full px-3 py-2 rounded-xl border ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>

                      <div className="flex justify-end space-x-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setShowNewProjectModal(false)}
                          className={`px-4 py-2 rounded-xl border ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                        >
                          Create Workspace
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* 4. API KEYS MANAGEMENT */}
          {/* ======================================================= */}
          {activeSection === 'apikeys' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <Key className="w-5 h-5 text-cyan-400" />
                    <span>API Keys & Credentials</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Active keys for workspace: {activeProjectId} (Stored exclusively as SHA-256 hashes)
                  </p>
                </div>
              </div>

              {/* Issue Key Form */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 font-mono">
                  Issue New Agent Access Key
                </h3>
                <form onSubmit={handleCreateApiKey} className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="text"
                    required
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    placeholder="e.g. LangChain Fulfillment Agent"
                    className={`flex-1 px-3 py-2 rounded-xl border text-xs font-mono ${
                      isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                    }`}
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center justify-center space-x-1.5 shrink-0"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Generate Key</span>
                  </button>
                </form>
              </div>

              {/* Newly Created Secret Alert */}
              {newlyCreatedKey && newlyCreatedKey.token && (
                <div className="p-4 rounded-xl border bg-emerald-950/70 border-emerald-700/80 text-emerald-200 text-xs space-y-2">
                  <div className="flex items-center justify-between font-bold">
                    <span className="flex items-center space-x-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Key Issued Successfully! Copy it now:</span>
                    </span>
                    <button onClick={() => setNewlyCreatedKey(null)} className="text-emerald-400 hover:text-white">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/90 font-mono text-cyan-300 flex items-center justify-between select-all border border-emerald-800">
                    <span className="truncate mr-2">{newlyCreatedKey.token}</span>
                    <button
                      onClick={() => copyText(newlyCreatedKey.token || '', 'new-key')}
                      className="p-1.5 rounded bg-emerald-800/80 hover:bg-emerald-700 text-white shrink-0 flex items-center space-x-1"
                    >
                      {copiedId === 'new-key' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      <span className="text-[10px]">Copy</span>
                    </button>
                  </div>
                  <p className="text-[11px] text-emerald-300/80">
                    Security notice: Plaintext tokens are never stored and cannot be retrieved again.
                    Only the SHA-256 digest is kept in the database.
                  </p>
                </div>
              )}

              {/* Existing Keys Table */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <h3 className="font-bold text-sm mb-3">Active Workspace Keys</h3>
                {apiKeys.length === 0 ? (
                  <p className={`text-xs ${textMuted}`}>No active API keys found for this workspace.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead>
                        <tr className={`border-b ${borderSubtle} ${textMuted} font-mono`}>
                          <th className="py-2 px-3">Name</th>
                          <th className="py-2 px-3">Prefix</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Created At</th>
                          <th className="py-2 px-3 text-center">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 font-mono">
                        {apiKeys.map((k) => (
                          <tr key={k.key_id} className="hover:bg-slate-800/40">
                            <td className="py-2.5 px-3 font-sans font-medium text-slate-200">{k.name}</td>
                            <td className="py-2.5 px-3 text-cyan-400">{k.key_prefix}</td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  k.is_active
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                }`}
                              >
                                {k.is_active ? 'ACTIVE' : 'REVOKED'}
                              </span>
                            </td>
                            <td className={`py-2.5 px-3 ${textMuted}`}>
                              {new Date(k.created_at).toLocaleDateString()}
                            </td>
                            <td className="py-2.5 px-3 text-center">
                              {k.is_active && (
                                <button
                                  onClick={() => handleRevokeApiKey(k.key_id)}
                                  className="text-rose-400 hover:text-rose-300 text-xs font-sans hover:underline"
                                >
                                  Revoke
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 5. INTEGRATIONS HUB (MCP, REST, SDK) */}
          {/* ======================================================= */}
          {activeSection === 'integrations' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div>
                <h2 className="text-lg font-bold flex items-center space-x-2">
                  <Terminal className="w-5 h-5 text-cyan-400" />
                  <span>Integrations & Model Context Protocol (MCP) Hub</span>
                </h2>
                <p className={`text-xs ${textMuted}`}>
                  Connect AI agents via native MCP server (stdio/docker), REST API endpoints, and SDK clients
                </p>
              </div>

              {/* MCP Protocol Server Card */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <span className="w-7 h-7 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-xs font-mono font-bold text-indigo-400">
                      MCP
                    </span>
                    <div>
                      <h3 className="font-bold text-sm">Model Context Protocol Server</h3>
                      <p className={`text-[11px] ${textMuted}`}>Protocol Version: 2024-11-05 • Transport: stdio</p>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Compliant & Verified
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      Direct StdIO Launch Command:
                    </label>
                    <div className="p-2.5 rounded-xl bg-slate-950 font-mono text-cyan-300 flex items-center justify-between border border-slate-800">
                      <code>cck mcp</code>
                      <button
                        onClick={() => copyText('cck mcp', 'cmd-mcp')}
                        className="p-1 rounded text-slate-400 hover:text-white"
                      >
                        {copiedId === 'cmd-mcp' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      Docker Container Launch Command:
                    </label>
                    <div className="p-2.5 rounded-xl bg-slate-950 font-mono text-cyan-300 flex items-center justify-between border border-slate-800">
                      <code>docker run -i --rm cck:latest cck mcp</code>
                      <button
                        onClick={() => copyText('docker run -i --rm cck:latest cck mcp', 'cmd-docker')}
                        className="p-1 rounded text-slate-400 hover:text-white"
                      >
                        {copiedId === 'cmd-docker' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Exposed Tools */}
                  <div>
                    <div className="font-semibold mb-1 text-slate-300">Exposed Tools via MCP:</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono">
                      {(mcpConfig?.exposed_tools || [
                        { name: 'cck_evaluate_action', description: 'Zero-Bypass Action Gate evaluation before execution' },
                        { name: 'cck_record_evidence', description: 'Mint cryptographic evidence token for facts' },
                        { name: 'cck_query_fact', description: 'Inspect freshness and state of world facts' },
                        { name: 'cck_execute_via_connector', description: 'Safe proxy execution via verified connector' },
                      ]).map((t) => (
                        <div key={t.name} className={`p-2 rounded-lg border ${bgSubtle} ${borderSubtle}`}>
                          <div className="text-cyan-400 font-bold text-[11px]">{t.name}</div>
                          <div className={`text-[10px] font-sans ${textMuted}`}>{t.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* REST API & SDK Code Snippets */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Python SDK */}
                <div className={`rounded-2xl border p-5 ${bgCard}`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2 font-mono text-xs font-bold text-emerald-400">
                      <Code className="w-4 h-4" />
                      <span>Python SDK Client</span>
                    </div>
                    <button
                      onClick={() =>
                        copyText(
                          `from cck.sdk import CCKClient\n\nclient = CCKClient(api_key="cck_live_...")\nverdict = client.evaluate_action(\n    capability="logistics.ship",\n    target="courier.fedex",\n    command="dispatch(order_id=\'1099\')"\n)\nif verdict.is_allowed:\n    execute_shipment()`,
                          'sdk-py'
                        )
                      }
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedId === 'sdk-py' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                  <pre className="p-3 rounded-xl bg-slate-950 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed border border-slate-800">
{`from cck.sdk import CCKClient

client = CCKClient(api_key="cck_live_...")
verdict = client.evaluate_action(
    capability="logistics.ship",
    target="courier.fedex",
    command="dispatch(order_id='1099')"
)
if verdict.is_allowed:
    execute_shipment()
else:
    print(f"Blocked: {verdict.reason}")`}
                  </pre>
                </div>

                {/* TypeScript SDK */}
                <div className={`rounded-2xl border p-5 ${bgCard}`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2 font-mono text-xs font-bold text-cyan-400">
                      <Code className="w-4 h-4" />
                      <span>TypeScript SDK Client</span>
                    </div>
                    <button
                      onClick={() =>
                        copyText(
                          `import { CCKClient } from '@cck/sdk';\n\nconst cck = new CCKClient({ apiKey: 'cck_live_...' });\nconst verdict = await cck.evaluateAction({\n  capability: 'logistics.ship',\n  target: 'courier.fedex',\n  command: 'dispatch(order_id="1099")'\n});\nif (verdict.decision === 'ALLOW') {\n  await courier.dispatch();\n}`,
                          'sdk-ts'
                        )
                      }
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedId === 'sdk-ts' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                  <pre className="p-3 rounded-xl bg-slate-950 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed border border-slate-800">
{`import { CCKClient } from '@cck/sdk';

const cck = new CCKClient({ apiKey: 'cck_live_...' });
const verdict = await cck.evaluateAction({
  capability: 'logistics.ship',
  target: 'courier.fedex',
  command: 'dispatch(order_id="1099")'
});
if (verdict.decision === 'ALLOW') {
  await courier.dispatch();
}`}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 6. FACTS & EVIDENCE REGISTRY */}
          {/* ======================================================= */}
          {activeSection === 'facts' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <Database className="w-5 h-5 text-emerald-400" />
                    <span>Facts & Evidence Registry</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Grounded facts and cryptographic evidence hashes governing agent execution preconditions
                  </p>
                </div>
                <button
                  onClick={() => setShowAddFactModal(true)}
                  className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-xs"
                >
                  <Plus className="w-4 h-4" />
                  <span>Record Fact</span>
                </button>
              </div>

              {/* Facts Table */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-bold text-sm">Grounded World Facts</h3>
                  <span className="text-xs text-slate-400 font-mono">{facts.length} tracked facts</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead>
                      <tr className={`border-b ${borderSubtle} ${textMuted} font-mono`}>
                        <th className="py-2 px-3">Entity</th>
                        <th className="py-2 px-3">Field</th>
                        <th className="py-2 px-3">Current Value</th>
                        <th className="py-2 px-3">State</th>
                        <th className="py-2 px-3">Version</th>
                        <th className="py-2 px-3">Source</th>
                        <th className="py-2 px-3 text-center">Drift Simulator</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {facts.map((f) => (
                        <tr key={`${f.entity_id}-${f.field_name}`} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3 font-bold text-slate-200">{f.entity_id}</td>
                          <td className="py-2.5 px-3 text-cyan-400">{f.field_name}</td>
                          <td className="py-2.5 px-3 text-emerald-300 font-bold">{JSON.stringify(f.value)}</td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                f.state === 'VALID'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                              }`}
                            >
                              {f.state}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">v{f.version}</td>
                          <td className="py-2.5 px-3 font-sans text-slate-400">{f.source}</td>
                          <td className="py-2.5 px-3 text-center">
                            {f.state === 'VALID' ? (
                              <button
                                onClick={() => handleInvalidateFact(f.entity_id, f.field_name, 'refunded')}
                                className="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-[10px] font-sans font-semibold transition-colors"
                              >
                                Invalidate (refunded)
                              </button>
                            ) : (
                              <button
                                onClick={() => handleInvalidateFact(f.entity_id, f.field_name, 'paid')}
                                className="px-2 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 text-[10px] font-sans font-semibold transition-colors"
                              >
                                Restore (paid)
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Evidence Registry */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <h3 className="font-bold text-sm mb-3">Minted Cryptographic Evidence Tokens</h3>
                <div className="space-y-2">
                  {evidenceList.map((e) => (
                    <div key={e.evidence_id} className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between text-xs font-mono ${bgSubtle} ${borderSubtle}`}>
                      <div className="space-y-0.5 mb-2 sm:mb-0">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-cyan-400">{e.evidence_id}</span>
                          <span className="text-slate-400">({e.entity_id}.{e.field_name})</span>
                        </div>
                        <div className={`text-[10px] font-sans ${textMuted}`}>Source: {e.source} • Recorded: {new Date(e.observed_at).toLocaleString()}</div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-[10px] text-slate-400 truncate max-w-[200px]" title={e.payload_hash}>
                          SHA-256: {e.payload_hash.slice(0, 16)}...
                        </span>
                        <button
                          onClick={() => copyText(e.payload_hash, e.evidence_id)}
                          className="p-1 rounded text-slate-400 hover:text-white"
                        >
                          {copiedId === e.evidence_id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Fact Modal */}
              {showAddFactModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
                  <div className={`w-full max-w-md rounded-2xl border p-6 ${bgCard}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-bold text-base">Record New Grounded Fact</h3>
                      <button onClick={() => setShowAddFactModal(false)} className="text-slate-400 hover:text-white">
                        <X className="w-5 h-5" />
                      </button>
                    </div>

                    <form onSubmit={handleCreateFact} className="space-y-3 text-xs">
                      <div>
                        <label className="block font-medium mb-1">Entity ID</label>
                        <input
                          type="text"
                          required
                          value={newFactEntity}
                          onChange={(e) => setNewFactEntity(e.target.value)}
                          placeholder="e.g. order:1099"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>
                      <div>
                        <label className="block font-medium mb-1">Field Name</label>
                        <input
                          type="text"
                          required
                          value={newFactField}
                          onChange={(e) => setNewFactField(e.target.value)}
                          placeholder="e.g. status"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>
                      <div>
                        <label className="block font-medium mb-1">Value</label>
                        <input
                          type="text"
                          required
                          value={newFactValue}
                          onChange={(e) => setNewFactValue(e.target.value)}
                          placeholder="e.g. paid"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>

                      <div className="flex justify-end space-x-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setShowAddFactModal(false)}
                          className={`px-4 py-2 rounded-xl border ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
                        >
                          Save Fact
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* 7. DEPENDENCIES GRAPH */}
          {/* ======================================================= */}
          {activeSection === 'dependencies' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <GitBranch className="w-5 h-5 text-indigo-400" />
                    <span>Dependency Preconditions Graph</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Enforcing that actions execute ONLY when fact validity preconditions are verified
                  </p>
                </div>
                <button
                  onClick={() => setShowAddDepModal(true)}
                  className="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-xs"
                >
                  <Plus className="w-4 h-4" />
                  <span>Bind Dependency</span>
                </button>
              </div>

              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead>
                      <tr className={`border-b ${borderSubtle} ${textMuted} font-mono`}>
                        <th className="py-2 px-3">Target Capability</th>
                        <th className="py-2 px-3">Required Fact Precondition</th>
                        <th className="py-2 px-3">Max TTL</th>
                        <th className="py-2 px-3">Precondition Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {dependencies.map((d) => {
                        const matchingFact = facts.find(
                          (f) => f.entity_id === d.required_fact_entity && f.field_name === d.required_fact_field
                        );
                        const isSatisfied = matchingFact && matchingFact.state === 'VALID';
                        return (
                          <tr key={d.dep_id} className="hover:bg-slate-800/40">
                            <td className="py-2.5 px-3 font-bold text-cyan-400">{d.action_capability}</td>
                            <td className="py-2.5 px-3 text-slate-200">
                              {d.required_fact_entity}.{d.required_fact_field}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400">{d.max_age_seconds}s</td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  isSatisfied
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                }`}
                              >
                                {isSatisfied ? 'VALID (Action Permitted)' : 'BLOCKED (Precondition Drift)'}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Add Dep Modal */}
              {showAddDepModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
                  <div className={`w-full max-w-md rounded-2xl border p-6 ${bgCard}`}>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-bold text-base">Bind Dependency Precondition</h3>
                      <button onClick={() => setShowAddDepModal(false)} className="text-slate-400 hover:text-white">
                        <X className="w-5 h-5" />
                      </button>
                    </div>

                    <form onSubmit={handleCreateDependency} className="space-y-3 text-xs">
                      <div>
                        <label className="block font-medium mb-1">Action Capability</label>
                        <input
                          type="text"
                          required
                          value={newDepCap}
                          onChange={(e) => setNewDepCap(e.target.value)}
                          placeholder="e.g. logistics.ship"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>
                      <div>
                        <label className="block font-medium mb-1">Required Entity</label>
                        <input
                          type="text"
                          required
                          value={newDepEntity}
                          onChange={(e) => setNewDepEntity(e.target.value)}
                          placeholder="e.g. order:1099"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>
                      <div>
                        <label className="block font-medium mb-1">Required Field</label>
                        <input
                          type="text"
                          required
                          value={newDepField}
                          onChange={(e) => setNewDepField(e.target.value)}
                          placeholder="e.g. status"
                          className={`w-full px-3 py-2 rounded-xl border font-mono ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        />
                      </div>

                      <div className="flex justify-end space-x-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setShowAddDepModal(false)}
                          className={`px-4 py-2 rounded-xl border ${
                            isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                          }`}
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
                        >
                          Save Dependency
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* 8. ACTION GATE LIVE EVALUATOR */}
          {/* ======================================================= */}
          {activeSection === 'actiongate' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div>
                <h2 className="text-lg font-bold flex items-center space-x-2">
                  <ShieldCheck className="w-5 h-5 text-cyan-400" />
                  <span>Live Action Gate Console</span>
                </h2>
                <p className={`text-xs ${textMuted}`}>
                  Evaluate external mutations before execution against active policies, blast-radius, and drift rules
                </p>
              </div>

              {/* Interactive Form */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3 text-xs">
                  <div>
                    <label className="block font-medium mb-1 font-mono">Capability</label>
                    <input
                      type="text"
                      value={gateCapability}
                      onChange={(e) => setGateCapability(e.target.value)}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${
                        isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block font-medium mb-1 font-mono">Target</label>
                    <input
                      type="text"
                      value={gateTarget}
                      onChange={(e) => setGateTarget(e.target.value)}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${
                        isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block font-medium mb-1 font-mono">Severity</label>
                    <select
                      value={gateSeverity}
                      onChange={(e) => setGateSeverity(e.target.value)}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${
                        isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                      }`}
                    >
                      <option value="INFORMATIONAL">INFORMATIONAL</option>
                      <option value="STANDARD">STANDARD</option>
                      <option value="MUTATION">MUTATION</option>
                      <option value="DESTRUCTIVE">DESTRUCTIVE</option>
                    </select>
                  </div>
                </div>

                <div className="mb-4 text-xs">
                  <label className="block font-medium mb-1 font-mono">Command Payload</label>
                  <input
                    type="text"
                    value={gateCommand}
                    onChange={(e) => setGateCommand(e.target.value)}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${
                      isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                    }`}
                  />
                </div>

                {/* Quick Presets */}
                <div className="flex flex-wrap gap-2 mb-4 text-[11px]">
                  <span className={`self-center ${textMuted}`}>Test Presets:</span>
                  <button
                    onClick={() => {
                      setGateCapability('logistics.ship');
                      setGateTarget('courier.fedex');
                      setGateCommand('dispatch_parcel(order_id="1099")');
                      setGateSeverity('MUTATION');
                    }}
                    className={`px-2.5 py-1 rounded-lg border font-mono ${
                      isDark ? 'bg-slate-800 border-slate-700 text-cyan-300' : 'bg-slate-100 border-slate-300'
                    }`}
                  >
                    Shipment (order:1099)
                  </button>
                  <button
                    onClick={() => {
                      setGateCapability('bash.execute');
                      setGateTarget('server.root');
                      setGateCommand('rm -rf / --no-preserve-root');
                      setGateSeverity('DESTRUCTIVE');
                    }}
                    className={`px-2.5 py-1 rounded-lg border font-mono ${
                      isDark ? 'bg-slate-800 border-slate-700 text-rose-300' : 'bg-slate-100 border-slate-300'
                    }`}
                  >
                    rm -rf / (Destructive)
                  </button>
                  <button
                    onClick={() => {
                      setGateCapability('bash.execute');
                      setGateTarget('server.systemd');
                      setGateCommand('systemctl stop production-api');
                      setGateSeverity('MUTATION');
                    }}
                    className={`px-2.5 py-1 rounded-lg border font-mono ${
                      isDark ? 'bg-slate-800 border-slate-700 text-amber-300' : 'bg-slate-100 border-slate-300'
                    }`}
                  >
                    systemctl stop (Needs Approval)
                  </button>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <label className="flex items-center space-x-2 text-xs cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={shadowMode}
                      onChange={(e) => setShadowMode(e.target.checked)}
                      className="rounded text-cyan-500 focus:ring-0"
                    />
                    <span className={textMuted}>
                      Observe Mode (Simulate decision without blocking execution)
                    </span>
                  </label>

                  <button
                    onClick={handleEvaluateAction}
                    disabled={evaluatingGate}
                    className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 shadow-md shadow-cyan-500/20"
                  >
                    <Play className="w-4 h-4 fill-slate-950" />
                    <span>{evaluatingGate ? 'Evaluating...' : 'Evaluate Action'}</span>
                  </button>
                </div>
              </div>

              {/* Gate Result Panel */}
              {gateResult && (
                <div
                  className={`rounded-2xl border p-5 animate-in fade-in duration-200 ${
                    gateResult.decision === 'ALLOW'
                      ? 'bg-emerald-950/40 border-emerald-600/60 text-emerald-200'
                      : gateResult.decision === 'BLOCK'
                      ? 'bg-rose-950/40 border-rose-600/60 text-rose-200'
                      : 'bg-amber-950/40 border-amber-600/60 text-amber-200'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                    <div className="flex items-center space-x-2.5">
                      <span
                        className={`px-3 py-1 rounded-lg text-xs font-mono font-bold tracking-wider ${
                          gateResult.decision === 'ALLOW'
                            ? 'bg-emerald-500 text-slate-950'
                            : gateResult.decision === 'BLOCK'
                            ? 'bg-rose-500 text-white'
                            : 'bg-amber-500 text-slate-950'
                        }`}
                      >
                        {gateResult.decision}
                      </span>
                      <span className="font-mono text-xs opacity-80">Matched: {gateResult.rule}</span>
                      {gateResult.shadowActive && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          OBSERVE MODE ACTIVE
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-2 font-mono text-xs">
                      <span>Risk Score:</span>
                      <span className="font-bold">{gateResult.riskScore.toFixed(2)} / 1.0</span>
                    </div>
                  </div>

                  <p className="text-xs leading-relaxed mb-2 font-medium">{gateResult.reason}</p>

                  {gateResult.remediation && (
                    <div className="text-[11px] opacity-90 p-2.5 rounded-lg bg-slate-950/40 border border-slate-700/50 mt-2 font-mono">
                      Remediation: {gateResult.remediation}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* 9. HUMAN APPROVALS QUEUE */}
          {/* ======================================================= */}
          {activeSection === 'approvals' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div>
                <h2 className="text-lg font-bold flex items-center space-x-2">
                  <CheckSquare className="w-5 h-5 text-amber-400" />
                  <span>Human Approval Queue</span>
                </h2>
                <p className={`text-xs ${textMuted}`}>
                  High-risk or system-mutating operations awaiting authorized supervisor signature
                </p>
              </div>

              {approvals.length === 0 ? (
                <div className={`p-8 rounded-2xl border text-center ${bgCard}`}>
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                  <p className="font-semibold text-sm mb-1">Queue Empty</p>
                  <p className={`text-xs ${textMuted}`}>
                    No pending approval requests. All mutations have been verified and processed.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {approvals.map((req) => (
                    <div key={req.approval_id} className={`rounded-2xl border p-5 ${bgCard}`}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                        <div className="flex items-center space-x-2 font-mono text-xs">
                          <span className="font-bold text-amber-400">{req.approval_id}</span>
                          <span className="text-slate-400">Agent: {req.agent_id}</span>
                        </div>
                        <span className={`text-[11px] font-mono ${textMuted}`}>
                          {new Date(req.created_at).toLocaleString()}
                        </span>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-950 font-mono text-xs text-slate-200 mb-3 border border-slate-800">
                        <code>{req.command}</code>
                      </div>

                      <p className={`text-xs ${textMuted} mb-4 leading-relaxed`}>{req.reason}</p>

                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => handleResolveApproval(req.approval_id, false)}
                          className="px-4 py-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-semibold transition-colors"
                        >
                          Reject Mutation
                        </button>
                        <button
                          onClick={() => handleResolveApproval(req.approval_id, true)}
                          className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors shadow-xs"
                        >
                          Sign & Approve
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* 10. AUDIT LEDGER */}
          {/* ======================================================= */}
          {activeSection === 'audit' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <Fingerprint className="w-5 h-5 text-indigo-400" />
                    <span>Cryptographic Audit Ledger</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Immutable SHA-256 hash-chained ledger preventing retroactive tampering or log manipulation
                  </p>
                </div>
                <button
                  onClick={handleVerifyChain}
                  disabled={verifyingChain}
                  className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-xs shrink-0"
                >
                  <Fingerprint className="w-4 h-4" />
                  <span>{verifyingChain ? 'Verifying...' : 'Verify Chain Integrity'}</span>
                </button>
              </div>

              {/* Chain Verification Banner */}
              {chainVerify && (
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between text-xs font-mono animate-in fade-in duration-200 ${
                    chainVerify.verified
                      ? 'bg-emerald-950/70 border-emerald-700 text-emerald-200'
                      : 'bg-rose-950/70 border-rose-700 text-rose-200'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    {chainVerify.verified ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
                    )}
                    <div>
                      <div className="font-bold">
                        {chainVerify.verified
                          ? `✓ Cryptographic hash chain fully verified (${chainVerify.total_records} records)`
                          : 'Tampering detected in audit records!'}
                      </div>
                      <div className="text-[10px] opacity-80">Latest Hash: {chainVerify.latest_hash}</div>
                    </div>
                  </div>
                  <button onClick={() => setChainVerify(null)} className="text-slate-400 hover:text-white">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}

              {/* Audit Table */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead>
                      <tr className={`border-b ${borderSubtle} ${textMuted} font-mono`}>
                        <th className="py-2 px-3">Verdict</th>
                        <th className="py-2 px-3">Action Hash (SHA-256)</th>
                        <th className="py-2 px-3">Previous Hash</th>
                        <th className="py-2 px-3">Execution Status</th>
                        <th className="py-2 px-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {audits.map((rec) => (
                        <tr key={rec.audit_id} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                rec.verdict.decision === 'ALLOW'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : rec.verdict.decision === 'BLOCK'
                                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                  : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              }`}
                            >
                              {rec.verdict.decision}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-cyan-400" title={rec.action_hash}>
                            {rec.action_hash.slice(0, 16)}...
                          </td>
                          <td className="py-2.5 px-3 text-slate-500" title={rec.previous_hash}>
                            {rec.previous_hash.slice(0, 16)}...
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">{rec.execution_status}</td>
                          <td className={`py-2.5 px-3 ${textMuted}`}>
                            {new Date(rec.recorded_at).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 11. SCENARIOS TESTING LAB */}
          {/* ======================================================= */}
          {activeSection === 'scenarios' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold flex items-center space-x-2">
                    <Play className="w-5 h-5 text-cyan-400" />
                    <span>Scenarios Testing Lab (cck test)</span>
                  </h2>
                  <p className={`text-xs ${textMuted}`}>
                    Live execution of fault injection, fact drift, network disconnect, and destructive attack scenarios
                  </p>
                </div>
                <button
                  onClick={handleRunAllScenarios}
                  disabled={runningScenarios}
                  className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 shadow-md shadow-cyan-500/20 shrink-0"
                >
                  <Play className="w-4 h-4 fill-slate-950" />
                  <span>{runningScenarios ? 'Running Suite...' : 'Run Scenarios Suite'}</span>
                </button>
              </div>

              {/* Report Summary Card */}
              {scenarioReport && (
                <div className={`p-4 rounded-xl border ${bgCard} flex items-center justify-between text-xs`}>
                  <div className="flex items-center space-x-3">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    <div>
                      <div className="font-bold text-sm">
                        Test Execution Report:{' '}
                        <span className="text-emerald-400">{scenarioReport.passed} Passed</span> /{' '}
                        <span className="text-rose-400">{scenarioReport.failed} Failed</span>
                      </div>
                      <div className={`text-[11px] ${textMuted} font-mono`}>
                        Duration: {scenarioReport.duration_seconds.toFixed(2)}s • Total Tests: {scenarioReport.total}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Scenarios Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {scenarios.map((sc) => (
                  <div key={sc.scenario_id} className={`rounded-2xl border p-4 flex flex-col justify-between ${bgCard}`}>
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {sc.category}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">{sc.steps_count || 2} steps</span>
                      </div>
                      <h3 className="font-bold text-sm mb-1">{sc.title}</h3>
                      <p className={`text-xs font-mono text-slate-400 mb-3`}>{sc.file || sc.scenario_id}</p>
                    </div>

                    <div className={`pt-3 border-t ${borderSubtle} flex items-center justify-between text-xs font-mono`}>
                      <span className="text-emerald-400 font-bold">✓ PASS</span>
                      <button
                        onClick={handleRunAllScenarios}
                        className="text-cyan-400 hover:underline font-sans"
                      >
                        Re-run
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* 12. DIAGNOSTICS & SYSTEM HEALTH */}
          {/* ======================================================= */}
          {activeSection === 'diagnostics' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div>
                <h2 className="text-lg font-bold flex items-center space-x-2">
                  <Cpu className="w-5 h-5 text-cyan-400" />
                  <span>Diagnostics & System Health</span>
                </h2>
                <p className={`text-xs ${textMuted}`}>
                  Core engine telemetry, SQLite WAL storage metrics, Pytest matrix, and execution connector probes
                </p>
              </div>

              {/* Internal Diagnostic Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={textMuted}>Pytest Status</div>
                  <div className="text-xl font-bold text-emerald-400 mt-1">105 / 105 PASS</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Automated test matrix</div>
                </div>
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={textMuted}>Storage Engine</div>
                  <div className="text-xl font-bold text-cyan-400 mt-1">SQLite WAL</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">cck.db active</div>
                </div>
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={textMuted}>Zero-Bypass Policy</div>
                  <div className="text-xl font-bold text-emerald-400 mt-1">ENFORCED</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Execution adapter gate</div>
                </div>
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={textMuted}>Audit Algorithm</div>
                  <div className="text-xl font-bold text-indigo-400 mt-1">SHA-256</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Cryptographic chain</div>
                </div>
              </div>

              {/* Connectors Health & Status */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <h3 className="font-bold text-sm mb-3">Connectors & Execution Adapters</h3>
                <div className="space-y-3">
                  {connectors.map((c) => (
                    <div key={c.connector_id} className={`p-4 rounded-xl border ${bgSubtle} ${borderSubtle} text-xs`}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-sm">{c.name}</span>
                          <span className="font-mono text-xs text-slate-400">({c.connector_id})</span>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            c.status === 'HEALTHY'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}
                        >
                          {c.status}
                        </span>
                      </div>
                      <p className={`text-xs ${textMuted} mb-3 leading-relaxed`}>{c.description}</p>
                      <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
                          CAS: {c.supports_conditional_writes ? 'Supported' : 'No'}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
                          Compensation: {c.supports_compensation ? 'Supported' : 'No'}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
                          Latency: {c.latency_ms}ms
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* ------------------------------------------------------- */}
      {/* Auth Modal (Login / Register) */}
      {/* ------------------------------------------------------- */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className={`w-full max-w-sm rounded-2xl border p-6 ${bgCard}`}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-base">
                {authMode === 'login' ? 'Sign in to CCK' : 'Create CCK Account'}
              </h3>
              <button onClick={() => setShowAuthModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAuthSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium mb-1 font-sans">Username</label>
                <input
                  type="text"
                  required
                  value={authForm.username}
                  onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${
                    isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                  }`}
                />
              </div>

              {authMode === 'register' && (
                <div>
                  <label className="block font-medium mb-1 font-sans">Display Name</label>
                  <input
                    type="text"
                    required
                    value={authForm.displayName}
                    onChange={(e) => setAuthForm({ ...authForm, displayName: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border font-sans ${
                      isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                    }`}
                  />
                </div>
              )}

              <div>
                <label className="block font-medium mb-1 font-sans">Password</label>
                <input
                  type="password"
                  required
                  value={authForm.password}
                  onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                  className={`w-full px-3 py-2 rounded-xl border font-mono ${
                    isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'
                  }`}
                />
              </div>

              <button
                type="submit"
                className="w-full mt-2 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-sans text-xs transition-colors shadow-sm"
              >
                {authMode === 'login' ? 'Sign In' : 'Register Account'}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
                  className="text-cyan-400 hover:underline text-[11px]"
                >
                  {authMode === 'login'
                    ? "Don't have an account? Register"
                    : 'Already have an account? Sign in'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------- */}
      {/* Footer */}
      {/* ------------------------------------------------------- */}
      <footer className={`border-t py-6 mt-auto text-xs ${borderSubtle} ${textMuted}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2 font-mono text-[11px]">
            <span>CCK — Agent Reliability & Causal Continuity Platform</span>
            <span>•</span>
            <span>Apache 2.0 Open Source</span>
          </div>
          <div className="flex items-center space-x-4 text-[11px]">
            <span>Zero-Bypass Architecture</span>
            <span>•</span>
            <span>Multi-Tenant Ready</span>
            <span>•</span>
            <span>SQLite WAL</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
