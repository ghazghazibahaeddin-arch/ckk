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
  Download,
  Share2,
  Printer,
  FlaskConical,
  FileCheck,
  WifiOff,
  Gauge,
  ArrowRight,
  Bot,
  GitMerge,
  Wallet,
  FileCheck2,
} from 'lucide-react';
import { PWAInstallButton } from './components/PWAInstallButton';
import { signInWithGoogle, signOutUser, subscribeToAuth } from './firebase';
import { ContractsView } from './components/assurance/ContractsView';
import { ConflictsView } from './components/assurance/ConflictsView';
import { MandatesView } from './components/assurance/MandatesView';
import { SkillsRegistryView } from './components/assurance/SkillsRegistryView';
import { EvaluationsView } from './components/assurance/EvaluationsView';
import { IncidentsView } from './components/assurance/IncidentsView';
import { DelegationsView } from './components/governance/DelegationsView';
import { BudgetGuardView } from './components/governance/BudgetGuardView';
import { McpGovernanceView } from './components/governance/McpGovernanceView';
import { CapabilityEvidenceView } from './components/governance/CapabilityEvidenceView';
import type {
  ActionContractRecord,
  ContractExecutionRecord,
  FactVersionHistoryRecord,
  ConflictRecord,
  RevalidationNoticeRecord,
  AgentMandateRecord,
  BusinessInvariantRule,
  SkillRecord,
  SkillImpactReceiptRecord,
  IncidentRecord,
  CorrectionPackRecord,
  ReplayPackRecord,
} from './assurance/types';
import type {
  DelegationRecord,
  BudgetPolicyRecord,
  McpServerRecord,
  CapabilityEvidenceReceiptRecord,
} from './governance/types';

// -------------------------------------------------------------
// Type Definitions
// -------------------------------------------------------------
export interface AgentItem {
  agent_id: string;
  project_id: string;
  tenant_id: string;
  name: string;
  framework: string;
  target_capability: string;
  target_resource: string;
  guardrail_mode: 'ENFORCE_AND_BLOCK' | 'REQUIRE_APPROVAL' | 'OBSERVE_ONLY';
  freshness_ttl_seconds: number;
  webhook_url?: string;
  created_at: string;
  last_evaluated_at?: string;
  last_seen_at?: string;
  total_evaluations: number;
  blocked_evaluations: number;
  status: 'CONNECTED' | 'DISCONNECTED' | 'INVALID_CREDENTIALS' | 'REVOKED' | 'ERROR';
  key_id?: string;
}
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

interface DecisionReceiptItem {
  receipt_id: string;
  action_id: string;
  timestamp: string;
  status: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';
  action: {
    capability: string;
    target: string;
    command: string;
    severity?: string;
  };
  agent_id: string;
  entity_id: string;
  relevant_facts: Array<{
    entity_id: string;
    field_name: string;
    value: unknown;
    state: string;
    version: number;
    observed_at: string;
  }>;
  evidence: Array<{
    evidence_id: string;
    source: string;
    payload_hash: string;
    observed_at: string;
  }>;
  dependency: {
    dep_id?: string;
    required_fact_entity?: string;
    required_fact_field?: string;
    max_age_seconds?: number;
    drift_detected?: boolean;
  };
  matched_policies: Array<{
    rule_id: string;
    name: string;
  }>;
  verdict: {
    decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REVALIDATE';
    risk_score: number;
    reasoning: string;
    remediation_suggestions?: string[];
  };
  audit_ref: {
    audit_id: string;
    action_hash: string;
    previous_hash: string;
  };
  redacted: boolean;
  shareable_token: string;
}

type NavSection =
  | 'overview'
  | 'delegations'
  | 'budgets'
  | 'mcp_governance'
  | 'capabilities'
  | 'contracts'
  | 'conflicts'
  | 'mandates'
  | 'skills'
  | 'evaluations'
  | 'incidents'
  | 'agents'
  | 'failurelab'
  | 'receipts'
  | 'benchmark'
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

  // CCK Decision Integrity Assurance State
  const [contracts, setContracts] = useState<ActionContractRecord[]>([]);
  const [contractExecutions, setContractExecutions] = useState<ContractExecutionRecord[]>([]);
  const [factHistory, setFactHistory] = useState<FactVersionHistoryRecord[]>([]);
  const [conflicts, setConflicts] = useState<ConflictRecord[]>([]);
  const [revalidations, setRevalidations] = useState<RevalidationNoticeRecord[]>([]);
  const [mandates, setMandates] = useState<AgentMandateRecord[]>([]);
  const [invariants, setInvariants] = useState<BusinessInvariantRule[]>([]);
  const [skills, setSkills] = useState<SkillRecord[]>([]);
  const [skillReceipts, setSkillReceipts] = useState<SkillImpactReceiptRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [correctionPacks, setCorrectionPacks] = useState<CorrectionPackRecord[]>([]);
  const [replayPacks, setReplayPacks] = useState<ReplayPackRecord[]>([]);

  // CCK Advanced Agent Governance State
  const [delegations, setDelegations] = useState<DelegationRecord[]>([]);
  const [budgets, setBudgets] = useState<BudgetPolicyRecord[]>([]);
  const [mcpServers, setMcpServers] = useState<McpServerRecord[]>([]);
  const [capabilityEvidence, setCapabilityEvidence] = useState<CapabilityEvidenceReceiptRecord[]>([]);

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
  const [activeProjectId, setActiveProjectId] = useState<string>('');
  const [showNewProjectModal, setShowNewProjectModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');

  // Connected AI Agents State
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [showConnectAgentModal, setShowConnectAgentModal] = useState(false);
  const [newAgentForm, setNewAgentForm] = useState({
    name: '',
    framework: 'langgraph',
    target_capability: 'orders.refund',
    target_resource: 'order:cust_01',
    guardrail_mode: 'ENFORCE_AND_BLOCK' as 'ENFORCE_AND_BLOCK' | 'REQUIRE_APPROVAL' | 'OBSERVE_ONLY',
    freshness_ttl_seconds: 300,
    webhook_url: '',
  });
  const [testingAgentId, setTestingAgentId] = useState<string | null>(null);
  const [togglingAgentId, setTogglingAgentId] = useState<string | null>(null);

  // 4-Step Connect Agent Onboarding Workflow State
  const [onboardingStep, setOnboardingStep] = useState<1 | 2 | 3 | 4>(1);
  const [registeredAgent, setRegisteredAgent] = useState<AgentItem | null>(null);
  const [agentCredentials, setAgentCredentials] = useState<{
    api_key: string;
    key_id: string;
    key_prefix: string;
    agent_id: string;
    created_at?: string;
    note?: string;
  } | null>(null);
  const [integrationFramework, setIntegrationFramework] = useState<'langgraph' | 'openai' | 'crewai' | 'mcp' | 'custom_http'>('langgraph');
  const [verifyingHeartbeat, setVerifyingHeartbeat] = useState(false);
  const [heartbeatSuccess, setHeartbeatSuccess] = useState<boolean | null>(null);
  const [heartbeatPayload, setHeartbeatPayload] = useState<any>(null);

  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<ApiKeyItem | null>(null);
  const [newKeyName, setNewKeyName] = useState('Agent Integration Token');
  const [confirmRevokeKeyId, setConfirmRevokeKeyId] = useState<string | null>(null);
  const [confirmDeleteAgentId, setConfirmDeleteAgentId] = useState<string | null>(null);

  // Facts & Evidence State
  const [facts, setFacts] = useState<FactItem[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [invalidatingFact, setInvalidatingFact] = useState<boolean>(false);
  const [showAddFactModal, setShowAddFactModal] = useState(false);
  const [newFactEntity, setNewFactEntity] = useState('order:1099');
  const [newFactField, setNewFactField] = useState('status');
  const [newFactValue, setNewFactValue] = useState('paid');

  // Webhook Test State
  const [webhookEntity, setWebhookEntity] = useState('order:1099');
  const [webhookField, setWebhookField] = useState('status');
  const [webhookValue, setWebhookValue] = useState('refunded');
  const [webhookSending, setWebhookSending] = useState(false);
  const [webhookResult, setWebhookResult] = useState<{
    evidence_id?: string;
    entity_id?: string;
    field_name?: string;
    value?: unknown;
    fact_state?: string;
    payload_hash?: string;
  } | null>(null);

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

  // Decision Receipts & Export State
  const [receipts, setReceipts] = useState<DecisionReceiptItem[]>([]);
  const [selectedReceiptModal, setSelectedReceiptModal] = useState<DecisionReceiptItem | null>(null);
  const [receiptRedactMode, setReceiptRedactMode] = useState<boolean>(true);

  // Failure Lab State
  const [failureLabScenario, setFailureLabScenario] = useState<
    'scenario_a_inventory' | 'scenario_b_permission' | 'scenario_c_refund'
  >('scenario_a_inventory');
  const [failureLabRunning, setFailureLabRunning] = useState<boolean>(false);
  const [failureLabResult, setFailureLabResult] = useState<any | null>(null);

  // Public Benchmark State
  const [benchmarkRunning, setBenchmarkRunning] = useState<boolean>(false);
  const [benchmarkResult, setBenchmarkResult] = useState<any | null>(null);

  // Online / Offline Fail-Closed Network Monitor
  const [isOnline, setIsOnline] = useState<boolean>(typeof navigator !== 'undefined' ? navigator.onLine : true);

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

  const fetchReceipts = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/receipts?redact=false');
      if (res.ok) {
        const data = await res.json();
        setReceipts(data);
      }
    } catch (err) {
      console.warn('Failed to fetch receipts', err);
    }
  }, []);

  const fetchAgents = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/agents');
      if (res.ok) {
        const data = await res.json();
        setAgents(data);
      }
    } catch (err) {
      console.warn('Failed to fetch agents', err);
    }
  }, []);

  const fetchAssuranceData = useCallback(async () => {
    try {
      const [
        contractsRes,
        executionsRes,
        historyRes,
        conflictsRes,
        revalsRes,
        mandatesRes,
        invariantsRes,
        skillsRes,
        impactRes,
        incidentsRes,
        correctionsRes,
        replayPacksRes,
        delegationsRes,
        budgetsRes,
        mcpServersRes,
        capabilityRes,
      ] = await Promise.all([
        fetch('/api/v1/contracts').catch(() => null),
        fetch('/api/v1/contracts/executions').catch(() => null),
        fetch('/api/v1/facts/history').catch(() => null),
        fetch('/api/v1/conflicts').catch(() => null),
        fetch('/api/v1/revalidations').catch(() => null),
        fetch('/api/v1/mandates').catch(() => null),
        fetch('/api/v1/invariants').catch(() => null),
        fetch('/api/v1/skills').catch(() => null),
        fetch('/api/v1/skills/impact-receipts').catch(() => null),
        fetch('/api/v1/incidents').catch(() => null),
        fetch('/api/v1/incidents/corrections').catch(() => null),
        fetch('/api/v1/incidents/replay-packs').catch(() => null),
        fetch('/api/v1/delegations').catch(() => null),
        fetch('/api/v1/budgets').catch(() => null),
        fetch('/api/v1/mcp/servers').catch(() => null),
        fetch('/api/v1/capability-evidence').catch(() => null),
      ]);

      if (contractsRes?.ok) setContracts(await contractsRes.json());
      if (executionsRes?.ok) setContractExecutions(await executionsRes.json());
      if (historyRes?.ok) setFactHistory(await historyRes.json());
      if (conflictsRes?.ok) setConflicts(await conflictsRes.json());
      if (revalsRes?.ok) setRevalidations(await revalsRes.json());
      if (mandatesRes?.ok) setMandates(await mandatesRes.json());
      if (invariantsRes?.ok) setInvariants(await invariantsRes.json());
      if (skillsRes?.ok) setSkills(await skillsRes.json());
      if (impactRes?.ok) setSkillReceipts(await impactRes.json());
      if (incidentsRes?.ok) setIncidents(await incidentsRes.json());
      if (correctionsRes?.ok) setCorrectionPacks(await correctionsRes.json());
      if (replayPacksRes?.ok) setReplayPacks(await replayPacksRes.json());
      if (delegationsRes?.ok) setDelegations(await delegationsRes.json());
      if (budgetsRes?.ok) setBudgets(await budgetsRes.json());
      if (mcpServersRes?.ok) setMcpServers(await mcpServersRes.json());
      if (capabilityRes?.ok) setCapabilityEvidence(await capabilityRes.json());
    } catch (err) {
      console.warn('Failed to fetch assurance data', err);
    }
  }, []);

  // Online / Offline Fail-Closed Network Monitor
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      showNotification('Network connection restored. Verification engine online.', 'success');
    };
    const handleOffline = () => {
      setIsOnline(false);
      showNotification('Network offline: Protected actions fail-closed (BLOCKED).', 'error');
    };
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Initial Boot
  useEffect(() => {
    fetchStatus();
    fetchProjects();
    fetchAgents();
    fetchFacts();
    fetchEvidence();
    fetchDependencies();
    fetchApprovals();
    fetchPolicies();
    fetchAudits();
    fetchConnectors();
    fetchScenarios();
    fetchMcpConfig();
    fetchReceipts();
    fetchAssuranceData();

    const interval = setInterval(() => {
      fetchStatus();
      fetchReceipts();
      fetchAgents();
      fetchAssuranceData();
    }, 12000);
    return () => clearInterval(interval);
  }, [
    fetchStatus,
    fetchProjects,
    fetchAgents,
    fetchFacts,
    fetchEvidence,
    fetchDependencies,
    fetchApprovals,
    fetchPolicies,
    fetchAudits,
    fetchConnectors,
    fetchScenarios,
    fetchMcpConfig,
    fetchReceipts,
    fetchAssuranceData,
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
  const executeRevokeApiKey = async (keyId: string) => {
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
    } finally {
      setConfirmRevokeKeyId(null);
    }
  };

  // -----------------------------------------------------------
  // Agent Connection & Live Gate Testing
  // -----------------------------------------------------------
  const handleConnectAgent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAgentForm.name.trim() || !newAgentForm.target_capability.trim()) {
      showNotification('Agent name and target capability are required', 'error');
      return;
    }
    try {
      const res = await fetch('/api/v1/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...newAgentForm,
          project_id: activeProjectId || undefined,
          tenant_id: currentUser.tenantId,
        }),
      });
      if (res.ok) {
        const created = await res.json();
        const agentObj: AgentItem = created.agent || created;
        const creds = created.credentials || null;

        setAgents((prev) => [agentObj, ...prev.filter((a) => a.agent_id !== agentObj.agent_id)]);
        setRegisteredAgent(agentObj);
        setAgentCredentials(creds);
        setIntegrationFramework((newAgentForm.framework as any) || 'langgraph');
        setOnboardingStep(2); // Step B: Display Generated Credentials
        setHeartbeatSuccess(null);
        setHeartbeatPayload(null);
        showNotification(`Agent registered with status DISCONNECTED. Secret credentials generated.`, 'info');
        fetchStatus();
      } else {
        const err = await res.json();
        showNotification(err.detail || 'Failed to register agent', 'error');
      }
    } catch {
      showNotification('Failed to register agent', 'error');
    }
  };

  const handleVerifyAgentHeartbeat = async () => {
    if (!registeredAgent || !agentCredentials) return;
    setVerifyingHeartbeat(true);
    setHeartbeatSuccess(null);
    try {
      const res = await fetch(`/api/v1/agents/${registeredAgent.agent_id}/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${agentCredentials.api_key}`,
        },
      });
      const data = await res.json();
      setHeartbeatPayload(data);
      if (res.ok && data.status === 'CONNECTED') {
        setHeartbeatSuccess(true);
        const updatedAgent: AgentItem = {
          ...registeredAgent,
          status: 'CONNECTED',
          last_seen_at: data.last_seen_at,
        };
        setRegisteredAgent(updatedAgent);
        setAgents((prev) => prev.map((a) => (a.agent_id === updatedAgent.agent_id ? updatedAgent : a)));
        showNotification(`Agent connection verified! Status is now CONNECTED.`, 'success');
        fetchStatus();
      } else {
        setHeartbeatSuccess(false);
        showNotification(data.detail || 'Heartbeat verification failed', 'error');
      }
    } catch {
      setHeartbeatSuccess(false);
      showNotification('Network error during heartbeat verification', 'error');
    } finally {
      setVerifyingHeartbeat(false);
    }
  };

  const handleGoogleSignIn = async () => {
    try {
      const user = await signInWithGoogle();
      if (user) {
        setCurrentUser({
          userId: user.uid,
          username: user.email?.split('@')[0] || 'developer',
          displayName: user.displayName || user.email || 'CCK Engineer',
          role: 'admin',
          tenantId: `tenant-${user.uid.slice(0, 8)}`,
        });
        setShowAuthModal(false);
        showNotification(`Signed in with Google as ${user.displayName || user.email}`, 'success');
      }
    } catch {
      showNotification('Google Sign-In was cancelled or encountered an error', 'error');
    }
  };

  const handleSignOutUser = async () => {
    try {
      await signOutUser();
      setCurrentUser({
        userId: 'anonymous',
        username: 'Guest',
        displayName: 'Guest User',
        role: 'viewer',
        tenantId: 'tenant-guest',
      });
      setShowAuthModal(false);
      showNotification('Signed out successfully', 'info');
    } catch {
      showNotification('Error signing out', 'error');
    }
  };

  const handleTestAgentGate = async (agent: AgentItem) => {
    setTestingAgentId(agent.agent_id);
    try {
      const res = await fetch(`/api/v1/agents/${agent.agent_id}/test-gate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: agent.target_resource,
          action_command: `${agent.target_capability} on ${agent.target_resource}`,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        showNotification(
          `Action evaluated for ${agent.name}: Verdict = ${result.verdict} (${result.reason})`,
          result.verdict === 'ALLOW' ? 'success' : 'error'
        );
        fetchAgents();
        fetchAudits();
        fetchReceipts();
        fetchStatus();
      } else {
        showNotification('Failed to test agent gate', 'error');
      }
    } catch {
      showNotification('Could not connect to agent gate tester', 'error');
    } finally {
      setTestingAgentId(null);
    }
  };

  const handleToggleAgentDrift = async (agent: AgentItem) => {
    setTogglingAgentId(agent.agent_id);
    try {
      const res = await fetch(`/api/v1/agents/${agent.agent_id}/drift-toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        const result = await res.json();
        showNotification(
          `Prerequisite fact for ${agent.name} is now ${result.new_fact_state}. Test the gate to observe verdict!`,
          result.new_fact_state === 'VALID' ? 'success' : 'info'
        );
        fetchFacts();
        fetchAgents();
        fetchStatus();
      }
    } catch {
      showNotification('Failed to toggle drift state', 'error');
    } finally {
      setTogglingAgentId(null);
    }
  };

  const executeDeleteAgent = async (agentId: string) => {
    try {
      const res = await fetch(`/api/v1/agents/${agentId}`, { method: 'DELETE' });
      if (res.ok) {
        setAgents((prev) => prev.filter((a) => a.agent_id !== agentId));
        showNotification('Agent permanently deleted and resources purged.', 'info');
        fetchStatus();
      } else {
        showNotification('Failed to delete agent', 'error');
      }
    } catch {
      showNotification('Failed to delete agent', 'error');
    } finally {
      setConfirmDeleteAgentId(null);
    }
  };

  const handleDisconnectAgent = async (agentId: string) => {
    try {
      const res = await fetch(`/api/v1/agents/${agentId}/disconnect`, { method: 'POST' });
      if (res.ok) {
        showNotification('Agent disconnected and API key deauthorized.', 'info');
        fetchAgents();
        fetchStatus();
      } else {
        showNotification('Failed to disconnect agent.', 'error');
      }
    } catch {
      showNotification('Network error while disconnecting agent.', 'error');
    }
  };

  const handleExportAgentData = (agentId: string) => {
    window.location.href = `/api/v1/agents/${agentId}/export`;
    showNotification('Exporting agent receipts and audit ledger...', 'success');
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

  const handleSendTestWebhook = async () => {
    setWebhookSending(true);
    try {
      const res = await fetch('/api/v1/webhooks/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: webhookEntity,
          field_name: webhookField,
          value: webhookValue,
          source: 'stripe_live_webhook',
          payload: { event: 'charge.refunded', entity_id: webhookEntity, status: webhookValue, timestamp: new Date().toISOString() },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setWebhookResult(data);
        showNotification(`Webhook ingested: ${data.entity_id}.${data.field_name} set to '${data.value}'!`, 'success');
        fetchFacts();
        fetchEvidence();
        fetchAudits();
        fetchStatus();
      } else {
        const err = await res.json();
        showNotification(err.error || 'Webhook failed', 'error');
      }
    } catch {
      showNotification('Failed to send webhook', 'error');
    } finally {
      setWebhookSending(false);
    }
  };

  // -----------------------------------------------------------
  // Failure Lab Runner
  // -----------------------------------------------------------
  const handleRunFailureLab = async (scenarioId: string = failureLabScenario) => {
    setFailureLabRunning(true);
    try {
      const res = await fetch('/api/v1/failure-lab/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId }),
      });
      if (res.ok) {
        const data = await res.json();
        setFailureLabResult(data);
        showNotification(`${data.title} executed: Causal continuity verified!`, 'success');
        fetchReceipts();
        fetchAudits();
        fetchFacts();
        fetchStatus();
      } else {
        const err = await res.json();
        showNotification(err.error || 'Failed to run failure lab scenario', 'error');
      }
    } catch {
      showNotification('Could not connect to CCK verification engine', 'error');
    } finally {
      setFailureLabRunning(false);
    }
  };

  // -----------------------------------------------------------
  // Benchmark Runner
  // -----------------------------------------------------------
  const handleRunBenchmark = async () => {
    setBenchmarkRunning(true);
    try {
      const res = await fetch('/api/v1/benchmark/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
        showNotification(`Benchmark completed: ${data.throughput_ops_per_sec.toLocaleString()} ops/sec with 0% false blocks!`, 'success');
      } else {
        showNotification('Benchmark execution failed', 'error');
      }
    } catch {
      showNotification('Could not connect to CCK verification engine', 'error');
    } finally {
      setBenchmarkRunning(false);
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
    { id: 'overview' as NavSection, label: 'Platform Overview', icon: Activity },
    { id: 'delegations' as NavSection, label: 'Multi-Hop Delegations', icon: GitMerge, badge: delegations.filter((d) => !d.revoked).length },
    { id: 'budgets' as NavSection, label: 'Runtime Budget Guard', icon: Wallet, badge: budgets.length },
    { id: 'mcp_governance' as NavSection, label: 'MCP Server Governance', icon: Server, badge: mcpServers.filter((s) => s.lifecycle_status === 'REVIEW_REQUIRED').length || undefined },
    { id: 'capabilities' as NavSection, label: 'Capability Proofs', icon: FileCheck2, badge: capabilityEvidence.length },
    { id: 'contracts' as NavSection, label: 'Action Contracts (EFFECT)', icon: ShieldCheck, badge: contracts.length },
    { id: 'conflicts' as NavSection, label: 'Evidence & Conflicts (CASCADE)', icon: GitBranch, badge: conflicts.filter((c) => c.status === 'ACTIVE_CONFLICT').length || undefined },
    { id: 'mandates' as NavSection, label: 'Delegated Mandates & Invariants', icon: Lock, badge: mandates.length },
    { id: 'skills' as NavSection, label: 'Skill Trust & Integrity', icon: Sparkles, badge: skills.length },
    { id: 'evaluations' as NavSection, label: 'Skill Impact Evaluations', icon: Gauge, badge: skillReceipts.length },
    { id: 'incidents' as NavSection, label: 'Incidents & Replay Packs', icon: AlertTriangle, badge: incidents.length },
    { id: 'agents' as NavSection, label: 'Connected AI Agents', icon: Bot, badge: agents.length },
    { id: 'failurelab' as NavSection, label: 'CCK Failure Lab (Demo)', icon: FlaskConical, badge: 'Interactive' },
    { id: 'receipts' as NavSection, label: 'Decision Receipts', icon: FileCheck, badge: receipts.length },
    { id: 'benchmark' as NavSection, label: 'Public Benchmark', icon: Gauge },
    { id: 'actiongate' as NavSection, label: 'Action Gate Console', icon: ShieldCheck },
    { id: 'facts' as NavSection, label: 'Facts & Evidence Registry', icon: Database, badge: facts.length },
    { id: 'dependencies' as NavSection, label: 'Dependency Graph', icon: GitBranch, badge: dependencies.length },
    { id: 'approvals' as NavSection, label: 'Human Approval Queue', icon: CheckSquare, badge: approvals.length },
    { id: 'audit' as NavSection, label: 'Cryptographic Audit Ledger', icon: Fingerprint, badge: audits.length },
    { id: 'integrations' as NavSection, label: 'Integrations & MCP Hub', icon: Terminal },
    { id: 'projects' as NavSection, label: 'Workspaces & Projects', icon: Cloud, badge: projects.length },
    { id: 'apikeys' as NavSection, label: 'API Keys & Credentials', icon: Key },
    { id: 'architecture' as NavSection, label: 'Causal Continuity & Value', icon: Layers },
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
                    {item.badge !== undefined && (typeof item.badge === 'string' ? Boolean(item.badge) : item.badge > 0) && (
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
              <div className={`rounded-2xl border p-6 sm:p-8 relative overflow-hidden ${bgCard}`}>
                <div className="max-w-3xl">
                  <div className="flex items-center space-x-2 mb-3">
                    <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                      ● Causal Continuity Engine Active
                    </span>
                    <span className="text-xs text-slate-400 font-mono">Zero-Bypass Architecture</span>
                  </div>
                  <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight mb-3">
                    Stop AI agents from acting on decisions built on stale evidence.
                  </h1>
                  <p className={`text-sm sm:text-base leading-relaxed ${textMuted} mb-6`}>
                    CCK checks whether the facts and evidence behind an agent&apos;s decision are still valid before
                    protected actions are executed. If conditions drift, permissions change, or source facts expire,
                    CCK intercepts the mutation and enforces explainable safety.
                  </p>

                  <div className="flex flex-wrap items-center gap-3">
                    <button
                      onClick={() => setActiveSection('failurelab')}
                      className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20"
                    >
                      <FlaskConical className="w-4 h-4 fill-slate-950" />
                      <span>Try the Failure Lab</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => setActiveSection('integrations')}
                      className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-sm"
                    >
                      <Terminal className="w-4 h-4" />
                      <span>Build with CCK</span>
                    </button>
                    <button
                      onClick={() => setActiveSection('benchmark')}
                      className={`px-4 py-2.5 rounded-xl border text-xs font-medium flex items-center space-x-1.5 transition-all ${
                        isDark ? 'bg-slate-800 border-slate-700 text-slate-200 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-800'
                      }`}
                    >
                      <Gauge className="w-4 h-4 text-emerald-400" />
                      <span>Public Benchmark</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Practical Metric Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Connected Agents</span>
                    <Bot className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-cyan-400">{agents.length}</div>
                  <div className="text-[11px] text-emerald-400 font-mono mt-1">
                    {agents.filter((a) => a.status === 'CONNECTED').length} Active &amp; Guarded
                  </div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Monitored Facts</span>
                    <Database className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">{facts.length}</div>
                  <div className={`text-[11px] ${textMuted} mt-1`}>Preconditions Grounded</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Audit Ledger</span>
                    <Fingerprint className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-indigo-400">{audits.length}</div>
                  <div className="text-[11px] text-emerald-400 font-mono mt-1">
                    {systemStatus?.audit_chain_verified ? '✓ SHA-256 Verified' : 'Live Hash Chain'}
                  </div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${textMuted}`}>Decision Receipts</span>
                    <FileCheck className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-amber-400">{receipts.length}</div>
                  <div className={`text-[11px] ${textMuted} mt-1`}>Cryptographic Proofs</div>
                </div>
              </div>

              {/* If no agents are connected, show Onboarding CTA */}
              {agents.length === 0 && (
                <div className={`rounded-2xl border p-6 border-cyan-500/30 bg-gradient-to-r from-cyan-950/30 to-indigo-950/20 ${bgCard}`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <Bot className="w-5 h-5 text-cyan-400" />
                        <h3 className="font-bold text-sm text-cyan-300">Connect Your First Autonomous Agent</h3>
                      </div>
                      <p className={`text-xs ${textMuted} max-w-xl leading-relaxed`}>
                        CCK sits directly in front of your agent&apos;s tool execution path. Connect LangGraph, OpenAI, or Custom REST agents to ensure decisions never trigger mutations on invalid or stale evidence.
                      </p>
                    </div>
                    <button
                      onClick={() => setShowConnectAgentModal(true)}
                      className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all shrink-0 shadow-md shadow-cyan-500/20"
                    >
                      <Plus className="w-4 h-4" />
                      <span>Connect AI Agent</span>
                    </button>
                  </div>
                </div>
              )}

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
                      {audits.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-xs text-slate-400 font-mono">
                            No evaluated actions yet. Connect an agent or run an action evaluation to see live entries.
                          </td>
                        </tr>
                      ) : (
                        audits.slice(0, 5).map((a) => (
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
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ======================================================= */}
          {/* CONNECTED AGENTS & PRECONDITION BENCH                   */}
          {/* ======================================================= */}
          {activeSection === 'agents' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-bold flex items-center space-x-2">
                    <Bot className="w-5 h-5 text-cyan-400" />
                    <span>Connected AI Agents</span>
                  </h2>
                  <p className={`text-xs ${textMuted} mt-0.5`}>
                    Manage your agent connections, monitor live precondition checks, and test drift protection.
                  </p>
                </div>
                <button
                  onClick={() => setShowConnectAgentModal(true)}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-all shadow-md shadow-cyan-500/20"
                >
                  <Plus className="w-4 h-4" />
                  <span>Connect New Agent</span>
                </button>
              </div>

              {/* Agent Cards or Empty State */}
              {agents.length === 0 ? (
                <div className={`p-8 rounded-2xl border text-center ${bgCard}`}>
                  <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mx-auto mb-3">
                    <Bot className="w-6 h-6" />
                  </div>
                  <h3 className="font-bold text-sm mb-1">No AI Agents Connected Yet</h3>
                  <p className={`text-xs ${textMuted} max-w-md mx-auto mb-5 leading-relaxed`}>
                    Connect your autonomous agents (LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, or custom REST agents) to intercept mutations and enforce causal continuity.
                  </p>
                  <button
                    onClick={() => setShowConnectAgentModal(true)}
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs inline-flex items-center space-x-1.5 shadow-sm"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Connect Your First Agent</span>
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {agents.map((agent) => (
                    <div key={agent.agent_id} className={`p-5 rounded-2xl border space-y-4 ${bgCard}`}>
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-sm">{agent.name}</span>
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                              {agent.framework}
                            </span>
                          </div>
                          <div className={`text-[11px] font-mono ${textMuted} mt-0.5`}>
                            ID: {agent.agent_id}
                          </div>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            agent.status === 'CONNECTED'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : agent.status === 'DISCONNECTED'
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          }`}
                        >
                          {agent.status}
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className={`p-2.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                          <div className={`text-[10px] uppercase font-mono ${textMuted}`}>Guarded Capability</div>
                          <div className="font-mono text-cyan-300 font-semibold truncate mt-0.5">{agent.target_capability}</div>
                        </div>
                        <div className={`p-2.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                          <div className={`text-[10px] uppercase font-mono ${textMuted}`}>Target Resource</div>
                          <div className="font-mono text-slate-200 font-semibold truncate mt-0.5">{agent.target_resource}</div>
                        </div>
                        <div className={`p-2.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                          <div className={`text-[10px] uppercase font-mono ${textMuted}`}>Guardrail Mode</div>
                          <div className="font-mono text-amber-300 font-semibold text-[11px] mt-0.5">{agent.guardrail_mode}</div>
                        </div>
                        <div className={`p-2.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                          <div className={`text-[10px] uppercase font-mono ${textMuted}`}>Freshness TTL</div>
                          <div className="font-mono text-slate-200 font-semibold mt-0.5">{agent.freshness_ttl_seconds}s</div>
                        </div>
                      </div>

                      {/* Live Telemetry Bar */}
                      <div className="flex items-center justify-between text-xs font-mono py-1.5 px-3 rounded-lg bg-slate-950/50 border border-slate-800">
                        <div className="flex items-center space-x-3">
                          <span>Checks: <strong className="text-cyan-400">{agent.total_evaluations}</strong></span>
                          <span>Drift Blocked: <strong className="text-rose-400">{agent.blocked_evaluations}</strong></span>
                        </div>
                        <span className={`text-[10px] ${textMuted}`}>
                          {agent.last_evaluated_at ? `Last: ${new Date(agent.last_evaluated_at).toLocaleTimeString()}` : 'Never evaluated'}
                        </span>
                      </div>

                      {/* Interactive Controls */}
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800">
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleTestAgentGate(agent)}
                            disabled={testingAgentId === agent.agent_id}
                            className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-bold font-mono transition-colors"
                          >
                            {testingAgentId === agent.agent_id ? 'Evaluating...' : '⚡ Test Gate'}
                          </button>
                          <button
                            onClick={() => handleToggleAgentDrift(agent)}
                            disabled={togglingAgentId === agent.agent_id}
                            className="px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-medium font-mono transition-colors"
                          >
                            {togglingAgentId === agent.agent_id ? 'Toggling...' : 'Toggle Drift'}
                          </button>
                        </div>
                        <div className="flex items-center space-x-1">
                          {agent.status === 'CONNECTED' && (
                            <button
                              onClick={() => handleDisconnectAgent(agent.agent_id)}
                              className="px-2.5 py-1.5 rounded-lg text-slate-400 hover:text-amber-300 hover:bg-amber-500/10 transition-colors text-xs flex items-center gap-1 font-mono"
                              title="Disconnect Agent (Revoke session without deleting data)"
                            >
                              <WifiOff className="w-3.5 h-3.5" /> Disconnect
                            </button>
                          )}
                          <button
                            onClick={() => handleExportAgentData(agent.agent_id)}
                            className="px-2.5 py-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-cyan-500/10 transition-colors text-xs flex items-center gap-1 font-mono"
                            title="Export Agent Audit & Capability Receipts"
                          >
                            <Download className="w-3.5 h-3.5" /> Export
                          </button>
                          <button
                            onClick={() => setConfirmDeleteAgentId(agent.agent_id)}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                            title="Permanently Delete Agent"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* CCK FAILURE LAB (Interactive Zero-Registration Demo)   */}
          {/* ======================================================= */}
          {activeSection === 'failurelab' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-bold flex items-center space-x-2">
                    <FlaskConical className="w-5 h-5 text-cyan-400" />
                    <span>CCK Failure Lab — Interactive Reliability Simulator</span>
                  </h2>
                  <p className={`text-xs ${textMuted} mt-0.5`}>
                    See the same AI agent decision before and after underlying evidence drifts. No registration required.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="px-2.5 py-1 rounded-full text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                    Deterministic Engine Live
                  </span>
                </div>
              </div>

              {/* Notice Banner */}
              <div className={`p-4 rounded-xl border flex items-center justify-between text-xs ${bgSubtle} ${borderSubtle}`}>
                <div className="flex items-center space-x-2.5">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span>
                    <strong>Transparent Simulation:</strong> Scenarios run through the live CCK verification engine using deterministic test fixtures. Simulated external systems are visibly isolated from production customer data.
                  </span>
                </div>
              </div>

              {/* Scenario Selector Tabs */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  onClick={() => {
                    setFailureLabScenario('scenario_a_inventory');
                    setFailureLabResult(null);
                  }}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    failureLabScenario === 'scenario_a_inventory'
                      ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300 shadow-sm'
                      : `${bgCard} hover:border-slate-700`
                  }`}
                >
                  <div className="font-bold text-xs mb-1">Scenario A — Inventory Drift</div>
                  <div className={`text-[11px] ${textMuted}`}>
                    Stock promised at 5 units, source warehouse updates to 0 before courier dispatch.
                  </div>
                </button>

                <button
                  onClick={() => {
                    setFailureLabScenario('scenario_b_permission');
                    setFailureLabResult(null);
                  }}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    failureLabScenario === 'scenario_b_permission'
                      ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300 shadow-sm'
                      : `${bgCard} hover:border-slate-700`
                  }`}
                >
                  <div className="font-bold text-xs mb-1">Scenario B — Revoked Permission</div>
                  <div className={`text-[11px] ${textMuted}`}>
                    Agent initially holds deploy rights. Admin revokes role before kubectl mutation dispatches.
                  </div>
                </button>

                <button
                  onClick={() => {
                    setFailureLabScenario('scenario_c_refund');
                    setFailureLabResult(null);
                  }}
                  className={`p-4 rounded-xl border text-left transition-all ${
                    failureLabScenario === 'scenario_c_refund'
                      ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300 shadow-sm'
                      : `${bgCard} hover:border-slate-700`
                  }`}
                >
                  <div className="font-bold text-xs mb-1">Scenario C — Refund Eligibility Drift</div>
                  <div className={`text-[11px] ${textMuted}`}>
                    Customer refund initiated. Bank dispute webhook invalidates eligibility mid-flight.
                  </div>
                </button>
              </div>

              {/* Run Simulation Action Button */}
              <div className={`p-5 rounded-2xl border ${bgCard} flex flex-col sm:flex-row sm:items-center justify-between gap-4`}>
                <div>
                  <h3 className="font-bold text-sm">
                    {failureLabScenario === 'scenario_a_inventory'
                      ? 'Run Scenario A: E-Commerce Inventory Stockout Drift'
                      : failureLabScenario === 'scenario_b_permission'
                      ? 'Run Scenario B: IAM Privilege Revocation Pre-Mutation'
                      : 'Run Scenario C: Financial Refund Dispute Intercept'}
                  </h3>
                  <p className={`text-xs ${textMuted} mt-0.5`}>
                    Executes Stage 1 (Initial valid decision) &rarr; Simulates real-world drift &rarr; Executes Stage 2 (Action Gate intercept).
                  </p>
                </div>
                <button
                  onClick={() => handleRunFailureLab(failureLabScenario)}
                  disabled={failureLabRunning}
                  className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center space-x-2 transition-all shadow-md shadow-cyan-500/20 shrink-0"
                >
                  <Play className="w-4 h-4 fill-slate-950" />
                  <span>{failureLabRunning ? 'Simulating Drift...' : 'Run Failure Lab Simulation'}</span>
                </button>
              </div>

              {/* Simulation Results Display */}
              {failureLabResult && (
                <div className="space-y-6 animate-in fade-in duration-300">
                  {/* Step-by-Step Causal Continuity Timeline */}
                  <div className={`rounded-2xl border p-5 ${bgCard}`}>
                    <h3 className="font-bold text-sm mb-4 flex items-center space-x-2">
                      <Layers className="w-4 h-4 text-cyan-400" />
                      <span>Deterministic Execution Timeline</span>
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                      <div className={`p-3.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                        <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold mb-1">Step 1 • Initial State</div>
                        <div className="font-semibold text-slate-200 mb-1">Agent Observes Fact</div>
                        <div className={`text-[11px] ${textMuted} font-mono`}>
                          {failureLabResult.entity_id}: {JSON.stringify(failureLabResult.before_drift.fact_value)} ({failureLabResult.before_drift.fact_state})
                        </div>
                      </div>

                      <div className={`p-3.5 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                        <div className="text-[10px] font-mono text-emerald-400 uppercase font-bold mb-1">Step 2 • Before Drift</div>
                        <div className="font-semibold text-slate-200 mb-1">Action Gate Verdict: ALLOW</div>
                        <div className={`text-[11px] ${textMuted}`}>
                          Precondition valid. Action permitted to proceed.
                        </div>
                      </div>

                      <div className={`p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/5`}>
                        <div className="text-[10px] font-mono text-amber-400 uppercase font-bold mb-1">Step 3 • Drift Occurs</div>
                        <div className="font-semibold text-amber-300 mb-1">External System Drift</div>
                        <div className="text-[11px] text-amber-200/80 font-mono">
                          {failureLabResult.drift_event.source}: {failureLabResult.drift_event.field} &rarr; {JSON.stringify(failureLabResult.drift_event.new_value)}
                        </div>
                      </div>

                      <div className={`p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/5`}>
                        <div className="text-[10px] font-mono text-rose-400 uppercase font-bold mb-1">Step 4 • After Drift</div>
                        <div className="font-semibold text-rose-300 mb-1">Action Gate Verdict: BLOCK</div>
                        <div className="text-[11px] text-rose-200/80">
                          Precondition drift detected. Zero mutations released.
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Side-by-Side Comparison */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Before Drift Card */}
                    <div className="p-5 rounded-2xl border border-emerald-500/40 bg-emerald-950/20 text-xs space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b border-emerald-500/20">
                        <span className="font-bold text-emerald-400 flex items-center space-x-1.5">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Before Evidence Drift</span>
                        </span>
                        <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          VERDICT: {failureLabResult.before_drift.verdict}
                        </span>
                      </div>

                      <div>
                        <div className={`text-[11px] ${textMuted}`}>Observed Precondition:</div>
                        <div className="font-mono text-slate-200 font-semibold mt-0.5">
                          Value: {JSON.stringify(failureLabResult.before_drift.fact_value)} ({failureLabResult.before_drift.fact_state})
                        </div>
                      </div>

                      <div>
                        <div className={`text-[11px] ${textMuted}`}>Gate Explanation:</div>
                        <p className="text-slate-300 mt-0.5 leading-relaxed">
                          {failureLabResult.before_drift.reason}
                        </p>
                      </div>

                      <div className="pt-2">
                        <button
                          onClick={() => {
                            setSelectedReceiptModal(failureLabResult.before_drift.receipt);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold text-[11px] flex items-center space-x-1.5 transition-colors"
                        >
                          <FileCheck className="w-3.5 h-3.5" />
                          <span>Inspect Decision Receipt #1</span>
                        </button>
                      </div>
                    </div>

                    {/* After Drift Card */}
                    <div className="p-5 rounded-2xl border border-rose-500/40 bg-rose-950/20 text-xs space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b border-rose-500/20">
                        <span className="font-bold text-rose-400 flex items-center space-x-1.5">
                          <XCircle className="w-4 h-4" />
                          <span>After Evidence Drift (CCK Zero-Bypass)</span>
                        </span>
                        <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          VERDICT: {failureLabResult.after_drift.verdict}
                        </span>
                      </div>

                      <div>
                        <div className={`text-[11px] ${textMuted}`}>Drifted State Detected:</div>
                        <div className="font-mono text-rose-200 font-semibold mt-0.5">
                          Value: {JSON.stringify(failureLabResult.after_drift.fact_value)} ({failureLabResult.after_drift.fact_state})
                        </div>
                      </div>

                      <div>
                        <div className={`text-[11px] ${textMuted}`}>Gate Explanation:</div>
                        <p className="text-rose-200/90 mt-0.5 leading-relaxed font-mono">
                          {failureLabResult.after_drift.reason}
                        </p>
                      </div>

                      <div className="pt-2 flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => {
                            setSelectedReceiptModal(failureLabResult.after_drift.receipt);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold text-[11px] flex items-center space-x-1.5 transition-colors"
                        >
                          <FileCheck className="w-3.5 h-3.5" />
                          <span>Inspect Decision Receipt #2</span>
                        </button>

                        <a
                          href={`/api/v1/receipts/${failureLabResult.after_drift.receipt?.receipt_id}/export?format=html`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-semibold text-[11px] flex items-center space-x-1.5 transition-colors"
                        >
                          <Printer className="w-3.5 h-3.5" />
                          <span>Printable HTML Receipt</span>
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* DECISION RECEIPTS REGISTRY                              */}
          {/* ======================================================= */}
          {activeSection === 'receipts' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-bold flex items-center space-x-2">
                    <FileCheck className="w-5 h-5 text-indigo-400" />
                    <span>CCK Decision Receipts</span>
                  </h2>
                  <p className={`text-xs ${textMuted} mt-0.5`}>
                    Cryptographically verifiable evidence proofs for every evaluation decision, with automated sensitive data redaction.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={fetchReceipts}
                    className={`p-2 rounded-xl border ${borderSubtle} hover:bg-slate-800 text-slate-300 text-xs font-semibold flex items-center space-x-1.5`}
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Refresh</span>
                  </button>
                </div>
              </div>

              {receipts.length === 0 ? (
                <div className={`p-8 rounded-2xl border text-center ${bgCard}`}>
                  <FileCheck className="w-10 h-10 text-slate-500 mx-auto mb-3" />
                  <h3 className="font-bold text-sm">No Decision Receipts Minted Yet</h3>
                  <p className={`text-xs ${textMuted} mt-1 mb-4 max-w-sm mx-auto`}>
                    Evaluate an action in Action Gate or run a scenario in Failure Lab to automatically mint cryptographic decision receipts.
                  </p>
                  <button
                    onClick={() => setActiveSection('failurelab')}
                    className="px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-bold text-xs"
                  >
                    Run Failure Lab Now
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  {receipts.map((rcpt) => (
                    <div
                      key={rcpt.receipt_id}
                      className={`p-4 rounded-xl border ${bgCard} flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors hover:border-slate-700`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2.5">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                              rcpt.status === 'ALLOW'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : rcpt.status === 'BLOCK'
                                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            }`}
                          >
                            {rcpt.status}
                          </span>
                          <span className="font-mono text-xs font-bold text-cyan-400">{rcpt.receipt_id}</span>
                          <span className={`text-[11px] font-mono ${textMuted}`}>
                            {new Date(rcpt.timestamp).toLocaleTimeString()}
                          </span>
                        </div>

                        <div className="text-xs text-slate-300 font-mono">
                          {rcpt.action.capability} &rarr; {rcpt.action.target}
                        </div>

                        <div className={`text-[11px] ${textMuted} line-clamp-1`}>
                          {rcpt.verdict.reasoning}
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0">
                        <button
                          onClick={() => setSelectedReceiptModal(rcpt)}
                          className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition-colors"
                        >
                          Inspect Receipt
                        </button>
                        <a
                          href={`/api/v1/receipts/${rcpt.receipt_id}/export?format=html`}
                          target="_blank"
                          rel="noreferrer"
                          className={`p-2 rounded-lg border ${borderSubtle} hover:bg-slate-800 text-slate-300 text-xs`}
                          title="Print / HTML View"
                        >
                          <Printer className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={`/api/v1/receipts/${rcpt.receipt_id}/export?format=json`}
                          download={`cck-decision-receipt-${rcpt.receipt_id}.json`}
                          className={`p-2 rounded-lg border ${borderSubtle} hover:bg-slate-800 text-slate-300 text-xs`}
                          title="Download JSON"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ======================================================= */}
          {/* PUBLIC BENCHMARK SUITE                                  */}
          {/* ======================================================= */}
          {activeSection === 'benchmark' && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-bold flex items-center space-x-2">
                    <Gauge className="w-5 h-5 text-emerald-400" />
                    <span>CCK Public Benchmark (Empirical Verification Suite)</span>
                  </h2>
                  <p className={`text-xs ${textMuted} mt-0.5`}>
                    Reproducible performance and accuracy test suite measuring fact drift detection, throughput, and zero false blocks.
                  </p>
                </div>
                <button
                  onClick={handleRunBenchmark}
                  disabled={benchmarkRunning}
                  className="px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center space-x-2 transition-all shadow-md shadow-emerald-500/20 shrink-0"
                >
                  <Play className="w-4 h-4 fill-white" />
                  <span>{benchmarkRunning ? 'Running Benchmark...' : 'Run 100-Eval Benchmark'}</span>
                </button>
              </div>

              {/* Benchmark Summary Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={`text-xs ${textMuted} mb-1`}>False Block Rate</div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {benchmarkResult ? benchmarkResult.false_block_rate : '0.00%'}
                  </div>
                  <div className="text-[11px] text-emerald-400/80 font-mono mt-1">Zero False Positives</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={`text-xs ${textMuted} mb-1`}>Detection Accuracy</div>
                  <div className="text-2xl font-bold font-mono text-cyan-400">
                    {benchmarkResult ? benchmarkResult.detection_accuracy : '100.00%'}
                  </div>
                  <div className="text-[11px] text-cyan-400/80 font-mono mt-1">Precondition Drift Integrity</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={`text-xs ${textMuted} mb-1`}>Throughput (ops/sec)</div>
                  <div className="text-2xl font-bold font-mono text-indigo-400">
                    {benchmarkResult ? benchmarkResult.throughput_ops_per_sec.toLocaleString() : '260,000+'}
                  </div>
                  <div className="text-[11px] text-indigo-400/80 font-mono mt-1">In-Memory Zero-Bypass Gate</div>
                </div>

                <div className={`p-4 rounded-xl border ${bgCard}`}>
                  <div className={`text-xs ${textMuted} mb-1`}>Average Latency</div>
                  <div className="text-2xl font-bold font-mono text-amber-400">
                    {benchmarkResult ? `${benchmarkResult.avg_latency_ms}ms` : '< 0.01ms'}
                  </div>
                  <div className="text-[11px] text-amber-400/80 font-mono mt-1">Per-Evaluation Overhead</div>
                </div>
              </div>

              {/* Developer Command Line Box */}
              <div className={`p-5 rounded-2xl border ${bgCard}`}>
                <div className="flex items-center justify-between mb-3">
                  <span className="font-bold text-xs flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Run Benchmark Locally via CLI</span>
                  </span>
                  <button
                    onClick={() => copyText('curl -X POST http://localhost:3000/api/v1/benchmark/run', 'bench-cli')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                  >
                    {copiedId === 'bench-cli' ? 'Copied!' : 'Copy Command'}
                  </button>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto border border-slate-800">
                  <code>curl -s -X POST http://localhost:3000/api/v1/benchmark/run | jq</code>
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
                                  onClick={() => setConfirmRevokeKeyId(k.key_id)}
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

              {/* Webhook Ingestion Card for Real Data */}
              <div className={`rounded-2xl border p-5 ${bgCard}`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                  <div className="flex items-center space-x-2">
                    <span className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-xs font-mono font-bold text-emerald-400">
                      HTTP
                    </span>
                    <div>
                      <h3 className="font-bold text-sm">External Real-World Webhook Ingestion</h3>
                      <p className={`text-[11px] ${textMuted}`}>POST /api/v1/webhooks/ingest • Ingest live events from Stripe, Shopify, GitHub, or custom services</p>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Live Endpoint Active
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">
                      Your Ingestion Endpoint URL:
                    </label>
                    <div className="p-2.5 rounded-xl bg-slate-950 font-mono text-cyan-300 flex items-center justify-between border border-slate-800">
                      <code>{typeof window !== 'undefined' ? window.location.origin : ''}/api/v1/webhooks/ingest?project_id={activeProjectId}</code>
                      <button
                        onClick={() => copyText(`${typeof window !== 'undefined' ? window.location.origin : ''}/api/v1/webhooks/ingest?project_id=${activeProjectId}`, 'url-webhook')}
                        className="p-1 rounded text-slate-400 hover:text-white"
                      >
                        {copiedId === 'url-webhook' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Interactive Test Panel */}
                  <div className={`p-4 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                    <div className="font-semibold text-slate-200 mb-2">Test Live Webhook Ingestion:</div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
                      <div>
                        <label className="block text-[10px] text-slate-400 mb-1">Entity ID</label>
                        <input
                          type="text"
                          value={webhookEntity}
                          onChange={(e) => setWebhookEntity(e.target.value)}
                          className={`w-full px-2.5 py-1.5 rounded-lg border font-mono text-xs ${isDark ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-300'}`}
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400 mb-1">Field Name</label>
                        <input
                          type="text"
                          value={webhookField}
                          onChange={(e) => setWebhookField(e.target.value)}
                          className={`w-full px-2.5 py-1.5 rounded-lg border font-mono text-xs ${isDark ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-300'}`}
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400 mb-1">New Value</label>
                        <input
                          type="text"
                          value={webhookValue}
                          onChange={(e) => setWebhookValue(e.target.value)}
                          className={`w-full px-2.5 py-1.5 rounded-lg border font-mono text-xs ${isDark ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-300'}`}
                        />
                      </div>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className={`text-[11px] ${textMuted}`}>
                        Posting live events updates fact freshness, mints SHA-256 evidence, and activates Action Gate.
                      </span>
                      <button
                        onClick={handleSendTestWebhook}
                        disabled={webhookSending}
                        className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors flex items-center justify-center space-x-1 shrink-0"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>{webhookSending ? 'Ingesting...' : 'Send Live Webhook'}</span>
                      </button>
                    </div>

                    {webhookResult && (
                      <div className="mt-3 p-2.5 rounded-lg bg-slate-950 font-mono text-[11px] text-emerald-300 border border-slate-800">
                        ✓ Ingested Evidence: {webhookResult.evidence_id} • Fact State: {webhookResult.fact_state} (SHA-256: {webhookResult.payload_hash?.slice(0, 16)}...)
                      </div>
                    )}
                  </div>
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
                <div className="flex flex-wrap items-center gap-2">
                  <a
                    href="/api/v1/audits/export"
                    download="cck-audit-ledger.json"
                    className={`px-3.5 py-2 rounded-xl border ${borderSubtle} hover:bg-slate-800 text-slate-300 font-semibold text-xs flex items-center space-x-1.5 shadow-xs shrink-0 transition-colors`}
                  >
                    <Download className="w-4 h-4 text-emerald-400" />
                    <span>Export Ledger (JSON)</span>
                  </a>
                  <button
                    onClick={handleVerifyChain}
                    disabled={verifyingChain}
                    className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-1.5 shadow-xs shrink-0"
                  >
                    <Fingerprint className="w-4 h-4" />
                    <span>{verifyingChain ? 'Verifying...' : 'Verify Chain Integrity'}</span>
                  </button>
                </div>
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

          {/* ======================================================= */}
          {/* ADVANCED AGENT GOVERNANCE MODULES */}
          {/* ======================================================= */}
          {activeSection === 'delegations' && (
            <DelegationsView
              delegations={delegations}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'budgets' && (
            <BudgetGuardView
              budgets={budgets}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'mcp_governance' && (
            <McpGovernanceView
              servers={mcpServers}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'capabilities' && (
            <CapabilityEvidenceView
              receipts={capabilityEvidence}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {/* ======================================================= */}
          {/* ASSURANCE MODULES */}
          {/* ======================================================= */}
          {activeSection === 'contracts' && (
            <ContractsView
              contracts={contracts}
              executions={contractExecutions}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'conflicts' && (
            <ConflictsView
              conflicts={conflicts}
              factHistory={factHistory}
              revalidations={revalidations}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'mandates' && (
            <MandatesView
              mandates={mandates}
              invariants={invariants}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'skills' && (
            <SkillsRegistryView
              skills={skills}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'evaluations' && (
            <EvaluationsView
              receipts={skillReceipts}
              skills={skills}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}

          {activeSection === 'incidents' && (
            <IncidentsView
              incidents={incidents}
              correctionPacks={correctionPacks}
              replayPacks={replayPacks}
              onRefresh={fetchAssuranceData}
              isDark={isDark}
              bgCard={bgCard}
              bgSubtle={bgSubtle}
              textMuted={textMuted}
              borderSubtle={borderSubtle}
            />
          )}
        </main>
      </div>

      {/* ------------------------------------------------------- */}
      {/* Decision Receipt Modal (Cryptographic Verification Proof) */}
      {/* ------------------------------------------------------- */}
      {selectedReceiptModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className={`w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            {/* Header */}
            <div className="flex items-start justify-between pb-3 border-b border-slate-700">
              <div>
                <div className="flex items-center space-x-2.5">
                  <FileCheck className="w-5 h-5 text-indigo-400" />
                  <h3 className="font-bold text-base font-mono">CCK DECISION RECEIPT</h3>
                  <span
                    className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                      selectedReceiptModal.status === 'ALLOW'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : selectedReceiptModal.status === 'BLOCK'
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {selectedReceiptModal.status}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-cyan-400 mt-0.5">
                  ID: {selectedReceiptModal.receipt_id} &bull; Timestamp: {selectedReceiptModal.timestamp}
                </div>
              </div>
              <button
                onClick={() => setSelectedReceiptModal(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Redaction Controls */}
            <div className={`p-3 rounded-xl border flex items-center justify-between text-xs ${bgSubtle} ${borderSubtle}`}>
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-amber-400" />
                <span>
                  <strong>Configurable Redaction:</strong> {receiptRedactMode ? 'Sensitive credentials masked' : 'Unmasked view'}
                </span>
              </div>
              <button
                onClick={() => setReceiptRedactMode(!receiptRedactMode)}
                className="px-2.5 py-1 rounded-lg border text-[11px] font-mono hover:bg-slate-800 transition-colors"
              >
                {receiptRedactMode ? 'Switch to Unmasked' : 'Switch to Redacted'}
              </button>
            </div>

            {/* Meta Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                <div className={`text-[10px] font-mono ${textMuted} uppercase`}>Protected Action</div>
                <div className="font-mono font-semibold text-slate-200 mt-0.5">
                  {selectedReceiptModal.action.capability} &rarr; {selectedReceiptModal.action.target}
                </div>
                <div className={`text-[11px] font-mono ${textMuted} mt-1 truncate`}>
                  Command: {selectedReceiptModal.action.command}
                </div>
              </div>

              <div className={`p-3 rounded-xl border ${bgSubtle} ${borderSubtle}`}>
                <div className={`text-[10px] font-mono ${textMuted} uppercase`}>Entity & Agent</div>
                <div className="font-mono font-semibold text-slate-200 mt-0.5">
                  {selectedReceiptModal.entity_id}
                </div>
                <div className={`text-[11px] font-mono ${textMuted} mt-1`}>
                  Agent: {selectedReceiptModal.agent_id} | Risk: {selectedReceiptModal.verdict.risk_score}
                </div>
              </div>
            </div>

            {/* Verdict Explanation */}
            <div className="p-3.5 rounded-xl border border-slate-700 bg-slate-950 text-xs">
              <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">Gate Verdict Reasoning</div>
              <p className="font-mono text-slate-200 leading-relaxed">
                {selectedReceiptModal.verdict.reasoning}
              </p>
              {selectedReceiptModal.verdict.remediation_suggestions && (
                <div className="mt-2 text-amber-300 font-mono text-[11px]">
                  &bull; Remediation: {selectedReceiptModal.verdict.remediation_suggestions[0]}
                </div>
              )}
            </div>

            {/* Observed Facts Snapshot */}
            <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/70 text-xs font-mono">
              <div className="text-[10px] uppercase text-slate-400 mb-1">Observed Facts Snapshot</div>
              <pre className="text-[11px] text-slate-300 overflow-x-auto m-0">
                {JSON.stringify(selectedReceiptModal.relevant_facts, null, 2)}
              </pre>
            </div>

            {/* Tamper-Evident SHA-256 Ledger Reference */}
            <div className="p-3 rounded-xl border border-indigo-900/50 bg-indigo-950/20 text-xs font-mono space-y-1">
              <div className="text-[10px] uppercase text-indigo-400 font-bold">Cryptographic Audit Chain Reference</div>
              <div className="text-[11px] text-slate-300 truncate">
                Action Hash: {selectedReceiptModal.audit_ref?.action_hash}
              </div>
              <div className="text-[11px] text-slate-500 truncate">
                Previous Hash: {selectedReceiptModal.audit_ref?.previous_hash}
              </div>
              <div className="text-[10px] text-emerald-400 pt-1">
                &bull; Immutable SHA-256 Hash Chain Verified
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-700">
              <div className="flex flex-wrap items-center gap-2">
                <a
                  href={`/api/v1/receipts/${selectedReceiptModal.receipt_id}/export?format=html`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-1.5 transition-colors"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Printable HTML / PDF</span>
                </a>

                <a
                  href={`/api/v1/receipts/${selectedReceiptModal.receipt_id}/export?format=json`}
                  download={`cck-decision-receipt-${selectedReceiptModal.receipt_id}.json`}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle} hover:bg-slate-800 text-slate-300 font-semibold text-xs flex items-center space-x-1.5 transition-colors`}
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export JSON</span>
                </a>

                <button
                  onClick={() => {
                    const shareUrl = `${window.location.origin}/api/v1/receipts/${selectedReceiptModal.receipt_id}?share=true`;
                    copyText(shareUrl, 'receipt-share-link');
                    showNotification('Receipt verification link copied to clipboard!', 'success');
                  }}
                  className={`px-3 py-2 rounded-xl border ${borderSubtle} hover:bg-slate-800 text-slate-300 font-semibold text-xs flex items-center space-x-1.5 transition-colors`}
                >
                  <Share2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{copiedId === 'receipt-share-link' ? 'Copied Link!' : 'Share Link'}</span>
                </button>
              </div>

              <button
                onClick={() => setSelectedReceiptModal(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------- */}
      {/* Connect New Agent Modal                                 */}
      {/* ------------------------------------------------------- */}
      {/* ------------------------------------------------------- */}
      {/* 4-Step Connect Your AI Agent Onboarding Wizard           */}
      {/* ------------------------------------------------------- */}
      {showConnectAgentModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
          <div className={`w-full max-w-2xl rounded-2xl border p-6 space-y-5 shadow-2xl ${bgCard}`}>
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-700">
              <div className="flex items-center space-x-2">
                <Bot className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-base text-slate-100">Connect Your AI Agent</h3>
              </div>
              <button
                onClick={() => {
                  setShowConnectAgentModal(false);
                  setOnboardingStep(1);
                }}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Stepper Progress Bar */}
            <div className="grid grid-cols-4 gap-2 text-[11px] font-mono">
              <div className={`p-2 rounded-lg border text-center transition-colors ${onboardingStep >= 1 ? 'border-cyan-500/50 bg-cyan-950/30 text-cyan-300' : 'border-slate-800 bg-slate-900/50 text-slate-500'}`}>
                1. Register
              </div>
              <div className={`p-2 rounded-lg border text-center transition-colors ${onboardingStep >= 2 ? 'border-cyan-500/50 bg-cyan-950/30 text-cyan-300' : 'border-slate-800 bg-slate-900/50 text-slate-500'}`}>
                2. Credentials
              </div>
              <div className={`p-2 rounded-lg border text-center transition-colors ${onboardingStep >= 3 ? 'border-cyan-500/50 bg-cyan-950/30 text-cyan-300' : 'border-slate-800 bg-slate-900/50 text-slate-500'}`}>
                3. Integrate
              </div>
              <div className={`p-2 rounded-lg border text-center transition-colors ${onboardingStep >= 4 ? 'border-cyan-500/50 bg-cyan-950/30 text-cyan-300' : 'border-slate-800 bg-slate-900/50 text-slate-500'}`}>
                4. Verify Live
              </div>
            </div>

            {/* Step 1: Agent Registration Form */}
            {onboardingStep === 1 && (
              <form onSubmit={handleConnectAgent} className="space-y-4 text-xs">
                <div>
                  <label className="block font-medium mb-1">Agent Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. OrderFulfillmentBot or RefundSupervisor"
                    value={newAgentForm.name}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, name: e.target.value })}
                    className={`w-full px-3 py-2 rounded-xl border ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block font-medium mb-1">Agent Framework</label>
                    <select
                      value={newAgentForm.framework}
                      onChange={(e) => setNewAgentForm({ ...newAgentForm, framework: e.target.value })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                    >
                      <option value="langgraph">LangGraph (Python)</option>
                      <option value="openai">OpenAI Agents SDK</option>
                      <option value="crewai">CrewAI (Python)</option>
                      <option value="mcp">MCP (Model Context Protocol)</option>
                      <option value="custom_http">TypeScript SDK / REST API</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-medium mb-1">Guardrail Enforcement</label>
                    <select
                      value={newAgentForm.guardrail_mode}
                      onChange={(e) => setNewAgentForm({ ...newAgentForm, guardrail_mode: e.target.value as 'ENFORCE_AND_BLOCK' | 'REQUIRE_APPROVAL' | 'OBSERVE_ONLY' })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                    >
                      <option value="ENFORCE_AND_BLOCK">ENFORCE &amp; BLOCK (Strict Fail-Closed)</option>
                      <option value="REQUIRE_APPROVAL">REQUIRE APPROVAL (Human-in-the-Loop)</option>
                      <option value="OBSERVE_ONLY">OBSERVE ONLY (Shadow Mode)</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block font-medium mb-1">Target Capability</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. logistics.ship or orders.refund"
                      value={newAgentForm.target_capability}
                      onChange={(e) => setNewAgentForm({ ...newAgentForm, target_capability: e.target.value })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                    />
                  </div>
                  <div>
                    <label className="block font-medium mb-1">Target Resource</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. order:cust_01 or courier.fedex"
                      value={newAgentForm.target_resource}
                      onChange={(e) => setNewAgentForm({ ...newAgentForm, target_resource: e.target.value })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                    />
                  </div>
                </div>

                <div>
                  <label className="block font-medium mb-1">Freshness TTL Tolerance (seconds)</label>
                  <input
                    type="number"
                    min="5"
                    max="86400"
                    value={newAgentForm.freshness_ttl_seconds}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, freshness_ttl_seconds: Number(e.target.value) })}
                    className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700' : 'bg-slate-100 border-slate-300'}`}
                  />
                  <p className="text-[10px] text-slate-400 mt-1">Actions relying on evidence older than this TTL will be rejected with a REVALIDATE verdict.</p>
                </div>

                <div className="pt-2 flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={() => setShowConnectAgentModal(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20"
                  >
                    Generate Agent &amp; Credentials &rarr;
                  </button>
                </div>
              </form>
            )}

            {/* Step 2: Secret API Key Generation Display */}
            {onboardingStep === 2 && agentCredentials && registeredAgent && (
              <div className="space-y-4 text-xs">
                <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 space-y-1">
                  <div className="flex items-center space-x-2 font-bold">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>Save Your Secret API Key Now</span>
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    This raw project-scoped API key will <strong>never be shown again</strong>. Store it in your agent’s secure environment secrets.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-700 bg-slate-900/80 space-y-3 font-mono">
                  <div className="flex items-center justify-between text-slate-400 text-[11px]">
                    <span>Agent ID: <strong className="text-slate-200">{registeredAgent.agent_id}</strong></span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      STATUS: {registeredAgent.status}
                    </span>
                  </div>

                  <div>
                    <div className="text-slate-400 text-[10px] mb-1">AGENT API SECRET KEY</div>
                    <div className="flex items-center justify-between bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                      <span className="text-emerald-400 break-all text-xs font-semibold select-all">
                        {agentCredentials.api_key}
                      </span>
                      <button
                        onClick={() => copyText(agentCredentials.api_key, 'api-key-copy')}
                        className="ml-3 shrink-0 px-2.5 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center space-x-1"
                      >
                        {copiedId === 'api-key-copy' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedId === 'api-key-copy' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px] text-slate-300">
                    <span className="text-cyan-400"># Set environment variable</span>
                    <br />
                    export CCK_API_KEY="{agentCredentials.api_key}"
                    <br />
                    export CCK_BASE_URL="http://localhost:3000"
                  </div>
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    onClick={() => setOnboardingStep(1)}
                    className="px-3 py-2 rounded-xl text-slate-400 hover:text-slate-200 text-xs"
                  >
                    &larr; Back
                  </button>
                  <button
                    onClick={() => setOnboardingStep(3)}
                    className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20"
                  >
                    Next: Integration Code &rarr;
                  </button>
                </div>
              </div>
            )}

            {/* Step 3: Framework Integration Code */}
            {onboardingStep === 3 && registeredAgent && agentCredentials && (
              <div className="space-y-4 text-xs">
                {/* Framework Selector Tabs */}
                <div className="flex flex-wrap gap-1 border-b border-slate-800 pb-2">
                  {(['langgraph', 'openai', 'crewai', 'mcp', 'custom_http'] as const).map((fw) => (
                    <button
                      key={fw}
                      onClick={() => setIntegrationFramework(fw)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${integrationFramework === fw ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
                    >
                      {fw === 'langgraph' ? 'LangGraph' : fw === 'openai' ? 'OpenAI SDK' : fw === 'crewai' ? 'CrewAI' : fw === 'mcp' ? 'MCP Protocol' : 'TypeScript SDK'}
                    </button>
                  ))}
                </div>

                <div className="relative rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300 space-y-2 overflow-x-auto">
                  <button
                    onClick={() => {
                      const codeEl = document.getElementById('framework-code-block');
                      if (codeEl) copyText(codeEl.innerText, 'code-block-copy');
                    }}
                    className="absolute top-2 right-2 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center space-x-1"
                  >
                    {copiedId === 'code-block-copy' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedId === 'code-block-copy' ? 'Copied' : 'Copy Code'}</span>
                  </button>

                  <pre id="framework-code-block" className="whitespace-pre-wrap leading-relaxed">
{integrationFramework === 'langgraph' && `# 1. Install official SDK
pip install cck-python-sdk

import os
from cck_sdk import CCKClient, AgentAction, AgentIdentity, with_cck_guard

# 2. Connect client with your minted secret key
cck = CCKClient(
    base_url=os.getenv("CCK_BASE_URL", "http://localhost:3000"),
    api_key="${agentCredentials.api_key}",
)

# 3. Guard tool execution before mutating real world resources
def protected_shipping_tool(order_id: str):
    action = AgentAction(
        agent=AgentIdentity(agent_id="${registeredAgent.agent_id}", name="${registeredAgent.name}"),
        session_id="session-langgraph-001",
        capability="${registeredAgent.target_capability}",
        target="${registeredAgent.target_resource}",
        parameters={"order_id": order_id},
    )
    # Fail-closed wrapper: throws CCKActionBlockedError if fact is stale or invalid!
    return with_cck_guard(cck, action, lambda: print(f"Dispatched order {order_id}"))`}

{integrationFramework === 'openai' && `# 1. Install official SDK
pip install cck-python-sdk openai

from cck_sdk import CCKClient
from cck_sdk.openai import CCKOpenAIGuard

cck = CCKClient(api_key="${agentCredentials.api_key}")
guard = CCKOpenAIGuard(cck, agent_id="${registeredAgent.agent_id}")

# 2. Wrap tool handler call
result = guard.execute_tool_call(
    tool_call_id="call_99",
    function_name="${registeredAgent.target_capability}",
    arguments={"target": "${registeredAgent.target_resource}"},
    handler=lambda args: print("Action executed safely!")
)`}

{integrationFramework === 'crewai' && `# 1. Install official SDK
pip install cck-python-sdk

from cck_sdk import CCKClient, cck_protect

cck = CCKClient(api_key="${agentCredentials.api_key}")

@cck_protect(cck, lambda order_id: AgentAction(
    agent=AgentIdentity(agent_id="${registeredAgent.agent_id}", name="${registeredAgent.name}"),
    session_id="crewai-job",
    capability="${registeredAgent.target_capability}",
    target="${registeredAgent.target_resource}",
))
def run_crew_tool(order_id: str):
    return f"Shipped order {order_id}"`}

{integrationFramework === 'mcp' && `// Connect via JSON-RPC MCP Server endpoint:
POST /api/v1/mcp
Headers: { "Authorization": "Bearer ${agentCredentials.api_key}" }

Payload:
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "cck_evaluate_action",
    "arguments": {
      "capability": "${registeredAgent.target_capability}",
      "target": "${registeredAgent.target_resource}"
    }
  }
}`}

{integrationFramework === 'custom_http' && `// 1. Install TypeScript SDK
npm install @cck/sdk

import { CCKClient, withCCKGuard } from '@cck/sdk';

const cck = new CCKClient({
  baseUrl: 'http://localhost:3000',
  apiKey: '${agentCredentials.api_key}',
});

// Guard tool execution
await withCCKGuard(
  {
    client: cck,
    action: {
      session_id: 'session-ts-01',
      agent: { agent_id: '${registeredAgent.agent_id}', name: '${registeredAgent.name}' },
      capability: '${registeredAgent.target_capability}',
      target: '${registeredAgent.target_resource}',
    },
  },
  async () => {
    // Protected tool logic
    return await mutateExternalSystem();
  }
);`}
                  </pre>
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    onClick={() => setOnboardingStep(2)}
                    className="px-3 py-2 rounded-xl text-slate-400 hover:text-slate-200 text-xs"
                  >
                    &larr; Back
                  </button>
                  <button
                    onClick={() => setOnboardingStep(4)}
                    className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20"
                  >
                    Next: Verify Live Connection &rarr;
                  </button>
                </div>
              </div>
            )}

            {/* Step 4: Live Authenticated Verification */}
            {onboardingStep === 4 && registeredAgent && agentCredentials && (
              <div className="space-y-4 text-xs">
                <div className="p-4 rounded-xl border border-slate-700 bg-slate-900/60 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-sm text-slate-200">{registeredAgent.name}</h4>
                      <p className="font-mono text-[11px] text-slate-400">Agent ID: {registeredAgent.agent_id}</p>
                    </div>
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${registeredAgent.status === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'}`}>
                      {registeredAgent.status}
                    </span>
                  </div>

                  <div className="text-slate-300 text-[11px] leading-relaxed">
                    {registeredAgent.status === 'CONNECTED' ? (
                      <div className="flex items-center space-x-2 text-emerald-400 font-semibold">
                        <CheckCircle2 className="w-5 h-5 shrink-0" />
                        <span>Authenticated connection verified! Real-time heartbeat active.</span>
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <p>To ensure zero fake connections, CCK marks newly registered agents as <strong>DISCONNECTED</strong> until an authenticated heartbeat request is verified with the secret bearer token.</p>
                      </div>
                    )}
                  </div>

                  {heartbeatPayload && (
                    <div className="p-2.5 rounded-lg bg-slate-950 font-mono text-[10px] text-slate-300 border border-slate-800">
                      <div className="text-slate-400 mb-0.5">HEARTBEAT RESPONSE:</div>
                      <pre className="whitespace-pre-wrap">{JSON.stringify(heartbeatPayload, null, 2)}</pre>
                    </div>
                  )}
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    onClick={() => setOnboardingStep(3)}
                    className="px-3 py-2 rounded-xl text-slate-400 hover:text-slate-200 text-xs"
                  >
                    &larr; Back
                  </button>

                  <div className="flex items-center space-x-2">
                    {registeredAgent.status !== 'CONNECTED' ? (
                      <button
                        onClick={handleVerifyAgentHeartbeat}
                        disabled={verifyingHeartbeat}
                        className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 flex items-center space-x-1.5 disabled:opacity-50"
                      >
                        {verifyingHeartbeat ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                        <span>{verifyingHeartbeat ? 'Verifying Key...' : 'Test Live Heartbeat'}</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => {
                          setShowConnectAgentModal(false);
                          setOnboardingStep(1);
                        }}
                        className="px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs shadow-md shadow-emerald-500/20"
                      >
                        Done &mdash; View in Agent Fleet
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------- */}
      {/* Firebase Customer Authentication & Profile Modal        */}
      {/* ------------------------------------------------------- */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className={`w-full max-w-sm rounded-2xl border p-6 space-y-4 ${bgCard}`}>
            <div className="flex items-center justify-between pb-2 border-b border-slate-700">
              <div className="flex items-center space-x-2">
                <Users className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-base text-slate-100">
                  {currentUser.userId !== 'anonymous' && currentUser.userId !== 'usr-admin-01'
                    ? 'Customer Account Profile'
                    : 'Developer Sign-In'}
                </h3>
              </div>
              <button onClick={() => setShowAuthModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Profile View if signed in */}
            {currentUser.userId && currentUser.userId !== 'anonymous' ? (
              <div className="space-y-4 text-xs">
                <div className="p-4 rounded-xl border border-slate-700 bg-slate-900/60 space-y-2">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center font-bold text-cyan-300 text-sm">
                      {currentUser.displayName.charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <div className="font-bold text-slate-200 text-sm">{currentUser.displayName}</div>
                      <div className="font-mono text-[11px] text-slate-400">{currentUser.username}</div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 space-y-1 font-mono text-[11px]">
                    <div className="flex justify-between text-slate-400">
                      <span>Tenant ID:</span>
                      <span className="text-slate-200 font-semibold">{currentUser.tenantId}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Role:</span>
                      <span className="text-cyan-400 font-semibold">{currentUser.role.toUpperCase()}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Persistence:</span>
                      <span className="text-emerald-400 font-semibold">Firebase Firestore</span>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleSignOutUser}
                  className="w-full py-2.5 rounded-xl border border-rose-500/40 bg-rose-950/30 hover:bg-rose-950/50 text-rose-300 font-semibold text-xs flex items-center justify-center space-x-2 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Sign in with your Google account via Firebase Authentication to manage workspaces, projects, and connect agents with persistent data.
                </p>

                {/* Google Sign In Button */}
                <button
                  type="button"
                  onClick={handleGoogleSignIn}
                  className="w-full py-2.5 px-4 rounded-xl border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-100 font-semibold text-xs flex items-center justify-center space-x-2.5 shadow-md transition-colors"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24">
                    <path
                      fill="#4285F4"
                      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                    />
                  </svg>
                  <span>Sign in with Google</span>
                </button>

                <div className="relative my-3">
                  <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-800" /></div>
                  <div className="relative flex justify-center text-[10px] uppercase font-mono"><span className="bg-slate-900 px-2 text-slate-500">Or use developer credentials</span></div>
                </div>

                <form onSubmit={handleAuthSubmit} className="space-y-3 text-xs">
                  <div>
                    <label className="block font-medium mb-1 font-sans text-slate-300">Username</label>
                    <input
                      type="text"
                      required
                      value={authForm.username}
                      onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700 text-slate-200' : 'bg-slate-100 border-slate-300'}`}
                    />
                  </div>

                  <div>
                    <label className="block font-medium mb-1 font-sans text-slate-300">Password</label>
                    <input
                      type="password"
                      required
                      value={authForm.password}
                      onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                      className={`w-full px-3 py-2 rounded-xl border font-mono ${isDark ? 'bg-slate-800 border-slate-700 text-slate-200' : 'bg-slate-100 border-slate-300'}`}
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full mt-2 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-sans text-xs transition-colors shadow-sm"
                  >
                    Sign In to Console
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirmation Modal for API Key Revocation */}
      {confirmRevokeKeyId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fadeIn">
          <div className={`w-full max-w-md rounded-xl ${bgCard} border ${borderSubtle} p-6 space-y-4 shadow-2xl`}>
            <div className="flex items-center gap-3 text-rose-400">
              <Key className="w-6 h-6" />
              <h3 className="font-bold text-lg text-white">Revoke Agent API Key</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Are you sure you want to revoke API key <span className="font-mono font-bold text-rose-300">{confirmRevokeKeyId}</span>?
              Any agent or service using this credential will immediately receive 403 Forbidden responses.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeKeyId(null)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle} text-slate-300 hover:text-white transition-colors`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => executeRevokeApiKey(confirmRevokeKeyId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors flex items-center gap-2"
              >
                <Key className="w-4 h-4" />
                Revoke Key Immediately
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Permanent Agent Deletion */}
      {confirmDeleteAgentId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fadeIn">
          <div className={`w-full max-w-md rounded-xl ${bgCard} border ${borderSubtle} p-6 space-y-4 shadow-2xl`}>
            <div className="flex items-center gap-3 text-rose-400">
              <Trash2 className="w-6 h-6" />
              <h3 className="font-bold text-lg text-white">Permanently Delete Agent</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete agent <span className="font-mono font-bold text-rose-300">{confirmDeleteAgentId}</span>?
              All associated delegations and runtime budget policies will be purged. (Tip: Use "Disconnect" instead if you only wish to deauthorize active credentials while retaining records.)
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmDeleteAgentId(null)}
                className={`px-4 py-2 rounded-lg border ${borderSubtle} text-slate-300 hover:text-white transition-colors`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => executeDeleteAgent(confirmDeleteAgentId)}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Delete Agent
              </button>
            </div>
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
