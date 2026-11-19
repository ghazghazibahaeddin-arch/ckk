/**
 * Feature 11: Permission Graph & Least Privilege
 *
 * Unified tenant-isolated permission graph linking:
 * Organization -> Tenant -> User -> Agent -> Tool -> Resource -> Action -> Scope -> Permission -> Policy -> Delegation
 *
 * Core Invariants:
 * - Tool descriptions & manifests (DECLARED) NEVER automatically grant EFFECTIVE permissions.
 * - Strictly distinguishes DECLARED, CONFIGURED, OBSERVED, GRANTED, and EFFECTIVE permissions.
 * - Computes effective scope by intersecting active Grants with Delegation & Mandate ceilings.
 * - Reports excess permissions for Least Privilege auditing.
 */

import crypto from 'crypto';
import type { DelegationRecord } from '../governance/types.ts';
import type {
  PermissionEvaluationResult,
  PermissionGrantRecord,
  ToolIdentityRecord,
} from './types.ts';

function wildcardMatch(pattern: string, value: string): boolean {
  if (!pattern || pattern === '*') return true;
  if (pattern.endsWith('*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}

export function createPermissionGrant(input: {
  tenant_id: string;
  org_id?: string;
  user_id?: string;
  agent_id: string;
  tool_id?: string;
  resource_pattern?: string;
  action?: string;
  scopes: string[];
  origin?: 'CONFIGURED' | 'GRANTED';
  policy_id?: string;
  delegation_id?: string;
  expires_at?: string;
  created_by?: string;
}): PermissionGrantRecord {
  const now = new Date().toISOString();
  return {
    grant_id: `pgr-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id,
    org_id: input.org_id || `org-${input.tenant_id}`,
    user_id: input.user_id,
    agent_id: input.agent_id,
    tool_id: input.tool_id || '*',
    resource_pattern: input.resource_pattern || '*',
    action: input.action || '*',
    scopes: Array.from(new Set(input.scopes.map((s) => String(s).trim()).filter(Boolean))),
    origin: input.origin || 'GRANTED',
    policy_id: input.policy_id,
    delegation_id: input.delegation_id,
    expires_at: input.expires_at,
    revoked: false,
    created_by: input.created_by || 'supervisor',
    created_at: now,
  };
}

export function evaluatePermissionGraph(params: {
  tenantId: string;
  agentId: string;
  toolId: string;
  resource: string;
  action: string;
  requestedScopes?: string[];
  grants: PermissionGrantRecord[];
  toolIdentity?: ToolIdentityRecord;
  delegation?: DelegationRecord | null;
  observedActions?: string[];
  strictNoImplicitAllow?: boolean;
  nowMs?: number;
}): PermissionEvaluationResult {
  const {
    tenantId,
    agentId,
    toolId,
    resource,
    action,
    requestedScopes = [],
    grants,
    toolIdentity,
    delegation,
    observedActions = [],
    strictNoImplicitAllow = false,
    nowMs = Date.now(),
  } = params;

  const declaredScopes = toolIdentity?.history?.[0]?.definition?.declared_permissions || [];

  const tenantAgentGrants = grants.filter(
    (g) => g.tenant_id === tenantId && (g.agent_id === agentId || g.agent_id === '*')
  );

  const activeGrants = tenantAgentGrants.filter((g) => {
    if (g.revoked) return false;
    if (g.expires_at) {
      const expMs = new Date(g.expires_at).getTime();
      if (!Number.isNaN(expMs) && expMs < nowMs) return false;
    }
    return true;
  });

  const matchingGrants = activeGrants.filter(
    (g) =>
      wildcardMatch(g.tool_id, toolId) &&
      wildcardMatch(g.resource_pattern, resource) &&
      wildcardMatch(g.action, action)
  );

  const configuredScopes = Array.from(
    new Set(matchingGrants.filter((g) => g.origin === 'CONFIGURED').flatMap((g) => g.scopes))
  );
  const grantedScopes = Array.from(new Set(matchingGrants.flatMap((g) => g.scopes)));

  // Effective scopes are constrained by delegation scope if a delegation is bound
  let effectiveScopes = [...grantedScopes];
  if (delegation) {
    if (delegation.revoked || new Date(delegation.valid_until).getTime() < nowMs) {
      effectiveScopes = [];
    } else if (delegation.scope?.allowed_tools && delegation.scope.allowed_tools.length > 0) {
      const toolPermittedByDelegation = delegation.scope.allowed_tools.some(
        (t: string) => t === '*' || t === toolId || t === action
      );
      if (!toolPermittedByDelegation) {
        effectiveScopes = [];
      }
    }
  }

  // Required scopes: if caller specifies requestedScopes, check least-privilege against ONLY requestedScopes;
  // otherwise check declaredScopes so claimed manifest scopes still require explicit grants (NEVER auto-granted!).
  const requiredScopes =
    requestedScopes.length > 0
      ? Array.from(new Set(requestedScopes.map((s) => s.trim()).filter(Boolean)))
      : Array.from(new Set(declaredScopes.map((s) => s.trim()).filter(Boolean)));

  const hasScopeCoverage = (scope: string) =>
    effectiveScopes.includes('*') ||
    effectiveScopes.includes(scope) ||
    effectiveScopes.some((eff) => wildcardMatch(eff, scope));

  const missingScopes = requiredScopes.filter((s) => !hasScopeCoverage(s));

  // Detect excess permissions across active grants for Least Privilege reporting
  const excessPermissions: PermissionEvaluationResult['excess_permissions'] = [];
  for (const g of activeGrants) {
    const isWildcard = g.tool_id === '*' && g.resource_pattern === '*' && g.action === '*';
    const unusedForTarget = !wildcardMatch(g.tool_id, toolId) || !wildcardMatch(g.resource_pattern, resource);
    const excessScopes = g.scopes.filter(
      (s) => s === '*' || (requiredScopes.length > 0 && !requiredScopes.includes(s))
    );

    if (isWildcard || g.scopes.includes('*')) {
      excessPermissions.push({
        grant_id: g.grant_id,
        tool_id: g.tool_id,
        resource_pattern: g.resource_pattern,
        action: g.action,
        scopes: g.scopes,
        reason: 'Over-broad wildcard privilege violates Principle of Least Privilege.',
      });
    } else if (!unusedForTarget && excessScopes.length > 0) {
      excessPermissions.push({
        grant_id: g.grant_id,
        tool_id: g.tool_id,
        resource_pattern: g.resource_pattern,
        action: g.action,
        scopes: excessScopes,
        reason: `Scopes [${excessScopes.join(', ')}] exceed current tool requirement [${requiredScopes.join(', ')}].`,
      });
    }
  }

  // Determine enforcement:
  // Always enforce if:
  // 1) strictNoImplicitAllow (e.g. MCP Gateway or explicit /permissions/evaluate)
  // 2) Agent has PermissionGrants configured (fail-closed outside explicit grants)
  // 3) Tool has declared_permissions (tool claim MUST have matching active grant!)
  const shouldEnforce =
    strictNoImplicitAllow || tenantAgentGrants.length > 0 || declaredScopes.length > 0;

  let allowed = true;
  let reason = `Effective permissions verified for agent "${agentId}" on tool "${toolId}".`;

  if (shouldEnforce) {
    if (matchingGrants.length === 0) {
      allowed = false;
      reason = `Permission DENIED: Agent "${agentId}" holds NO active grant for tool="${toolId}", resource="${resource}", action="${action}". Tool declared permissions [${declaredScopes.join(', ') || 'none'}] are never auto-granted.`;
    } else if (missingScopes.length > 0) {
      allowed = false;
      reason = `Permission DENIED: Missing granted scopes [${missingScopes.join(', ')}] for agent "${agentId}" on "${toolId}". Granted scopes: [${effectiveScopes.join(', ') || 'none'}].`;
    } else if (requiredScopes.length === 0 && effectiveScopes.length === 0) {
      allowed = false;
      reason = `Permission DENIED: Effective scope set is empty (expired/revoked grant or delegation ceiling).`;
    }
  }

  return {
    allowed,
    decision: allowed ? 'ALLOW' : 'BLOCK',
    tenant_id: tenantId,
    agent_id: agentId,
    tool_id: toolId,
    resource,
    action,
    requested_scopes: requiredScopes,
    declared_scopes: declaredScopes,
    configured_scopes: configuredScopes,
    observed_scopes: Array.from(new Set(observedActions)),
    granted_scopes: grantedScopes,
    effective_scopes: effectiveScopes,
    missing_scopes: missingScopes,
    excess_permissions: excessPermissions,
    matched_grant_ids: matchingGrants.map((g) => g.grant_id),
    reason,
    evaluated_at: new Date().toISOString(),
  };
}

export function buildPermissionGraphSnapshot(params: {
  tenantId: string;
  agents: Array<{ agent_id: string; name: string }>;
  grants: PermissionGrantRecord[];
  tools: ToolIdentityRecord[];
  delegations: DelegationRecord[];
}): {
  nodes: Array<{ id: string; type: string; label: string; meta?: Record<string, unknown> }>;
  edges: Array<{ from: string; to: string; relation: string; origin?: string }>;
  summary: {
    active_grants: number;
    revoked_grants: number;
    declared_tool_scopes: number;
    wildcard_excess_grants: number;
    active_delegations: number;
  };
} {
  const { tenantId, agents, grants, tools, delegations } = params;
  const nodes: Array<{ id: string; type: string; label: string; meta?: Record<string, unknown> }> = [];
  const edges: Array<{ from: string; to: string; relation: string; origin?: string }> = [];
  const seenNodes = new Set<string>();

  const addNode = (id: string, type: string, label: string, meta?: Record<string, unknown>) => {
    if (seenNodes.has(id)) return;
    seenNodes.add(id);
    nodes.push({ id, type, label, meta });
  };

  const tenantNodeId = `TENANT:${tenantId}`;
  addNode(tenantNodeId, 'TENANT', tenantId);

  for (const agt of agents) {
    const aId = `AGENT:${agt.agent_id}`;
    addNode(aId, 'AGENT', agt.name || agt.agent_id);
    edges.push({ from: tenantNodeId, to: aId, relation: 'OWNS_AGENT' });
  }

  const tenantGrants = grants.filter((g) => g.tenant_id === tenantId);
  for (const g of tenantGrants) {
    const orgId = `ORG:${g.org_id}`;
    addNode(orgId, 'ORGANIZATION', g.org_id);
    edges.push({ from: orgId, to: tenantNodeId, relation: 'CONTAINS_TENANT' });

    if (g.user_id) {
      const uId = `USER:${g.user_id}`;
      addNode(uId, 'USER', g.user_id);
      edges.push({ from: tenantNodeId, to: uId, relation: 'AUTHORIZES_USER' });
    }

    const agtNode = `AGENT:${g.agent_id}`;
    addNode(agtNode, 'AGENT', g.agent_id);
    const toolNode = `TOOL:${g.tool_id}`;
    addNode(toolNode, 'TOOL', g.tool_id);
    const resNode = `RESOURCE:${g.resource_pattern}`;
    addNode(resNode, 'RESOURCE', g.resource_pattern);
    const actNode = `ACTION:${g.action}`;
    addNode(actNode, 'ACTION', g.action);

    edges.push({ from: agtNode, to: toolNode, relation: g.revoked ? 'REVOKED_GRANT' : 'GRANTED_TOOL', origin: g.origin });
    edges.push({ from: toolNode, to: resNode, relation: 'TARGETS_RESOURCE', origin: g.origin });
    edges.push({ from: resNode, to: actNode, relation: 'PERMITS_ACTION', origin: g.origin });

    for (const sc of g.scopes) {
      const scNode = `SCOPE:${sc}`;
      addNode(scNode, 'SCOPE', sc);
      edges.push({ from: actNode, to: scNode, relation: 'GRANTS_SCOPE', origin: g.origin });
    }
  }

  const tenantTools = tools.filter((t) => t.tenant_id === tenantId);
  let declaredCount = 0;
  for (const t of tenantTools) {
    const toolNode = `TOOL:${t.tool_id}`;
    addNode(toolNode, 'TOOL', t.name, { fingerprint: t.current_fingerprint, drift_status: t.drift_status });
    const declared = t.history[0]?.definition.declared_permissions || [];
    declaredCount += declared.length;
    for (const perm of declared) {
      const declNode = `DECLARED_PERM:${perm}`;
      addNode(declNode, 'DECLARED_PERMISSION', perm);
      edges.push({ from: toolNode, to: declNode, relation: 'DECLARES_PERMISSION', origin: 'DECLARED' });
    }
  }

  const tenantDelegations = delegations.filter((d) => d.tenant_id === tenantId);
  for (const del of tenantDelegations) {
    const delNode = `DELEGATION:${del.delegation_id}`;
    addNode(delNode, 'DELEGATION', `${del.delegator_agent_id} -> ${del.delegatee_agent_id}`, { revoked: del.revoked });
    edges.push({ from: `AGENT:${del.delegator_agent_id}`, to: delNode, relation: 'DELEGATES_FROM' });
    edges.push({ from: delNode, to: `AGENT:${del.delegatee_agent_id}`, relation: 'DELEGATES_TO' });
  }

  return {
    nodes,
    edges,
    summary: {
      active_grants: tenantGrants.filter((g) => !g.revoked).length,
      revoked_grants: tenantGrants.filter((g) => g.revoked).length,
      declared_tool_scopes: declaredCount,
      wildcard_excess_grants: tenantGrants.filter(
        (g) => !g.revoked && (g.tool_id === '*' || g.scopes.includes('*'))
      ).length,
      active_delegations: tenantDelegations.filter((d) => !d.revoked).length,
    },
  };
}
