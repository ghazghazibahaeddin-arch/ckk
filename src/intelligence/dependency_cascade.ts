/**
 * Feature 4: Impact & Invalidation Cascade
 *
 * Typed multi-node dependency graph connecting:
 * SOURCE -> FACT -> EVIDENCE -> ENTITY -> AGENT_TASK -> PLAN -> CONTRACT -> TOOL -> DECISION -> PROTECTED_ACTION
 *
 * Capabilities:
 * - Cycle detection & safe bounded BFS/DFS traversal
 * - Direct vs indirect downstream dependent attribution
 * - Transitive invalidation / revalidation state propagation
 * - Idempotent cascade execution + outbox partial-failure tracking
 * - Tenant isolation
 * - Protected-action upstream check for Action Gate
 */

import crypto from 'crypto';
import type {
  CascadeOutboxEntry,
  DependencyEdgeRecord,
  DependencyNodeRecord,
  DependencyNodeState,
  DependencyNodeType,
  InvalidationCascadeRecord,
} from './types.ts';

export function makeNodeId(tenantId: string, nodeType: DependencyNodeType, refId: string): string {
  const digest = crypto
    .createHash('sha256')
    .update(`${tenantId}::${nodeType}::${refId}`)
    .digest('hex')
    .slice(0, 12);
  return `dnode-${nodeType.toLowerCase()}-${digest}`;
}

export function upsertDependencyNode(params: {
  nodes: DependencyNodeRecord[];
  tenantId: string;
  nodeType: DependencyNodeType;
  refId: string;
  label?: string;
  state?: DependencyNodeState;
  metadata?: Record<string, unknown>;
}): DependencyNodeRecord {
  const { nodes, tenantId, nodeType, refId, label, state = 'VALID', metadata } = params;
  const nodeId = makeNodeId(tenantId, nodeType, refId);
  const existing = nodes.find((n) => n.node_id === nodeId && n.tenant_id === tenantId);
  if (existing) {
    if (label) existing.label = label;
    if (metadata) existing.metadata = { ...(existing.metadata || {}), ...metadata };
    return existing;
  }
  const created: DependencyNodeRecord = {
    node_id: nodeId,
    tenant_id: tenantId,
    node_type: nodeType,
    ref_id: refId,
    label: label || `${nodeType}:${refId}`,
    state,
    last_changed_at: new Date().toISOString(),
    metadata,
  };
  nodes.unshift(created);
  return created;
}

export function wouldCreateCycle(params: {
  edges: DependencyEdgeRecord[];
  tenantId: string;
  fromNodeId: string;
  toNodeId: string;
  maxDepth?: number;
}): boolean {
  const { edges, tenantId, fromNodeId, toNodeId, maxDepth = 32 } = params;
  if (fromNodeId === toNodeId) return true;

  const tenantEdges = edges.filter((e) => e.tenant_id === tenantId);
  const queue: Array<{ id: string; depth: number }> = [{ id: toNodeId, depth: 0 }];
  const visited = new Set<string>([toNodeId]);

  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur.id === fromNodeId) return true;
    if (cur.depth >= maxDepth) continue;
    for (const edge of tenantEdges) {
      if (edge.from_node_id === cur.id && !visited.has(edge.to_node_id)) {
        visited.add(edge.to_node_id);
        queue.push({ id: edge.to_node_id, depth: cur.depth + 1 });
      }
    }
  }
  return false;
}

export function addDependencyEdge(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  tenantId: string;
  fromNodeId: string;
  toNodeId: string;
  relation: DependencyEdgeRecord['relation'];
}): { ok: boolean; edge?: DependencyEdgeRecord; error?: string } {
  const { nodes, edges, tenantId, fromNodeId, toNodeId, relation } = params;

  const fromNode = nodes.find((n) => n.node_id === fromNodeId && n.tenant_id === tenantId);
  const toNode = nodes.find((n) => n.node_id === toNodeId && n.tenant_id === tenantId);
  if (!fromNode || !toNode) {
    return {
      ok: false,
      error: 'Both from_node_id and to_node_id must exist within the same tenant graph.',
    };
  }

  const dup = edges.find(
    (e) =>
      e.tenant_id === tenantId &&
      e.from_node_id === fromNodeId &&
      e.to_node_id === toNodeId &&
      e.relation === relation
  );
  if (dup) {
    return { ok: true, edge: dup };
  }

  if (wouldCreateCycle({ edges, tenantId, fromNodeId, toNodeId })) {
    return {
      ok: false,
      error: `CYCLE_DETECTED: Edge ${fromNode.ref_id} -> ${toNode.ref_id} would introduce a dependency cycle.`,
    };
  }

  const edge: DependencyEdgeRecord = {
    edge_id: `dedge-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: tenantId,
    from_node_id: fromNodeId,
    to_node_id: toNodeId,
    relation,
    created_at: new Date().toISOString(),
  };
  edges.unshift(edge);
  return { ok: true, edge };
}

export function findDownstreamDependents(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  tenantId: string;
  startNodeId: string;
  maxDepth?: number;
}): {
  direct: DependencyNodeRecord[];
  indirect: DependencyNodeRecord[];
  maxDepthReached: number;
} {
  const { nodes, edges, tenantId, startNodeId, maxDepth = 16 } = params;
  const tenantNodes = new Map(nodes.filter((n) => n.tenant_id === tenantId).map((n) => [n.node_id, n]));
  const tenantEdges = edges.filter((e) => e.tenant_id === tenantId);

  const visited = new Set<string>([startNodeId]);
  const queue: Array<{ nodeId: string; depth: number }> = [{ nodeId: startNodeId, depth: 0 }];
  const direct: DependencyNodeRecord[] = [];
  const indirect: DependencyNodeRecord[] = [];
  let maxDepthReached = 0;

  while (queue.length > 0) {
    const cur = queue.shift()!;
    maxDepthReached = Math.max(maxDepthReached, cur.depth);
    if (cur.depth >= maxDepth) continue;

    for (const edge of tenantEdges) {
      if (edge.from_node_id !== cur.nodeId) continue;
      if (visited.has(edge.to_node_id)) continue;
      visited.add(edge.to_node_id);

      const targetNode = tenantNodes.get(edge.to_node_id);
      if (!targetNode) continue;

      const nextDepth = cur.depth + 1;
      if (nextDepth === 1) {
        direct.push(targetNode);
      } else {
        indirect.push(targetNode);
      }
      queue.push({ nodeId: edge.to_node_id, depth: nextDepth });
    }
  }

  return { direct, indirect, maxDepthReached };
}

export function findUpstreamDependencies(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  tenantId: string;
  targetNodeId: string;
  maxDepth?: number;
}): DependencyNodeRecord[] {
  const { nodes, edges, tenantId, targetNodeId, maxDepth = 16 } = params;
  const tenantNodes = new Map(nodes.filter((n) => n.tenant_id === tenantId).map((n) => [n.node_id, n]));
  const tenantEdges = edges.filter((e) => e.tenant_id === tenantId);

  const visited = new Set<string>([targetNodeId]);
  const queue: Array<{ nodeId: string; depth: number }> = [{ nodeId: targetNodeId, depth: 0 }];
  const upstream: DependencyNodeRecord[] = [];

  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur.depth >= maxDepth) continue;
    for (const edge of tenantEdges) {
      if (edge.to_node_id !== cur.nodeId) continue;
      if (visited.has(edge.from_node_id)) continue;
      visited.add(edge.from_node_id);
      const src = tenantNodes.get(edge.from_node_id);
      if (src) {
        upstream.push(src);
        queue.push({ nodeId: src.node_id, depth: cur.depth + 1 });
      }
    }
  }

  return upstream;
}

export function executeInvalidationCascade(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  cascades: InvalidationCascadeRecord[];
  tenantId: string;
  triggerNodeId: string;
  targetState: 'INVALIDATED' | 'REVALIDATE_REQUIRED';
  reason: string;
  traceId: string;
  idempotencyKey?: string;
  maxDepth?: number;
  simulateOutboxFailureNodeId?: string;
}): InvalidationCascadeRecord {
  const {
    nodes,
    edges,
    cascades,
    tenantId,
    triggerNodeId,
    targetState,
    reason,
    traceId,
    idempotencyKey,
    maxDepth = 16,
    simulateOutboxFailureNodeId,
  } = params;

  const effectiveIdem =
    idempotencyKey ||
    `casc-${crypto.createHash('sha256').update(`${tenantId}:${triggerNodeId}:${targetState}:${reason}`).digest('hex').slice(0, 16)}`;

  const existing = cascades.find((c) => c.tenant_id === tenantId && c.idempotency_key === effectiveIdem);
  if (existing) {
    return existing;
  }

  const nowIso = new Date().toISOString();
  const cascadeId = `casc-${crypto.randomUUID().slice(0, 8)}`;

  const triggerNode = nodes.find((n) => n.node_id === triggerNodeId && n.tenant_id === tenantId);
  if (triggerNode) {
    triggerNode.state = targetState;
    triggerNode.last_changed_at = nowIso;
    triggerNode.invalidated_by_cascade_id = cascadeId;
  }

  const { direct, indirect, maxDepthReached } = findDownstreamDependents({
    nodes,
    edges,
    tenantId,
    startNodeId: triggerNodeId,
    maxDepth,
  });

  const allImpacted = [...direct, ...indirect];
  const outbox: CascadeOutboxEntry[] = [];
  let partialFailure = false;

  for (const depNode of allImpacted) {
    if (simulateOutboxFailureNodeId && depNode.node_id === simulateOutboxFailureNodeId) {
      partialFailure = true;
      // Fail-closed: still mark node REVALIDATE_REQUIRED locally while flagging outbox delivery retry
      depNode.state = 'REVALIDATE_REQUIRED';
      depNode.invalidated_by_cascade_id = cascadeId;
      outbox.push({
        outbox_id: `out-${crypto.randomUUID().slice(0, 8)}`,
        target_node_id: depNode.node_id,
        target_type: depNode.node_type,
        action: 'EMIT_NOTICE',
        status: 'PENDING_RETRY',
        error_message: 'Simulated downstream dispatch interruption; queued in outbox for retry.',
        attempts: 1,
      });
      continue;
    }

    depNode.state =
      depNode.node_type === 'PROTECTED_ACTION' || depNode.node_type === 'CONTRACT' || depNode.node_type === 'AGENT_TASK'
        ? targetState
        : 'REVALIDATE_REQUIRED';
    depNode.last_changed_at = nowIso;
    depNode.invalidated_by_cascade_id = cascadeId;

    outbox.push({
      outbox_id: `out-${crypto.randomUUID().slice(0, 8)}`,
      target_node_id: depNode.node_id,
      target_type: depNode.node_type,
      action: targetState === 'INVALIDATED' ? 'MARK_INVALIDATED' : 'MARK_REVALIDATE_REQUIRED',
      status: 'COMPLETED',
      attempts: 1,
    });
  }

  const affectedProtected = allImpacted
    .filter((n) => n.node_type === 'PROTECTED_ACTION')
    .map((n) => n.ref_id);

  const cascadeRecord: InvalidationCascadeRecord = {
    cascade_id: cascadeId,
    tenant_id: tenantId,
    trigger_node_id: triggerNodeId,
    trigger_reason: reason,
    trace_id: traceId,
    idempotency_key: effectiveIdem,
    max_depth_reached: maxDepthReached,
    direct_dependents: direct.map((n) => n.node_id),
    indirect_dependents: indirect.map((n) => n.node_id),
    affected_protected_actions: affectedProtected,
    outbox_entries: outbox,
    partial_failure: partialFailure,
    created_at: nowIso,
  };

  cascades.unshift(cascadeRecord);
  return cascadeRecord;
}

export function revalidateCascadeNodes(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  tenantId: string;
  rootNodeId: string;
}): number {
  const { nodes, edges, tenantId, rootNodeId } = params;
  const nowIso = new Date().toISOString();
  let updated = 0;

  const root = nodes.find((n) => n.node_id === rootNodeId && n.tenant_id === tenantId);
  if (root) {
    root.state = 'VALID';
    root.last_changed_at = nowIso;
    updated += 1;
  }

  const { direct, indirect } = findDownstreamDependents({
    nodes,
    edges,
    tenantId,
    startNodeId: rootNodeId,
  });

  for (const dep of [...direct, ...indirect]) {
    const ups = findUpstreamDependencies({ nodes, edges, tenantId, targetNodeId: dep.node_id });
    const hasStillBrokenUpstream = ups.some((u) => u.state === 'INVALIDATED' || u.state === 'REVALIDATE_REQUIRED');
    if (!hasStillBrokenUpstream) {
      dep.state = 'VALID';
      dep.last_changed_at = nowIso;
      updated += 1;
    }
  }
  return updated;
}

export function checkProtectedActionCascadeBlock(params: {
  nodes: DependencyNodeRecord[];
  edges: DependencyEdgeRecord[];
  tenantId: string;
  capability: string;
  entityId?: string;
  toolId?: string;
  contractId?: string;
}): {
  blocked: boolean;
  requiresRevalidation: boolean;
  blockingNodes: DependencyNodeRecord[];
  reason?: string;
} {
  const { nodes, edges, tenantId, capability, entityId, toolId, contractId } = params;
  const tenantNodes = nodes.filter((n) => n.tenant_id === tenantId);
  if (tenantNodes.length === 0) {
    return { blocked: false, requiresRevalidation: false, blockingNodes: [] };
  }

  // Match protected action node or directly referenced tool/entity/contract nodes
  const candidateRoots = tenantNodes.filter((n) => {
    if (n.node_type === 'PROTECTED_ACTION' && (n.ref_id === capability || n.ref_id === `action:${capability}`)) {
      return true;
    }
    if (toolId && n.node_type === 'TOOL' && (n.ref_id === toolId || n.ref_id === `tool:${toolId}`)) {
      return true;
    }
    if (contractId && n.node_type === 'CONTRACT' && n.ref_id === contractId) {
      return true;
    }
    if (entityId && n.node_type === 'ENTITY' && n.ref_id === entityId) {
      return true;
    }
    return false;
  });

  const broken = new Map<string, DependencyNodeRecord>();
  for (const root of candidateRoots) {
    if (root.state === 'INVALIDATED' || root.state === 'REVALIDATE_REQUIRED') {
      broken.set(root.node_id, root);
    }
    const upstreams = findUpstreamDependencies({
      nodes,
      edges,
      tenantId,
      targetNodeId: root.node_id,
    });
    for (const u of upstreams) {
      if (u.state === 'INVALIDATED' || u.state === 'REVALIDATE_REQUIRED') {
        broken.set(u.node_id, u);
      }
    }
  }

  if (broken.size === 0) {
    return { blocked: false, requiresRevalidation: false, blockingNodes: [] };
  }

  const blockingNodes = Array.from(broken.values());
  const hasInvalidated = blockingNodes.some((n) => n.state === 'INVALIDATED');
  const labels = blockingNodes.map((n) => `${n.node_type}:${n.ref_id}(${n.state})`).join(', ');

  return {
    blocked: hasInvalidated,
    requiresRevalidation: !hasInvalidated,
    blockingNodes,
    reason: `Dependency cascade ${hasInvalidated ? 'INVALIDATED' : 'REVALIDATE_REQUIRED'}: upstream dependencies [${labels}] affect capability "${capability}".`,
  };
}
