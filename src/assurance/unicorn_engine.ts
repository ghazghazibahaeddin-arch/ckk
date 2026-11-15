import * as crypto from 'crypto';

// -------------------------------------------------------------
// CCK Unicorn Capabilities: Types & Interfaces
// -------------------------------------------------------------

export interface KillSwitchRecord {
  switch_id: string;
  tenant_id: string;
  scope_type: 'GLOBAL_TENANT' | 'AGENT' | 'CAPABILITY';
  scope_value: string; // tenant_id, agent_id, or capability prefix like "payments.*"
  reason: string;
  triggered_by: string;
  auto_triggered: boolean;
  status: 'ACTIVE' | 'RESUMED';
  triggered_at: string;
  resumed_at?: string;
  blocked_hits_count: number;
}

export interface CircuitBreakerRule {
  breaker_id: string;
  tenant_id: string;
  name: string;
  target_scope: 'AGENT' | 'TENANT';
  target_id: string; // '*' or specific agent_id
  max_consecutive_blocks: number;
  window_seconds: number;
  recent_block_timestamps: string[];
  status: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  enabled: boolean;
  trip_count: number;
  last_tripped_at?: string;
  linked_switch_id?: string;
  created_at: string;
}

export interface AlertWebhookSubscription {
  webhook_id: string;
  tenant_id: string;
  name: string;
  target_url: string;
  events: string[];
  signing_secret_prefix: string;
  signing_secret_hash: string;
  is_active: boolean;
  created_at: string;
  last_delivery_at?: string;
}

export interface WebhookDeliveryRecord {
  delivery_id: string;
  webhook_id: string;
  tenant_id: string;
  event_type: string;
  signature_header: string;
  payload_preview: Record<string, unknown>;
  status: 'SIGNED_LOGGED' | 'DELIVERED' | 'BLOCKED_SSRF' | 'FAILED';
  http_status?: number;
  delivered_at: string;
}

export interface SimulationOverrideConfig {
  max_amount_usd?: number;
  blocked_capabilities?: string[];
  blocked_targets?: string[];
  simulated_drifted_entities?: string[];
  enforce_strict_prompt_guard?: boolean;
  enforce_ssrf_guard?: boolean;
}

export interface SimulationActionDiff {
  item_id: string;
  source: 'HISTORICAL_RECEIPT' | 'CANDIDATE_ACTION';
  agent_id: string;
  capability: string;
  target: string;
  entity_id: string;
  amount_usd: number;
  baseline_decision: string;
  simulated_decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  changed: boolean;
  flip_direction: 'ALLOW_TO_BLOCK' | 'BLOCK_TO_ALLOW' | 'UNCHANGED';
  triggered_rule: string;
  reason: string;
}

export interface SimulationRunRecord {
  sim_id: string;
  tenant_id: string;
  name: string;
  created_at: string;
  overrides: SimulationOverrideConfig;
  summary: {
    total_evaluated: number;
    baseline_allows: number;
    baseline_blocks: number;
    simulated_allows: number;
    simulated_blocks: number;
    flipped_to_block: number;
    flipped_to_allow: number;
    blast_radius_usd_saved: number;
  };
  diffs: SimulationActionDiff[];
}

export interface ReceiptProofVerification {
  verified: boolean;
  receipt_id: string;
  signature_valid: boolean;
  chain_linked: boolean;
  tampered: boolean;
  tampered_fields: string[];
  computed_digest: string;
  stored_digest: string;
  hmac_signature: string;
  verified_at: string;
}

export interface AgentTrustPassport {
  agent_id: string;
  agent_name: string;
  framework: string;
  tenant_id: string;
  grade: 'AAA' | 'AA' | 'A' | 'B' | 'PROBATION';
  trust_score: number;
  total_evaluations: number;
  allowed_count: number;
  blocked_count: number;
  prevention_rate_pct: number;
  estimated_usd_protected: number;
  active_kill_switches: number;
  open_incidents: number;
  chain_verified: boolean;
  issued_at: string;
  passport_hash: string;
  badge_svg: string;
}

export interface CiGateCheckItem {
  check_id: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  details: string;
}

export interface CiGateCheckReport {
  report_id: string;
  tenant_id: string;
  agent_id: string;
  agent_name: string;
  status: 'PASS' | 'FAIL';
  checks: CiGateCheckItem[];
  blocked_reasons: string[];
  evaluated_at: string;
  github_actions_yaml: string;
}

export interface ProgrammablePolicyInput {
  rule_id: string;
  tenant_id?: string;
  name: string;
  description: string;
  capability_pattern: string;
  target_pattern: string;
  action_effect: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  rollout_mode?: 'ENFORCE' | 'SHADOW';
  max_amount_usd?: number;
  blocked_keywords?: string[];
  risk_level: string;
  is_active: boolean;
  is_custom?: boolean;
}

// -------------------------------------------------------------
// 1. Cryptographic Receipt Signing & Zero-Trust Verification
// -------------------------------------------------------------

export function computeCanonicalReceiptDigest(receipt: {
  receipt_id: string;
  action_id: string;
  status: string;
  agent_id: string;
  entity_id: string;
  action: { capability: string; target: string; command: string };
  audit_ref?: { audit_id?: string; action_hash?: string; previous_hash?: string };
}): string {
  const canonical = JSON.stringify({
    receipt_id: receipt.receipt_id,
    action_id: receipt.action_id,
    status: receipt.status,
    agent_id: receipt.agent_id,
    entity_id: receipt.entity_id,
    capability: receipt.action?.capability || '',
    target: receipt.action?.target || '',
    command: receipt.action?.command || '',
    action_hash: receipt.audit_ref?.action_hash || '',
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

export function signReceiptProof(
  receipt: {
    receipt_id: string;
    action_id: string;
    status: string;
    agent_id: string;
    entity_id: string;
    action: { capability: string; target: string; command: string };
    audit_ref?: { audit_id?: string; action_hash?: string; previous_hash?: string };
  },
  hmacSecret: string
): { payload_digest: string; hmac_signature: string } {
  const payload_digest = computeCanonicalReceiptDigest(receipt);
  const hmac_signature =
    'cck_sig_v1_' +
    crypto.createHmac('sha256', hmacSecret).update(payload_digest).digest('hex');
  return { payload_digest, hmac_signature };
}

export function verifyReceiptProof(params: {
  storedReceipt: {
    receipt_id: string;
    action_id: string;
    status: string;
    agent_id: string;
    entity_id: string;
    action: { capability: string; target: string; command: string };
    audit_ref?: { audit_id?: string; action_hash?: string; previous_hash?: string };
    proof?: { payload_digest: string; hmac_signature: string };
  };
  auditLedger: Array<{ audit_id: string; action_hash: string; previous_hash: string }>;
  hmacSecret: string;
  candidateTamper?: {
    status?: string;
    target?: string;
    command?: string;
    capability?: string;
    agent_id?: string;
  };
}): ReceiptProofVerification {
  const { storedReceipt, auditLedger, hmacSecret, candidateTamper } = params;
  const storedProof = storedReceipt.proof || signReceiptProof(storedReceipt, hmacSecret);

  const inspectedReceipt = {
    ...storedReceipt,
    status: candidateTamper?.status ?? storedReceipt.status,
    agent_id: candidateTamper?.agent_id ?? storedReceipt.agent_id,
    action: {
      capability: candidateTamper?.capability ?? storedReceipt.action.capability,
      target: candidateTamper?.target ?? storedReceipt.action.target,
      command: candidateTamper?.command ?? storedReceipt.action.command,
    },
  };

  const computedDigest = computeCanonicalReceiptDigest(inspectedReceipt);
  const expectedSig =
    'cck_sig_v1_' +
    crypto.createHmac('sha256', hmacSecret).update(computedDigest).digest('hex');

  const sigMatches =
    expectedSig.length === storedProof.hmac_signature.length &&
    crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(storedProof.hmac_signature));

  const tamperedFields: string[] = [];
  if (candidateTamper?.status && candidateTamper.status !== storedReceipt.status) tamperedFields.push('status');
  if (candidateTamper?.target && candidateTamper.target !== storedReceipt.action.target) tamperedFields.push('action.target');
  if (candidateTamper?.command && candidateTamper.command !== storedReceipt.action.command) tamperedFields.push('action.command');
  if (candidateTamper?.capability && candidateTamper.capability !== storedReceipt.action.capability) tamperedFields.push('action.capability');
  if (candidateTamper?.agent_id && candidateTamper.agent_id !== storedReceipt.agent_id) tamperedFields.push('agent_id');
  if (!sigMatches && tamperedFields.length === 0) tamperedFields.push('canonical_digest');

  const matchingAudit = auditLedger.find(
    (a) =>
      a.audit_id === storedReceipt.audit_ref?.audit_id &&
      a.action_hash === storedReceipt.audit_ref?.action_hash
  );
  const chainLinked = Boolean(matchingAudit);

  return {
    verified: sigMatches && chainLinked,
    receipt_id: storedReceipt.receipt_id,
    signature_valid: sigMatches,
    chain_linked: chainLinked,
    tampered: !sigMatches,
    tampered_fields: tamperedFields,
    computed_digest: computedDigest,
    stored_digest: storedProof.payload_digest,
    hmac_signature: storedProof.hmac_signature,
    verified_at: new Date().toISOString(),
  };
}

// -------------------------------------------------------------
// 2. Kill Switch Matching & Wildcard Utilities
// -------------------------------------------------------------

export function matchPatternWildcard(pattern: string, value: string): boolean {
  const p = (pattern || '*').trim().toLowerCase();
  const v = (value || '').trim().toLowerCase();
  if (p === '*' || p === '') return true;
  if (p.endsWith('.*')) {
    const prefix = p.slice(0, -1); // keeps trailing dot
    return v.startsWith(prefix) || v === p.slice(0, -2);
  }
  if (p.endsWith('*')) {
    return v.startsWith(p.slice(0, -1));
  }
  return v === p || v.includes(p);
}

export function matchActiveKillSwitch(params: {
  switches: KillSwitchRecord[];
  tenantId: string;
  agentId: string;
  capability: string;
}): KillSwitchRecord | null {
  const { switches, tenantId, agentId, capability } = params;
  const active = switches.filter(
    (s) => s.status === 'ACTIVE' && (s.tenant_id === tenantId || s.tenant_id === '*')
  );
  if (active.length === 0) return null;

  const globalSwitch = active.find((s) => s.scope_type === 'GLOBAL_TENANT');
  if (globalSwitch) return globalSwitch;

  const agentSwitch = active.find(
    (s) => s.scope_type === 'AGENT' && (s.scope_value === agentId || s.scope_value === '*')
  );
  if (agentSwitch) return agentSwitch;

  const capSwitch = active.find(
    (s) => s.scope_type === 'CAPABILITY' && matchPatternWildcard(s.scope_value, capability)
  );
  if (capSwitch) return capSwitch;

  return null;
}

// -------------------------------------------------------------
// 3. Programmable Custom Policy Rule Evaluation
// -------------------------------------------------------------

export function evaluateCustomPolicyRules(params: {
  rules: ProgrammablePolicyInput[];
  tenantId: string;
  capability: string;
  target: string;
  command: string;
  amountUsd: number;
}): {
  matchedRule: ProgrammablePolicyInput | null;
  effect: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  isShadow: boolean;
  reason: string;
} {
  const { rules, tenantId, capability, target, command, amountUsd } = params;
  const cmdLower = (command || '').toLowerCase();

  const customRules = rules.filter(
    (r) => r.is_active && r.is_custom && (!r.tenant_id || r.tenant_id === tenantId || r.tenant_id === '*')
  );

  for (const rule of customRules) {
    const capMatches = matchPatternWildcard(rule.capability_pattern, capability);
    const targetMatches = matchPatternWildcard(rule.target_pattern, target);
    if (!capMatches || !targetMatches) continue;

    // Check optional amount threshold condition
    if (typeof rule.max_amount_usd === 'number' && rule.max_amount_usd > 0) {
      if (amountUsd <= rule.max_amount_usd) {
        continue; // Condition not violated
      }
    }

    // Check optional blocked keywords condition
    if (Array.isArray(rule.blocked_keywords) && rule.blocked_keywords.length > 0) {
      const hit = rule.blocked_keywords.some((kw) =>
        kw.trim() ? cmdLower.includes(kw.trim().toLowerCase()) : false
      );
      if (!hit) continue;
    }

    if (rule.action_effect === 'ALLOW') continue;

    const isShadow = rule.rollout_mode === 'SHADOW';
    const conditionNote =
      typeof rule.max_amount_usd === 'number' && rule.max_amount_usd > 0
        ? `Amount $${amountUsd} exceeded rule ceiling $${rule.max_amount_usd}.`
        : rule.description || `Matched custom firewall policy "${rule.name}".`;

    return {
      matchedRule: rule,
      effect: rule.action_effect,
      isShadow,
      reason: isShadow
        ? `Shadow Policy Flag [${rule.rule_id}]: ${conditionNote}`
        : `Action ${rule.action_effect === 'BLOCK' ? 'BLOCKED' : 'HELD'} by Policy Firewall [${rule.rule_id} - ${rule.name}]: ${conditionNote}`,
    };
  }

  return { matchedRule: null, effect: 'ALLOW', isShadow: false, reason: '' };
}

// -------------------------------------------------------------
// 4. Counterfactual Dry-Run & Blast-Radius Simulator (Time Machine)
// -------------------------------------------------------------

export function extractActionAmountUsd(item: {
  command?: string;
  amount_usd?: number;
  parameters?: Record<string, unknown>;
}): number {
  if (typeof item.amount_usd === 'number' && !isNaN(item.amount_usd)) return item.amount_usd;
  const p = item.parameters || {};
  const fromParam = Number(p.amount_usd ?? p.estimated_cost_usd ?? p.amount ?? p.cost ?? p.price ?? 0);
  if (!isNaN(fromParam) && fromParam > 0) return fromParam;
  const match = (item.command || '').match(/\$?\s*(\d+(?:\.\d+)?)\s*(?:usd|dollars)?/i);
  if (match && match[1]) {
    const parsed = parseFloat(match[1]);
    if (!isNaN(parsed)) return parsed;
  }
  return 0;
}

export function evaluateCounterfactualSimulation(params: {
  tenantId: string;
  name: string;
  overrides: SimulationOverrideConfig;
  historicalReceipts: Array<{
    receipt_id: string;
    agent_id: string;
    entity_id: string;
    status: string;
    action: { capability: string; target: string; command: string };
  }>;
  candidateActions?: Array<{
    action_id?: string;
    agent_id?: string;
    capability: string;
    target: string;
    entity_id?: string;
    command?: string;
    amount_usd?: number;
    baseline_decision?: string;
  }>;
}): SimulationRunRecord {
  const { tenantId, name, overrides, historicalReceipts, candidateActions = [] } = params;

  const items: Array<{
    item_id: string;
    source: 'HISTORICAL_RECEIPT' | 'CANDIDATE_ACTION';
    agent_id: string;
    capability: string;
    target: string;
    entity_id: string;
    command: string;
    amount_usd: number;
    baseline_decision: string;
  }> = [
    ...historicalReceipts.slice(0, 50).map((r) => ({
      item_id: r.receipt_id,
      source: 'HISTORICAL_RECEIPT' as const,
      agent_id: r.agent_id,
      capability: r.action.capability,
      target: r.action.target,
      entity_id: r.entity_id,
      command: r.action.command || '',
      amount_usd: extractActionAmountUsd({ command: r.action.command }),
      baseline_decision: r.status,
    })),
    ...candidateActions.map((c, idx) => ({
      item_id: c.action_id || `cand-${idx + 1}`,
      source: 'CANDIDATE_ACTION' as const,
      agent_id: c.agent_id || 'agt-sim',
      capability: c.capability,
      target: c.target,
      entity_id: c.entity_id || 'order:1099',
      command: c.command || '',
      amount_usd: extractActionAmountUsd(c),
      baseline_decision: c.baseline_decision || 'ALLOW',
    })),
  ];

  const diffs: SimulationActionDiff[] = [];
  let baselineAllows = 0;
  let baselineBlocks = 0;
  let simulatedAllows = 0;
  let simulatedBlocks = 0;
  let flippedToBlock = 0;
  let flippedToAllow = 0;
  let blastRadiusUsdSaved = 0;

  for (const item of items) {
    if (item.baseline_decision === 'ALLOW') baselineAllows++;
    else baselineBlocks++;

    let simDecision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' =
      item.baseline_decision === 'BLOCK' ? 'BLOCK' : item.baseline_decision === 'REQUIRE_APPROVAL' ? 'REQUIRE_APPROVAL' : 'ALLOW';
    let triggeredRule = 'NONE';
    let reason = 'Matches baseline policy trajectory.';

    const cmdLower = item.command.toLowerCase();
    const targetLower = item.target.toLowerCase();

    // 1. Strict Prompt Guard override
    if (
      overrides.enforce_strict_prompt_guard &&
      ['ignore previous', 'dan mode', 'system prompt', 'jailbreak', 'rm -rf', 'exfiltrate'].some((p) =>
        cmdLower.includes(p)
      )
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_STRICT_PROMPT_GUARD';
      reason = 'Counterfactual Strict Prompt Guard intercepted suspicious instruction pattern.';
    }
    // 2. Strict SSRF Guard override
    else if (
      overrides.enforce_ssrf_guard &&
      ['169.254.169.254', '127.0.0.1', 'localhost', 'metadata.google.internal'].some(
        (h) => targetLower.includes(h) || cmdLower.includes(h)
      )
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_SSRF_EGRESS_FIREWALL';
      reason = 'Counterfactual SSRF Firewall blocked private metadata/loopback egress.';
    }
    // 3. Simulated Fact Drift entities
    else if (
      Array.isArray(overrides.simulated_drifted_entities) &&
      overrides.simulated_drifted_entities.some(
        (ent) => ent && (item.entity_id === ent || item.target.includes(ent) || item.command.includes(ent))
      )
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_CASCADE_FACT_DRIFT';
      reason = `Simulated upstream drift on entity "${item.entity_id}" invalidated execution preconditions.`;
    }
    // 4. Simulated Blocked Capabilities
    else if (
      Array.isArray(overrides.blocked_capabilities) &&
      overrides.blocked_capabilities.some((cap) => cap && matchPatternWildcard(cap, item.capability))
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_CAPABILITY_FREEZE';
      reason = `Capability "${item.capability}" matched counterfactual blocklist.`;
    }
    // 5. Simulated Blocked Targets
    else if (
      Array.isArray(overrides.blocked_targets) &&
      overrides.blocked_targets.some((tgt) => tgt && matchPatternWildcard(tgt, item.target))
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_TARGET_EGRESS_DENY';
      reason = `Target "${item.target}" matched counterfactual destination deny rule.`;
    }
    // 6. Simulated Single-Action Spending Cap
    else if (
      typeof overrides.max_amount_usd === 'number' &&
      overrides.max_amount_usd > 0 &&
      item.amount_usd > overrides.max_amount_usd
    ) {
      simDecision = 'BLOCK';
      triggeredRule = 'SIM_SPENDING_CAP_CEILING';
      reason = `Action exposure $${item.amount_usd} exceeds simulated ceiling $${overrides.max_amount_usd}.`;
    }

    if (simDecision === 'ALLOW') simulatedAllows++;
    else simulatedBlocks++;

    let flipDirection: 'ALLOW_TO_BLOCK' | 'BLOCK_TO_ALLOW' | 'UNCHANGED' = 'UNCHANGED';
    if (item.baseline_decision === 'ALLOW' && simDecision !== 'ALLOW') {
      flipDirection = 'ALLOW_TO_BLOCK';
      flippedToBlock++;
      blastRadiusUsdSaved += item.amount_usd > 0 ? item.amount_usd : 50;
    } else if (item.baseline_decision !== 'ALLOW' && simDecision === 'ALLOW') {
      flipDirection = 'BLOCK_TO_ALLOW';
      flippedToAllow++;
    }

    diffs.push({
      item_id: item.item_id,
      source: item.source,
      agent_id: item.agent_id,
      capability: item.capability,
      target: item.target,
      entity_id: item.entity_id,
      amount_usd: item.amount_usd,
      baseline_decision: item.baseline_decision,
      simulated_decision: simDecision,
      changed: flipDirection !== 'UNCHANGED',
      flip_direction: flipDirection,
      triggered_rule: triggeredRule,
      reason,
    });
  }

  return {
    sim_id: `sim-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: tenantId,
    name: name || 'Pre-Flight Policy Dry-Run',
    created_at: new Date().toISOString(),
    overrides,
    summary: {
      total_evaluated: items.length,
      baseline_allows: baselineAllows,
      baseline_blocks: baselineBlocks,
      simulated_allows: simulatedAllows,
      simulated_blocks: simulatedBlocks,
      flipped_to_block: flippedToBlock,
      flipped_to_allow: flippedToAllow,
      blast_radius_usd_saved: Math.round(blastRadiusUsdSaved * 100) / 100,
    },
    diffs,
  };
}

// -------------------------------------------------------------
// 5. Agent Trust Passport & SVG Badge Generator
// -------------------------------------------------------------

export function computeAgentTrustPassport(params: {
  agent: {
    agent_id: string;
    name: string;
    framework: string;
    tenant_id: string;
    status: string;
    total_evaluations: number;
    blocked_evaluations: number;
  };
  agentReceipts: Array<{
    status: string;
    action: { command: string };
  }>;
  activeKillSwitchesCount: number;
  openIncidentsCount: number;
  chainVerified: boolean;
}): AgentTrustPassport {
  const { agent, agentReceipts, activeKillSwitchesCount, openIncidentsCount, chainVerified } = params;
  const total = Math.max(agent.total_evaluations || 0, agentReceipts.length);
  const blocked = Math.max(
    agent.blocked_evaluations || 0,
    agentReceipts.filter((r) => r.status === 'BLOCK').length
  );
  const allowed = Math.max(0, total - blocked);

  const estimatedUsdProtected = agentReceipts
    .filter((r) => r.status === 'BLOCK')
    .reduce((acc, r) => {
      const amt = extractActionAmountUsd({ command: r.action?.command });
      return acc + (amt > 0 ? amt : 125);
    }, blocked > 0 ? 0 : 0) || blocked * 125;

  let score = 96;
  if (activeKillSwitchesCount > 0) score -= 28;
  if (openIncidentsCount > 0) score -= Math.min(25, openIncidentsCount * 10);
  if (!chainVerified) score -= 20;
  if (agent.status !== 'CONNECTED') score -= 4;
  if (total > 0 && blocked / total > 0.5 && blocked > 3) score -= 8;
  score = Math.max(15, Math.min(100, Math.round(score)));

  let grade: AgentTrustPassport['grade'] = 'AAA';
  if (activeKillSwitchesCount > 0 || score < 55) grade = 'PROBATION';
  else if (score >= 92) grade = 'AAA';
  else if (score >= 82) grade = 'AA';
  else if (score >= 70) grade = 'A';
  else grade = 'B';

  const issuedAt = new Date().toISOString();
  const passportHash = crypto
    .createHash('sha256')
    .update(`${agent.agent_id}:${agent.tenant_id}:${grade}:${score}:${total}:${blocked}`)
    .digest('hex')
    .slice(0, 24);

  const badgeColor =
    grade === 'AAA' || grade === 'AA' ? '#10b981' : grade === 'A' ? '#06b6d4' : grade === 'B' ? '#f59e0b' : '#ef4444';

  const safeName = agent.name.replace(/[<>&"']/g, '').slice(0, 22);
  const badgeSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="32" role="img" aria-label="CCK Verified: ${grade}"><rect width="165" height="32" rx="6" fill="#0f172a"/><rect x="160" width="80" height="32" rx="6" fill="${badgeColor}"/><text x="12" y="20" fill="#f8fafc" font-family="monospace" font-size="11" font-weight="700">CCK: ${safeName}</text><text x="200" y="20" text-anchor="middle" fill="#020617" font-family="monospace" font-size="11" font-weight="800">${grade} (${score})</text></svg>`;

  return {
    agent_id: agent.agent_id,
    agent_name: agent.name,
    framework: agent.framework,
    tenant_id: agent.tenant_id,
    grade,
    trust_score: score,
    total_evaluations: total,
    allowed_count: allowed,
    blocked_count: blocked,
    prevention_rate_pct: total > 0 ? Math.round((blocked / total) * 100) : 0,
    estimated_usd_protected: Math.round(estimatedUsdProtected * 100) / 100,
    active_kill_switches: activeKillSwitchesCount,
    open_incidents: openIncidentsCount,
    chain_verified: chainVerified,
    issued_at: issuedAt,
    passport_hash: passportHash,
    badge_svg: badgeSvg,
  };
}

// -------------------------------------------------------------
// 6. Zero-Dependency CI/CD Release Readiness Gate
// -------------------------------------------------------------

export function evaluateCiReleaseGate(params: {
  tenantId: string;
  agent: {
    agent_id: string;
    name: string;
    status: string;
    guardrail_mode: string;
  };
  activeSwitches: KillSwitchRecord[];
  openIncidents: Array<{ incident_id: string; severity: string; title: string }>;
  unverifiedSkillsCount: number;
  baseOrigin: string;
}): CiGateCheckReport {
  const { tenantId, agent, activeSwitches, openIncidents, unverifiedSkillsCount, baseOrigin } = params;
  const checks: CiGateCheckItem[] = [];
  const blockedReasons: string[] = [];

  // Check 1: Active Kill Switch Freeze
  if (activeSwitches.length > 0) {
    const msg = `${activeSwitches.length} active Kill Switch(es) freezing execution.`;
    checks.push({ check_id: 'CI-KILL-SWITCH', title: 'Kill Switch Clearance', status: 'FAIL', details: msg });
    blockedReasons.push(msg);
  } else {
    checks.push({ check_id: 'CI-KILL-SWITCH', title: 'Kill Switch Clearance', status: 'PASS', details: 'No active freeze switches.' });
  }

  // Check 2: Unresolved High/Critical Incidents
  const criticalIncidents = openIncidents.filter((i) => i.severity === 'HIGH' || i.severity === 'CRITICAL');
  if (criticalIncidents.length > 0) {
    const msg = `${criticalIncidents.length} unresolved HIGH/CRITICAL incident(s) require Replay Pack verification.`;
    checks.push({ check_id: 'CI-INCIDENTS', title: 'Incident & Replay Gate', status: 'FAIL', details: msg });
    blockedReasons.push(msg);
  } else {
    checks.push({ check_id: 'CI-INCIDENTS', title: 'Incident & Replay Gate', status: 'PASS', details: 'Zero open critical incidents.' });
  }

  // Check 3: Guardrail Enforcement Mode
  if (agent.guardrail_mode === 'OBSERVE_ONLY') {
    checks.push({
      check_id: 'CI-GUARDRAIL-MODE',
      title: 'Production Enforcement Mode',
      status: 'WARN',
      details: 'Agent is in OBSERVE_ONLY mode; consider switching to ENFORCE_AND_BLOCK before production deploy.',
    });
  } else {
    checks.push({
      check_id: 'CI-GUARDRAIL-MODE',
      title: 'Production Enforcement Mode',
      status: 'PASS',
      details: `Enforcing ${agent.guardrail_mode} policy gate.`,
    });
  }

  // Check 4: Skill Integrity Registry
  if (unverifiedSkillsCount > 0) {
    checks.push({
      check_id: 'CI-SKILL-TRUST',
      title: 'Skill Attestation Verification',
      status: 'WARN',
      details: `${unverifiedSkillsCount} registered skill(s) pending cryptographic attestation.`,
    });
  } else {
    checks.push({
      check_id: 'CI-SKILL-TRUST',
      title: 'Skill Attestation Verification',
      status: 'PASS',
      details: 'All active skills verified.',
    });
  }

  const cleanOrigin = baseOrigin || 'https://your-cck-instance.example.com';
  const githubActionsYaml = `name: CCK Agent Integrity Gate
on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  cck-release-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Verify Agent Decision Integrity Before Deploy
        run: |
          STATUS=$(curl -s -X POST "${cleanOrigin}/api/v1/ci/gate-check" \\
            -H "Content-Type: application/json" \\
            -H "x-tenant-id: ${tenantId}" \\
            -d '{"agent_id":"${agent.agent_id}"}' | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.status);")
          echo "CCK CI Gate Status: $STATUS"
          if [ "$STATUS" != "PASS" ]; then exit 1; fi`;

  return {
    report_id: `ci-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: tenantId,
    agent_id: agent.agent_id,
    agent_name: agent.name,
    status: blockedReasons.length > 0 ? 'FAIL' : 'PASS',
    checks,
    blocked_reasons: blockedReasons,
    evaluated_at: new Date().toISOString(),
    github_actions_yaml: githubActionsYaml,
  };
}
