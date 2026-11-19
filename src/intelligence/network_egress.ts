/**
 * Feature 16: Network Egress Control
 *
 * Enforces per-(tenant, tool, agent) Network Egress Policies at the CCK MCP/Webhook
 * fetch gateway boundary:
 * - Hostname & domain allow/deny rules
 * - Port & protocol rules (HTTPS enforcement option)
 * - HTTP method policy
 * - DNS resolution + IPv4/IPv6 private, loopback, link-local, metadata IP blocking
 *   (protects against DNS rebinding and literal SSRF targets)
 * - Safe redirect handling (disables blind auto-redirects; validates every Location hop!)
 * - Fail-closed if egress evaluator encounters an error or unparseable URL
 *
 * Security Boundary Note:
 * Enforced for ALL HTTP calls routed through the CCK Gateway / Egress Controller.
 * Arbitrary code executed directly by an external agent outside CCK's gateway cannot
 * be intercepted by Node application code without OS firewall / container network policies.
 */

import crypto from 'crypto';
import dns from 'dns/promises';
import net from 'net';
import type { EgressDecisionReceipt, NetworkEgressPolicyRecord } from './types.ts';

function isPrivateOrReservedIp(ip: string): { isPrivate: boolean; isLoopback: boolean; isLinkLocal: boolean; isMetadata: boolean } {
  const normalized = ip.trim().toLowerCase();

  // Handle IPv4-mapped IPv6 like ::ffff:127.0.0.1
  const v4 = normalized.startsWith('::ffff:') ? normalized.slice(7) : normalized;

  if (net.isIPv4(v4)) {
    const parts = v4.split('.').map(Number);
    const [a, b] = parts;
    const isLoopback = a === 127 || v4 === '0.0.0.0';
    const isLinkLocal = a === 169 && b === 254;
    const isMetadata = v4 === '169.254.169.254';
    const isPrivate =
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127); // CGNAT 100.64/10
    return { isPrivate, isLoopback, isLinkLocal, isMetadata };
  }

  if (net.isIPv6(normalized)) {
    const isLoopback = normalized === '::1' || normalized === '0:0:0:0:0:0:0:1';
    const isLinkLocal = normalized.startsWith('fe80:');
    const isPrivate = normalized.startsWith('fc') || normalized.startsWith('fd'); // ULA fc00::/7
    const isMetadata = normalized === 'fd00:ec2::254';
    return { isPrivate, isLoopback, isLinkLocal, isMetadata };
  }

  // Unrecognized IP literal -> treat conservatively
  return { isPrivate: true, isLoopback: false, isLinkLocal: false, isMetadata: false };
}

function matchDomain(pattern: string, hostname: string): boolean {
  const p = pattern.trim().toLowerCase();
  const h = hostname.trim().toLowerCase();
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const root = p.slice(2);
    return h === root || h.endsWith(`.${root}`);
  }
  return h === p;
}

export function createNetworkEgressPolicy(input: {
  tenant_id: string;
  tool_id?: string;
  agent_id?: string;
  hostname_allowlist?: string[];
  allowed_domains?: string[];
  denied_domains?: string[];
  allowed_ports?: number[];
  denied_ports?: number[];
  protocol_rules?: Array<'https' | 'http'>;
  block_private_ips?: boolean;
  block_loopback?: boolean;
  block_link_local?: boolean;
  block_metadata?: boolean;
  allowed_ips?: string[];
  allow_loopback_for_test?: boolean;
  redirect_policy?: 'BLOCK' | 'VALIDATE_HOPS';
  max_redirects?: number;
  method_policy?: string[];
  require_tls_in_prod?: boolean;
}): NetworkEgressPolicyRecord {
  const now = new Date().toISOString();
  return {
    egress_policy_id: `egpol-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: input.tenant_id || 'tenant_default',
    tool_id: input.tool_id || '*',
    agent_id: input.agent_id || '*',
    policy_version: 1,
    hostname_allowlist: input.hostname_allowlist || [],
    domain_rules: {
      allowed_domains: input.allowed_domains || [],
      denied_domains: input.denied_domains || ['metadata.google.internal', '*.internal'],
    },
    port_rules: {
      allowed_ports: input.allowed_ports || [443, 80],
      denied_ports: input.denied_ports || [22, 25, 3306, 5432, 6379],
    },
    protocol_rules: input.protocol_rules || ['https'],
    ip_rules: {
      block_private_ips: input.block_private_ips !== false,
      block_loopback: input.block_loopback !== false,
      block_link_local: input.block_link_local !== false,
      block_metadata: input.block_metadata !== false,
      allowed_ips: input.allowed_ips,
      allow_loopback_for_test: Boolean(input.allow_loopback_for_test),
    },
    redirect_policy: input.redirect_policy || 'BLOCK',
    max_redirects: Math.max(0, Math.min(5, input.max_redirects ?? 2)),
    method_policy: (input.method_policy || ['POST', 'GET']).map((m) => m.toUpperCase()),
    destination_risk_policy: {
      require_tls_in_prod: input.require_tls_in_prod !== false,
      max_risk_level: 'MEDIUM',
    },
    is_active: true,
    created_at: now,
    updated_at: now,
  };
}

export function selectEgressPolicy(params: {
  policies: NetworkEgressPolicyRecord[];
  tenantId: string;
  toolId: string;
  agentId: string;
}): NetworkEgressPolicyRecord | undefined {
  const active = params.policies.filter((p) => p.is_active && p.tenant_id === params.tenantId);
  const scored = active
    .filter((p) => (p.tool_id === '*' || p.tool_id === params.toolId) && (p.agent_id === '*' || p.agent_id === params.agentId))
    .map((p) => {
      let score = 0;
      if (p.tool_id === params.toolId) score += 20;
      if (p.agent_id === params.agentId) score += 10;
      return { policy: p, score };
    })
    .sort((a, b) => b.score - a.score);
  return scored[0]?.policy;
}

export async function evaluateNetworkEgress(params: {
  tenantId: string;
  toolId: string;
  agentId: string;
  url: string;
  method?: string;
  policies: NetworkEgressPolicyRecord[];
  receiptsLedger?: EgressDecisionReceipt[];
  allowLoopbackForTest?: boolean;
  redirectHops?: string[];
  dnsResolverOverride?: (hostname: string) => Promise<string[]>;
}): Promise<{ allowed: boolean; receipt: EgressDecisionReceipt; policy?: NetworkEgressPolicyRecord }> {
  const nowIso = new Date().toISOString();
  const method = (params.method || 'POST').toUpperCase();
  const redirectHops = params.redirectHops || [];

  const recordReceipt = (r: EgressDecisionReceipt) => {
    if (params.receiptsLedger) {
      params.receiptsLedger.unshift(r);
      if (params.receiptsLedger.length > 300) params.receiptsLedger.pop();
    }
    return r;
  };

  let parsed: URL;
  try {
    parsed = new URL(params.url);
  } catch {
    const r = recordReceipt({
      egress_receipt_id: `egr-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      tool_id: params.toolId,
      agent_id: params.agentId,
      destination_url: params.url,
      hostname: 'invalid',
      resolved_ips: [],
      port: 0,
      protocol: 'invalid',
      method,
      redirect_hops: redirectHops,
      decision: 'BLOCK',
      reason: 'Egress BLOCKED (Fail-Closed): Malformed destination URL.',
      evaluated_at: nowIso,
    });
    return { allowed: false, receipt: r };
  }

  const protocol = parsed.protocol.replace(/:$/, '').toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port ? Number(parsed.port) : protocol === 'https' ? 443 : protocol === 'http' ? 80 : 0;

  const matchedPolicy = selectEgressPolicy({
    policies: params.policies,
    tenantId: params.tenantId,
    toolId: params.toolId,
    agentId: params.agentId,
  });

  const blockWith = (reason: string, resolvedIps: string[] = []): { allowed: boolean; receipt: EgressDecisionReceipt; policy?: NetworkEgressPolicyRecord } => {
    const r = recordReceipt({
      egress_receipt_id: `egr-${crypto.randomUUID().slice(0, 8)}`,
      tenant_id: params.tenantId,
      tool_id: params.toolId,
      agent_id: params.agentId,
      destination_url: params.url,
      hostname,
      resolved_ips: resolvedIps,
      port,
      protocol,
      method,
      redirect_hops: redirectHops,
      decision: 'BLOCK',
      policy_id: matchedPolicy?.egress_policy_id,
      policy_version: matchedPolicy?.policy_version,
      reason,
      evaluated_at: nowIso,
    });
    return { allowed: false, receipt: r, policy: matchedPolicy };
  };

  if (protocol !== 'https' && protocol !== 'http') {
    return blockWith(`Egress BLOCKED: Unsupported protocol "${protocol}". Only HTTP/HTTPS governed.`);
  }

  // Method, Protocol, Port, Allowlist checks when policy is configured
  if (matchedPolicy) {
    if (matchedPolicy.method_policy.length > 0 && !matchedPolicy.method_policy.includes(method)) {
      return blockWith(`Egress BLOCKED: HTTP method "${method}" not in allowed method_policy [${matchedPolicy.method_policy.join(', ')}].`);
    }
    const effectiveAllowLoopback = Boolean(params.allowLoopbackForTest || matchedPolicy.ip_rules.allow_loopback_for_test);
    if (!matchedPolicy.protocol_rules.includes(protocol as 'https' | 'http')) {
      const isLocalTestHost = hostname === '127.0.0.1' || hostname === 'localhost';
      if (!(effectiveAllowLoopback && isLocalTestHost && protocol === 'http')) {
        return blockWith(`Egress BLOCKED: Protocol "${protocol}" prohibited by egress policy ${matchedPolicy.egress_policy_id}.`);
      }
    }
    if (matchedPolicy.port_rules.denied_ports.includes(port)) {
      return blockWith(`Egress BLOCKED: Port ${port} is explicitly denied.`);
    }
    if (matchedPolicy.port_rules.allowed_ports.length > 0 && !matchedPolicy.port_rules.allowed_ports.includes(port) && !(effectiveAllowLoopback && port >= 1024)) {
      return blockWith(`Egress BLOCKED: Port ${port} is not in allowed_ports [${matchedPolicy.port_rules.allowed_ports.join(', ')}].`);
    }
    if (matchedPolicy.domain_rules.denied_domains.some((d) => matchDomain(d, hostname))) {
      return blockWith(`Egress BLOCKED: Hostname "${hostname}" matched denied_domains rule.`);
    }
    const hasAllowRules = matchedPolicy.hostname_allowlist.length > 0 || matchedPolicy.domain_rules.allowed_domains.length > 0;
    if (hasAllowRules) {
      const inHostList = matchedPolicy.hostname_allowlist.some((h) => matchDomain(h, hostname));
      const inDomList = matchedPolicy.domain_rules.allowed_domains.some((d) => matchDomain(d, hostname));
      if (!inHostList && !inDomList) {
        return blockWith(`Egress BLOCKED: Hostname "${hostname}" is not in tool egress allowlist.`);
      }
    }
  } else {
    // Baseline default guard even if no explicit policy exists
    if (hostname.includes('metadata.google.internal') || hostname.endsWith('.internal')) {
      return blockWith(`Egress BLOCKED: Internal/metadata hostname "${hostname}" is forbidden.`);
    }
  }

  // DNS & IP validation (DNS rebinding & SSRF guard)
  let resolvedIps: string[] = [];
  if (net.isIP(hostname) !== 0) {
    resolvedIps = [hostname];
  } else if (hostname === 'localhost') {
    resolvedIps = ['127.0.0.1'];
  } else {
    try {
      if (params.dnsResolverOverride) {
        resolvedIps = await params.dnsResolverOverride(hostname);
      } else {
        const lookups = await dns.lookup(hostname, { all: true });
        resolvedIps = lookups.map((l) => l.address);
      }
    } catch {
      return blockWith(`Egress BLOCKED (Fail-Closed): DNS resolution failed for "${hostname}".`);
    }
  }

  const allowLoopback = Boolean(
    params.allowLoopbackForTest || matchedPolicy?.ip_rules.allow_loopback_for_test
  );
  const blockPrivate = matchedPolicy ? matchedPolicy.ip_rules.block_private_ips : true;
  const blockLoopback = matchedPolicy ? matchedPolicy.ip_rules.block_loopback && !allowLoopback : !allowLoopback;
  const blockLinkLocal = matchedPolicy ? matchedPolicy.ip_rules.block_link_local : true;
  const blockMetadata = matchedPolicy ? matchedPolicy.ip_rules.block_metadata : true;

  for (const ip of resolvedIps) {
    const ipExplicitlyAllowed = matchedPolicy?.ip_rules.allowed_ips?.includes(ip);
    const check = isPrivateOrReservedIp(ip);
    if (check.isMetadata && blockMetadata) {
      return blockWith(`Egress BLOCKED: Resolved IP "${ip}" is cloud metadata endpoint.`, resolvedIps);
    }
    if (check.isLinkLocal && blockLinkLocal) {
      return blockWith(`Egress BLOCKED: Resolved IP "${ip}" is link-local address.`, resolvedIps);
    }
    if (check.isLoopback && blockLoopback && !ipExplicitlyAllowed) {
      return blockWith(`Egress BLOCKED: Loopback IP "${ip}" is forbidden by egress policy.`, resolvedIps);
    }
    if (check.isPrivate && blockPrivate && !ipExplicitlyAllowed) {
      return blockWith(`Egress BLOCKED: Private RFC1918/ULA IP "${ip}" is forbidden (SSRF/DNS rebinding guard).`, resolvedIps);
    }
  }

  const allowReceipt = recordReceipt({
    egress_receipt_id: `egr-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    tool_id: params.toolId,
    agent_id: params.agentId,
    destination_url: params.url,
    hostname,
    resolved_ips: resolvedIps,
    port,
    protocol,
    method,
    redirect_hops: redirectHops,
    decision: 'ALLOW',
    policy_id: matchedPolicy?.egress_policy_id,
    policy_version: matchedPolicy?.policy_version,
    reason: `Egress ALLOWED to ${hostname} [${resolvedIps.join(', ')}]:${port}.`,
    evaluated_at: nowIso,
  });

  return { allowed: true, receipt: allowReceipt, policy: matchedPolicy };
}

/**
 * Performs governed HTTP fetch through the Egress Controller with manual redirect inspection.
 */
export async function governedEgressFetch(params: {
  tenantId: string;
  toolId: string;
  agentId: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  policies: NetworkEgressPolicyRecord[];
  receiptsLedger?: EgressDecisionReceipt[];
  allowLoopbackForTest?: boolean;
}): Promise<{
  ok: boolean;
  response?: Response;
  receipt: EgressDecisionReceipt;
  error?: string;
}> {
  let currentUrl = params.url;
  const hops: string[] = [];

  const initialCheck = await evaluateNetworkEgress({
    tenantId: params.tenantId,
    toolId: params.toolId,
    agentId: params.agentId,
    url: currentUrl,
    method: params.method,
    policies: params.policies,
    receiptsLedger: params.receiptsLedger,
    allowLoopbackForTest: params.allowLoopbackForTest,
    redirectHops: hops,
  });

  if (!initialCheck.allowed) {
    return {
      ok: false,
      receipt: initialCheck.receipt,
      error: initialCheck.receipt.reason,
    };
  }

  const maxRedirects = initialCheck.policy?.redirect_policy === 'VALIDATE_HOPS' ? initialCheck.policy.max_redirects : 0;

  for (let hopCount = 0; hopCount <= maxRedirects; hopCount++) {
    const resp = await fetch(currentUrl, {
      method: params.method || 'POST',
      headers: params.headers,
      body: params.body,
      redirect: 'manual',
      signal: params.signal,
    });

    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location');
      if (!location) {
        return {
          ok: false,
          receipt: initialCheck.receipt,
          error: `Egress BLOCKED: Upstream returned ${resp.status} redirect without valid Location header.`,
        };
      }
      const nextUrl = new URL(location, currentUrl).toString();
      hops.push(nextUrl);

      if (initialCheck.policy?.redirect_policy !== 'VALIDATE_HOPS' || hopCount >= maxRedirects) {
        const blockReceipt: EgressDecisionReceipt = {
          egress_receipt_id: `egr-${crypto.randomUUID().slice(0, 8)}`,
          tenant_id: params.tenantId,
          tool_id: params.toolId,
          agent_id: params.agentId,
          destination_url: nextUrl,
          hostname: new URL(nextUrl).hostname,
          resolved_ips: [],
          port: 0,
          protocol: new URL(nextUrl).protocol.replace(/:$/, ''),
          method: params.method || 'POST',
          redirect_hops: [...hops],
          decision: 'BLOCK',
          policy_id: initialCheck.policy?.egress_policy_id,
          policy_version: initialCheck.policy?.policy_version,
          reason: `Egress BLOCKED: Redirect to "${nextUrl}" denied by redirect_policy=${initialCheck.policy?.redirect_policy || 'BLOCK'}.`,
          evaluated_at: new Date().toISOString(),
        };
        if (params.receiptsLedger) params.receiptsLedger.unshift(blockReceipt);
        return {
          ok: false,
          receipt: blockReceipt,
          error: blockReceipt.reason,
        };
      }

      const hopEval = await evaluateNetworkEgress({
        tenantId: params.tenantId,
        toolId: params.toolId,
        agentId: params.agentId,
        url: nextUrl,
        method: params.method,
        policies: params.policies,
        receiptsLedger: params.receiptsLedger,
        allowLoopbackForTest: params.allowLoopbackForTest,
        redirectHops: [...hops],
      });
      if (!hopEval.allowed) {
        return {
          ok: false,
          receipt: hopEval.receipt,
          error: `Egress BLOCKED on redirect hop: ${hopEval.receipt.reason}`,
        };
      }
      currentUrl = nextUrl;
      continue;
    }

    return { ok: true, response: resp, receipt: initialCheck.receipt };
  }

  return {
    ok: false,
    receipt: initialCheck.receipt,
    error: 'Egress BLOCKED: Exceeded maximum validated redirect hops.',
  };
}
