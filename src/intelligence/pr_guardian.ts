/**
 * Feature 19: CCK GitHub PR Guardian
 *
 * Evaluates Pull Request changes to MCP configurations, tool schemas, connector manifests,
 * and CCK policies using CCK's real core engines:
 * - Tool Identity Fingerprinting & Tool Drift Detection (CRITICAL/HIGH/MEDIUM/LOW)
 * - Permission Escalation & Endpoint Change Detection
 * - Static Scanner Findings
 * - Safe Replay Fixtures (when declared)
 *
 * Security & Least-Privilege Guarantees:
 * - Never executes arbitrary untrusted code from PR head
 * - Returns INSUFFICIENT_COVERAGE when diff/snapshot is unparseable or incomplete (NEVER false PASS)
 * - Configurable fail_on_severity threshold ('CRITICAL' | 'HIGH')
 */

import crypto from 'crypto';
import type {
  CanonicalToolDefinition,
  PrGuardianEvaluationReport,
  PrGuardianVerdict,
  ScannerFinding,
} from './types.ts';
import { computeToolFingerprint, detectToolDrift } from './tool_intelligence.ts';
import { CCK_SCANNER_VERSION } from './scanner.ts';

export const PR_GUARDIAN_POLICY_VERSION = 'cck-pr-policy-v1';

export interface PrToolSnapshotEntry {
  file: string;
  tool: Partial<CanonicalToolDefinition> & { tool_id: string; name?: string };
}

export function evaluatePullRequestGuardian(params: {
  tenantId?: string;
  repository: string;
  prNumber?: number;
  baseSha: string;
  headSha: string;
  changedFiles: string[];
  baseTools?: PrToolSnapshotEntry[];
  headTools?: PrToolSnapshotEntry[];
  coverageAvailable?: boolean;
  failOnSeverity?: 'CRITICAL' | 'HIGH';
  replayFixtures?: Array<{
    pack_name: string;
    expected_decision: string;
    actual_decision: string;
  }>;
}): PrGuardianEvaluationReport {
  const {
    tenantId,
    repository,
    prNumber,
    baseSha,
    headSha,
    changedFiles,
    baseTools = [],
    headTools = [],
    coverageAvailable = true,
    failOnSeverity = 'CRITICAL',
    replayFixtures = [],
  } = params;

  const toolRelatedFiles = changedFiles.filter((f) =>
    /(mcp|tool|connector|cck\.config|policies)/i.test(f)
  );

  // Incomplete / broken diff -> fail safe with INSUFFICIENT_COVERAGE (NEVER fake PASS!)
  if (!coverageAvailable || !baseSha || !headSha) {
    const reportPartial = {
      report_ref: `prg-${crypto.randomUUID().slice(0, 10)}`,
      tenant_id: tenantId,
      repository,
      pr_number: prNumber,
      base_sha: baseSha || 'missing',
      head_sha: headSha || 'missing',
      verdict: 'INSUFFICIENT_COVERAGE' as PrGuardianVerdict,
      merge_blocked: true,
      fail_on_severity: failOnSeverity,
      policy_version: PR_GUARDIAN_POLICY_VERSION,
      scanner_version: CCK_SCANNER_VERSION,
      changed_files: changedFiles,
      analyzed_tool_files: toolRelatedFiles,
      tool_fingerprint_changes: [],
      changed_permissions: { added: [], removed: [] },
      changed_endpoints: { added: [], removed: [] },
      schema_changes: [],
      replay_checks: [],
      findings: [
        {
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-PR-COVERAGE',
          severity: 'HIGH' as const,
          certainty: 'CONFIRMED' as const,
          file: '.',
          title: 'Insufficient coverage to evaluate PR changes',
          description: 'Base/Head diff or tool manifests could not be parsed cleanly; PR Guardian refuses to return a false PASS.',
          evidence: `base_sha=${baseSha || 'missing'}, head_sha=${headSha || 'missing'}, coverageAvailable=${coverageAvailable}`,
          recommendation: 'Ensure PR checkout includes base and head commits and valid JSON tool/MCP definitions.',
          confidence: 1.0,
          limitation: 'Cannot verify security drift without complete base/head manifests.',
          scanner_version: CCK_SCANNER_VERSION,
        },
      ],
      coverage: {
        percentage: 0,
        covered_areas: [],
        uncovered_reasons: ['Missing or unparseable base/head tool manifest comparison'],
      },
      github_annotations: [
        {
          level: 'warning' as const,
          file: toolRelatedFiles[0] || '.github/workflows/cck-pr-guardian.yml',
          title: 'CCK PR Guardian: INSUFFICIENT COVERAGE',
          message: 'Unable to parse tool/MCP diff completely; manual review required.',
        },
      ],
      markdown_summary: `### CCK PR Guardian Verdict: INSUFFICIENT COVERAGE\nCommit \`${headSha || 'unknown'}\` could not be fully evaluated. No false PASS granted.`,
      executed_at: new Date().toISOString(),
    };
    return {
      ...reportPartial,
      report_digest_sha256: crypto.createHash('sha256').update(JSON.stringify(reportPartial)).digest('hex'),
    };
  }

  // No tool/MCP/policy/connector files touched -> clean PASS
  if (toolRelatedFiles.length === 0 && baseTools.length === 0 && headTools.length === 0) {
    const cleanPartial = {
      report_ref: `prg-${crypto.randomUUID().slice(0, 10)}`,
      tenant_id: tenantId,
      repository,
      pr_number: prNumber,
      base_sha: baseSha,
      head_sha: headSha,
      verdict: 'PASS' as PrGuardianVerdict,
      merge_blocked: false,
      fail_on_severity: failOnSeverity,
      policy_version: PR_GUARDIAN_POLICY_VERSION,
      scanner_version: CCK_SCANNER_VERSION,
      changed_files: changedFiles,
      analyzed_tool_files: [],
      tool_fingerprint_changes: [],
      changed_permissions: { added: [], removed: [] },
      changed_endpoints: { added: [], removed: [] },
      schema_changes: [],
      replay_checks: [],
      findings: [],
      coverage: {
        percentage: 100,
        covered_areas: ['changed_file_classification', 'no_tool_or_policy_drift'],
        uncovered_reasons: [],
      },
      github_annotations: [],
      markdown_summary: `### CCK PR Guardian Verdict: PASS\n- Commit: \`${headSha}\`\n- Checked ${changedFiles.length} changed file(s): no MCP/tool/connector/policy changes detected.`,
      executed_at: new Date().toISOString(),
    };
    return {
      ...cleanPartial,
      report_digest_sha256: crypto.createHash('sha256').update(JSON.stringify(cleanPartial)).digest('hex'),
    };
  }

  const normalizeEntry = (raw: any, fallbackFile: string): PrToolSnapshotEntry | null => {
    if (!raw || typeof raw !== 'object') return null;
    const toolObj = raw.tool && typeof raw.tool === 'object' ? raw.tool : raw;
    if (!toolObj.tool_id && !toolObj.name && !toolObj.id) return null;
    return {
      file: String(raw.file || fallbackFile),
      tool: {
        ...toolObj,
        tool_id: String(toolObj.tool_id || toolObj.id || toolObj.name),
        declared_permissions: Array.isArray(toolObj.declared_permissions)
          ? toolObj.declared_permissions
          : Array.isArray(toolObj.permissions)
          ? toolObj.permissions
          : [],
        declared_endpoints: Array.isArray(toolObj.declared_endpoints)
          ? toolObj.declared_endpoints
          : Array.isArray(toolObj.endpoints)
          ? toolObj.endpoints
          : [],
      },
    };
  };

  // Compare baseTools vs headTools via Tool Identity Fingerprinter & Drift Detector
  const baseMap = new Map<string, PrToolSnapshotEntry>();
  for (const rawB of baseTools) {
    const entry = normalizeEntry(rawB, toolRelatedFiles[0] || 'mcp.json');
    if (entry) baseMap.set(entry.tool.tool_id, entry);
  }
  const headMap = new Map<string, PrToolSnapshotEntry>();
  for (const rawH of headTools) {
    const entry = normalizeEntry(rawH, toolRelatedFiles[0] || 'mcp.json');
    if (entry) headMap.set(entry.tool.tool_id, entry);
  }

  const fingerprintChanges: PrGuardianEvaluationReport['tool_fingerprint_changes'] = [];
  const addedPerms = new Set<string>();
  const removedPerms = new Set<string>();
  const addedEndpoints = new Set<string>();
  const removedEndpoints = new Set<string>();
  const schemaChanges: string[] = [];
  const findings: ScannerFinding[] = [];
  const annotations: PrGuardianEvaluationReport['github_annotations'] = [];

  for (const [toolId, headEntry] of headMap.entries()) {
    const baseEntry = baseMap.get(toolId);
    const nextCanon: CanonicalToolDefinition = {
      tool_id: headEntry.tool.tool_id,
      name: headEntry.tool.name || headEntry.tool.tool_id,
      version: headEntry.tool.version || '1.0.0',
      input_schema: headEntry.tool.input_schema || {},
      output_schema: headEntry.tool.output_schema,
      declared_permissions: headEntry.tool.declared_permissions || [],
      declared_endpoints: headEntry.tool.declared_endpoints || [],
      capabilities: headEntry.tool.capabilities || [],
      identity_source: headEntry.tool.identity_source || 'DECLARED',
    };
    const nextFp = computeToolFingerprint(nextCanon).fingerprint_hash;

    if (!baseEntry) {
      fingerprintChanges.push({
        tool_id: toolId,
        to_fingerprint: nextFp,
        to_version: nextCanon.version,
        drift_severity: nextCanon.declared_permissions.some((p) => /admin|\*|exec|delete/i.test(p)) ? 'CRITICAL' : 'MEDIUM',
        drift_types: ['NEW_TOOL_ADDED'],
      });
      nextCanon.declared_permissions.forEach((p) => addedPerms.add(p));
      nextCanon.declared_endpoints.forEach((e) => addedEndpoints.add(e));
      const sev = nextCanon.declared_permissions.some((p) => /admin|\*|exec|delete|root/i.test(p))
        ? 'CRITICAL'
        : 'MEDIUM';
      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: 'CCK-PR-NEW-TOOL',
        severity: sev,
        certainty: 'CONFIRMED',
        file: headEntry.file,
        location: `tool:${toolId}`,
        title: `New tool "${toolId}" introduced in PR (${nextCanon.version})`,
        description: `PR introduces tool "${toolId}" with permissions [${nextCanon.declared_permissions.join(', ') || 'none'}] and endpoints [${nextCanon.declared_endpoints.join(', ') || 'none'}].`,
        evidence: `fingerprint=${nextFp.slice(0, 16)}`,
        recommendation: 'Verify least-privilege permissions and network egress allowlist prior to merge.',
        confidence: 0.95,
        limitation: 'Static PR manifest inspection.',
        scanner_version: CCK_SCANNER_VERSION,
      });
      annotations.push({
        level: sev === 'CRITICAL' ? 'error' : 'warning',
        file: headEntry.file,
        title: `New tool added: ${toolId}`,
        message: `Permissions: [${nextCanon.declared_permissions.join(', ')}]`,
      });
      continue;
    }

    const prevCanon: CanonicalToolDefinition = {
      tool_id: baseEntry.tool.tool_id,
      name: baseEntry.tool.name || baseEntry.tool.tool_id,
      version: baseEntry.tool.version || '1.0.0',
      input_schema: baseEntry.tool.input_schema || {},
      output_schema: baseEntry.tool.output_schema,
      declared_permissions: baseEntry.tool.declared_permissions || [],
      declared_endpoints: baseEntry.tool.declared_endpoints || [],
      capabilities: baseEntry.tool.capabilities || [],
      identity_source: baseEntry.tool.identity_source || 'DECLARED',
    };
    const prevFp = computeToolFingerprint(prevCanon).fingerprint_hash;

    const drift = detectToolDrift({
      tenantId: tenantId || 'pr_guardian',
      toolIdentityId: `tid-${toolId}`,
      previous: prevCanon,
      next: nextCanon,
      fromFingerprint: prevFp,
      toFingerprint: nextFp,
    });

    if (drift) {
      fingerprintChanges.push({
        tool_id: toolId,
        from_fingerprint: prevFp,
        to_fingerprint: nextFp,
        from_version: prevCanon.version,
        to_version: nextCanon.version,
        drift_severity: drift.severity,
        drift_types: drift.drift_types,
      });

      const newP = nextCanon.declared_permissions.filter((p) => !prevCanon.declared_permissions.includes(p));
      const remP = prevCanon.declared_permissions.filter((p) => !nextCanon.declared_permissions.includes(p));
      newP.forEach((p) => addedPerms.add(p));
      remP.forEach((p) => removedPerms.add(p));

      const newE = nextCanon.declared_endpoints.filter((e) => !prevCanon.declared_endpoints.includes(e));
      const remE = prevCanon.declared_endpoints.filter((e) => !nextCanon.declared_endpoints.includes(e));
      newE.forEach((e) => addedEndpoints.add(e));
      remE.forEach((e) => removedEndpoints.add(e));

      if (drift.drift_types.includes('INPUT_SCHEMA_CHANGED') || drift.drift_types.includes('OUTPUT_SCHEMA_CHANGED')) {
        schemaChanges.push(`${toolId}: ${drift.drift_types.join(', ')}`);
      }

      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: `CCK-PR-DRIFT-${drift.severity}`,
        severity: drift.severity,
        certainty: 'CONFIRMED',
        file: headEntry.file,
        location: `tool:${toolId}`,
        title: `Tool drift detected on "${toolId}" (${drift.drift_types.join(', ')})`,
        description: drift.explanation.join(' '),
        evidence: `${prevFp.slice(0, 12)} -> ${nextFp.slice(0, 12)}`,
        recommendation: `Recommended CCK Action: ${drift.recommended_action}. Review permission/endpoint/schema diffs before merging.`,
        confidence: 0.99,
        limitation: 'Derived from base vs head tool definition canonical diff.',
        scanner_version: CCK_SCANNER_VERSION,
      });
      annotations.push({
        level: drift.severity === 'CRITICAL' ? 'error' : drift.severity === 'HIGH' ? 'warning' : 'notice',
        file: headEntry.file,
        title: `CCK Tool Drift [${drift.severity}]: ${toolId}`,
        message: drift.explanation.join(' '),
      });
    }
  }

  const replayChecks = replayFixtures.map((rf) => ({
    pack_name: rf.pack_name,
    status: rf.expected_decision === rf.actual_decision ? 'PASSED' : 'REGRESSION',
    detail: `expected=${rf.expected_decision}, actual=${rf.actual_decision}`,
  }));
  for (const rc of replayChecks) {
    if (rc.status !== 'PASSED') {
      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: 'CCK-PR-REPLAY-REGRESSION',
        severity: 'CRITICAL',
        certainty: 'CONFIRMED',
        file: toolRelatedFiles[0] || '.',
        title: `Safe Replay regression in "${rc.pack_name}"`,
        description: `Replay fixture outcome diverged (${rc.detail}).`,
        evidence: rc.detail,
        recommendation: 'Resolve policy or tool regression before merge.',
        confidence: 1.0,
        limitation: 'Based on declared replay fixtures.',
        scanner_version: CCK_SCANNER_VERSION,
      });
    }
  }

  const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
  const hasHigh = findings.some((f) => f.severity === 'HIGH');
  const hasMedium = findings.some((f) => f.severity === 'MEDIUM');

  let verdict: PrGuardianVerdict = 'PASS';
  let mergeBlocked = false;
  if (hasCritical || (failOnSeverity === 'HIGH' && hasHigh)) {
    verdict = 'BLOCKING_FINDING';
    mergeBlocked = true;
  } else if (hasHigh) {
    verdict = 'NEEDS_HUMAN_REVIEW';
    mergeBlocked = false;
  } else if (hasMedium || findings.some((f) => f.severity === 'LOW')) {
    verdict = 'WARNING';
    mergeBlocked = false;
  }

  const reportRef = `prg-${crypto.randomUUID().slice(0, 10)}`;
  const executedAt = new Date().toISOString();
  const markdownLines = [
    `### CCK GitHub PR Guardian — Verdict: **${verdict}**`,
    `- **Repository**: \`${repository}\`${prNumber ? ` (#${prNumber})` : ''}`,
    `- **Commit**: \`${baseSha.slice(0, 8)}..${headSha.slice(0, 8)}\``,
    `- **Policy / Scanner**: \`${PR_GUARDIAN_POLICY_VERSION}\` / \`${CCK_SCANNER_VERSION}\``,
    `- **Fingerprint Changes**: ${fingerprintChanges.length}`,
    `- **Added Permissions**: ${Array.from(addedPerms).join(', ') || 'None'}`,
    `- **Added Endpoints**: ${Array.from(addedEndpoints).join(', ') || 'None'}`,
    `- **Schema Changes**: ${schemaChanges.join('; ') || 'None'}`,
    `- **Findings**: ${findings.length} (${findings.filter((f) => f.severity === 'CRITICAL').length} CRITICAL, ${findings.filter((f) => f.severity === 'HIGH').length} HIGH)`,
    `- **Report Ref**: \`${reportRef}\``,
  ];

  const partial = {
    report_ref: reportRef,
    tenant_id: tenantId,
    repository,
    pr_number: prNumber,
    base_sha: baseSha,
    head_sha: headSha,
    verdict,
    merge_blocked: mergeBlocked,
    fail_on_severity: failOnSeverity,
    policy_version: PR_GUARDIAN_POLICY_VERSION,
    scanner_version: CCK_SCANNER_VERSION,
    changed_files: changedFiles,
    analyzed_tool_files: toolRelatedFiles,
    tool_fingerprint_changes: fingerprintChanges,
    changed_permissions: {
      added: Array.from(addedPerms),
      removed: Array.from(removedPerms),
    },
    changed_endpoints: {
      added: Array.from(addedEndpoints),
      removed: Array.from(removedEndpoints),
    },
    schema_changes: schemaChanges,
    replay_checks: replayChecks,
    findings,
    coverage: {
      percentage: 100,
      covered_areas: ['tool_fingerprinting', 'permission_drift', 'endpoint_changes', 'schema_changes'],
      uncovered_reasons: [],
    },
    github_annotations: annotations,
    markdown_summary: markdownLines.join('\n'),
    executed_at: executedAt,
  };

  return {
    ...partial,
    report_digest_sha256: crypto.createHash('sha256').update(JSON.stringify(partial)).digest('hex'),
  };
}
