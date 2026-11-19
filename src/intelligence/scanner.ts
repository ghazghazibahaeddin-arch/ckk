/**
 * Feature 18: One-Command CCK Scanner
 *
 * Local Read-Only Static & Configuration Security/Reliability Scanner for MCP servers,
 * tool schemas, connector manifests, policies, and permission declarations.
 *
 * Core Guarantees:
 * - Zero account / login required for local scans
 * - Zero network upload by default (LOCAL mode never calls external or CCK endpoints)
 * - Strictly skips reading secret files (.env*, *.pem, *.key, credentials*) and masks any accidental secret values
 * - Reuses CCK's real Tool Identity Fingerprinter & Permission Risk Rules
 * - Explicitly distinguishes CONFIRMED vs POTENTIAL findings and reports unscanned files & static limitations
 * - Never labels any scan "Safe" or "100% Secure"
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { CanonicalToolDefinition, ScanMode, ScanReport, ScannerFinding, ScanSeverity } from './types.ts';
import { computeToolFingerprint } from './tool_intelligence.ts';

export const CCK_SCANNER_VERSION = '0.3.0-local';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  'coverage',
]);

const PRIVACY_SKIP_FILE_PATTERNS = [
  /^\.env(\..+)?$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /id_rsa/i,
  /id_ed25519/i,
  /secrets?\.(json|ya?ml)$/i,
  /credentials.*\.json$/i,
];

const INLINE_SECRET_REGEX =
  /(sk_live_[A-Za-z0-9_-]{10,}|cck_live_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

const CRITICAL_PERM_REGEX = /^(admin|\*|root|shell|exec|command|system\.write|filesystem\.delete|db\.drop|secret\.read)/i;
const BROAD_PERM_REGEX = /(write|delete|refund|transfer|billing|payment|modify)/i;

function isPrivacySensitiveFileName(fileName: string): boolean {
  return PRIVACY_SKIP_FILE_PATTERNS.some((rx) => rx.test(fileName));
}

function collectCandidateFiles(rootDir: string): {
  targetFiles: string[];
  skippedPrivacy: string[];
  unscannedOthersCount: number;
} {
  const targetFiles: string[] = [];
  const skippedPrivacy: string[] = [];
  let unscannedOthersCount = 0;

  const walk = (dir: string, depth: number) => {
    if (depth > 6) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);
      const relPath = path.relative(rootDir, fullPath) || entry.name;
      if (entry.isDirectory()) {
        walk(fullPath, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;

      if (isPrivacySensitiveFileName(entry.name)) {
        skippedPrivacy.push(relPath);
        continue;
      }

      const lower = entry.name.toLowerCase();
      const isMcpOrToolOrPolicy =
        lower === 'mcp.json' ||
        lower === '.mcp.json' ||
        lower === 'mcp_config.json' ||
        lower === 'claude_desktop_config.json' ||
        lower === 'tools.json' ||
        lower === 'tool_manifest.json' ||
        lower.endsWith('.tool.json') ||
        lower.endsWith('.mcp.json') ||
        lower === 'connector.manifest.json' ||
        lower === 'cck-connector.json' ||
        lower === 'cck.config.json' ||
        lower === 'cck.config.yaml' ||
        lower === 'package.json' ||
        lower === 'pyproject.toml' ||
        (lower.endsWith('.json') && (relPath.includes('policies') || relPath.includes('tools') || relPath.includes('mcp') || relPath.includes('connectors')));

      if (isMcpOrToolOrPolicy) {
        targetFiles.push(relPath);
      } else {
        unscannedOthersCount += 1;
      }
    }
  };

  if (fs.existsSync(rootDir)) {
    const stat = fs.statSync(rootDir);
    if (stat.isFile()) {
      const base = path.basename(rootDir);
      if (isPrivacySensitiveFileName(base)) {
        skippedPrivacy.push(base);
      } else {
        targetFiles.push(base);
      }
    } else {
      walk(rootDir, 0);
    }
  }

  return {
    targetFiles: targetFiles.sort(),
    skippedPrivacy: skippedPrivacy.sort(),
    unscannedOthersCount,
  };
}

function redactEvidenceText(raw: string): string {
  return raw
    .replace(INLINE_SECRET_REGEX, '[REDACTED_SECRET_PATTERN]')
    .replace(/(Bearer\s+)[A-Za-z0-9\-_.]+/gi, '$1[REDACTED]');
}

function inspectToolEntriesFromJson(params: {
  parsed: Record<string, unknown>;
  relFile: string;
  findings: ScannerFinding[];
  fingerprints: ScanReport['tool_fingerprints'];
}) {
  const { parsed, relFile, findings, fingerprints } = params;

  const extractTool = (rawTool: Record<string, unknown>, idxName: string) => {
    const toolId = String(rawTool.tool_id || rawTool.id || rawTool.name || idxName);
    const name = String(rawTool.name || toolId);
    const version = String(rawTool.version || '1.0.0');
    const perms = Array.isArray(rawTool.declared_permissions)
      ? rawTool.declared_permissions.map(String)
      : Array.isArray(rawTool.permissions)
      ? rawTool.permissions.map(String)
      : [];
    const endpoints = Array.isArray(rawTool.declared_endpoints)
      ? rawTool.declared_endpoints.map(String)
      : Array.isArray(rawTool.endpoints)
      ? rawTool.endpoints.map(String)
      : typeof rawTool.endpoint_url === 'string'
      ? [rawTool.endpoint_url]
      : typeof rawTool.url === 'string'
      ? [rawTool.url]
      : [];
    const capabilities = Array.isArray(rawTool.capabilities)
      ? rawTool.capabilities.map(String)
      : [];

    const canonDef: CanonicalToolDefinition = {
      tool_id: toolId,
      name,
      version,
      input_schema: (rawTool.input_schema as Record<string, unknown>) || (rawTool.inputSchema as Record<string, unknown>) || {},
      output_schema: (rawTool.output_schema as Record<string, unknown>) || undefined,
      declared_permissions: perms,
      declared_endpoints: endpoints,
      capabilities,
      identity_source: 'DECLARED',
    };
    const { fingerprint_hash } = computeToolFingerprint(canonDef);
    fingerprints.push({
      tool_id: toolId,
      name,
      version,
      fingerprint_sha256: fingerprint_hash,
      file: relFile,
      declared_permissions: perms,
      declared_endpoints: endpoints,
    });

    // Rule CCK-TOOL-001: Missing schema on tool definition
    if (!rawTool.input_schema && !rawTool.inputSchema) {
      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: 'CCK-TOOL-001',
        severity: 'MEDIUM',
        certainty: 'CONFIRMED',
        file: relFile,
        location: `tool:${toolId}`,
        title: `Tool "${toolId}" declares no explicit input_schema`,
        description: 'Without an explicit JSON input_schema, Action Gate and Data Flow Guard cannot strictly validate parameters statically.',
        evidence: `Tool "${toolId}" has empty input_schema`,
        recommendation: 'Define an explicit JSON Schema with strict parameter types and bounded constraints.',
        confidence: 0.95,
        limitation: 'Static check confirms schema field absence; runtime middleware may enforce additional validation.',
        scanner_version: CCK_SCANNER_VERSION,
      });
    }

    // Rule CCK-PERM-001: Over-privileged / critical permissions or capabilities declared
    for (const p of Array.from(new Set([...perms, ...capabilities]))) {
      if (CRITICAL_PERM_REGEX.test(p)) {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-PERM-001',
          severity: 'CRITICAL',
          certainty: 'CONFIRMED',
          file: relFile,
          location: `tool:${toolId}.permissions`,
          title: `Over-privileged or wildcard permission "${p}" declared`,
          description: `Tool "${toolId}" requests critical/unscoped permission "${p}" which violates least-privilege boundaries.`,
          evidence: `declared_permissions includes "${p}"`,
          recommendation: `Scope "${p}" to explicit read/resource grants and enforce CCK Permission Graph + Action Gate checks.`,
          confidence: 0.98,
          limitation: 'Static configuration finding; CCK Permission Graph runtime grant check determines effective enforcement.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      } else if (BROAD_PERM_REGEX.test(p) && !rawTool.requires_approval) {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-PERM-002',
          severity: 'HIGH',
          certainty: 'POTENTIAL',
          file: relFile,
          location: `tool:${toolId}.permissions`,
          title: `Mutating permission "${p}" without explicit approval policy hint`,
          description: `Tool "${toolId}" requests state-mutating permission "${p}" without declaring human-approval/contract metadata.`,
          evidence: `declared_permissions includes "${p}"`,
          recommendation: 'Pair mutating tools with CCK Action Contracts and REQUIRE_APPROVAL/Action Gate rules.',
          confidence: 0.8,
          limitation: 'Potential finding: runtime CCK policy engine may already gate this capability.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      }
    }

    // Rule CCK-EGRESS-001: SSRF metadata or plaintext HTTP endpoints
    for (const ep of endpoints) {
      if (/169\.254\.169\.254|metadata\.google\.internal/i.test(ep)) {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-EGRESS-001',
          severity: 'CRITICAL',
          certainty: 'CONFIRMED',
          file: relFile,
          location: `tool:${toolId}.endpoints`,
          title: 'Cloud metadata address referenced in tool endpoints',
          description: 'Endpoint declaration references a cloud instance metadata address vulnerable to SSRF credential theft.',
          evidence: `endpoint="${ep}"`,
          recommendation: 'Remove metadata address immediately and bind CCK Network Egress Control policy.',
          confidence: 0.99,
          limitation: 'Static config inspection.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      } else if (ep.startsWith('http://') && !ep.includes('localhost') && !ep.includes('127.0.0.1')) {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-EGRESS-002',
          severity: 'HIGH',
          certainty: 'CONFIRMED',
          file: relFile,
          location: `tool:${toolId}.endpoints`,
          title: 'Unencrypted plaintext HTTP external endpoint configured',
          description: `External endpoint uses plain http:// instead of HTTPS.`,
          evidence: `endpoint="${ep}"`,
          recommendation: 'Switch endpoint to https:// and enable require_tls_in_prod in Network Egress Policy.',
          confidence: 0.95,
          limitation: 'Static config inspection.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      }
    }
  };

  if (Array.isArray(parsed.tools)) {
    parsed.tools.forEach((t, idx) => {
      if (t && typeof t === 'object') {
        extractTool(t as Record<string, unknown>, `tool_${idx}`);
      }
    });
  } else if (parsed.mcpServers && typeof parsed.mcpServers === 'object') {
    for (const [srvName, srvVal] of Object.entries(parsed.mcpServers as Record<string, unknown>)) {
      if (srvVal && typeof srvVal === 'object') {
        const srvObj = srvVal as Record<string, unknown>;
        extractTool({ ...srvObj, tool_id: srvObj.tool_id || srvName, name: srvName }, srvName);
        if (srvObj.env && typeof srvObj.env === 'object') {
          for (const [envK, envV] of Object.entries(srvObj.env as Record<string, unknown>)) {
            if (typeof envV === 'string' && INLINE_SECRET_REGEX.test(envV)) {
              findings.push({
                finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
                rule_id: 'CCK-SEC-001',
                severity: 'CRITICAL',
                certainty: 'CONFIRMED',
                file: relFile,
                location: `mcpServers.${srvName}.env.${envK}`,
                title: `Hardcoded secret literal found in MCP configuration (${envK})`,
                description: 'Plaintext secret token detected inside static MCP configuration file instead of an Ephemeral Secret Broker reference.',
                evidence: `${envK}=${redactEvidenceText(envV)}`,
                recommendation: 'Replace literal credential with a CCK secret_ref managed by Ephemeral Secret Broker.',
                confidence: 0.99,
                limitation: 'Pattern-based static check; token value intentionally redacted in report.',
                scanner_version: CCK_SCANNER_VERSION,
              });
            }
          }
        }
      }
    }
  } else if (parsed.connector_id) {
    // Connector Manifest check
    const manifestObj = parsed as Record<string, unknown>;
    const reqHosts = ((manifestObj.network_requirements as Record<string, unknown>)?.allowed_hosts as string[]) || [];
    if (reqHosts.includes('*')) {
      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: 'CCK-CONN-001',
        severity: 'CRITICAL',
        certainty: 'CONFIRMED',
        file: relFile,
        location: 'network_requirements.allowed_hosts',
        title: `Connector "${manifestObj.connector_id}" allows wildcard egress host "*"`,
        description: 'Connector manifest allows arbitrary network egress hosts instead of explicit domain allowlist.',
        evidence: 'allowed_hosts: ["*"]',
        recommendation: 'Restrict allowed_hosts to explicit FQDNs required by the connector.',
        confidence: 0.99,
        limitation: 'Static manifest check.',
        scanner_version: CCK_SCANNER_VERSION,
      });
    }
    extractTool(
      {
        tool_id: String(manifestObj.connector_id),
        name: String(manifestObj.name || manifestObj.connector_id),
        version: String(manifestObj.version || '1.0.0'),
        declared_permissions: Array.isArray(manifestObj.required_permissions) ? manifestObj.required_permissions : [],
        declared_endpoints: reqHosts.map((h) => (h.startsWith('http') ? h : `https://${h}`)),
        capabilities: Array.isArray(manifestObj.declared_capabilities) ? manifestObj.declared_capabilities : [],
        input_schema: { connector_manifest: true },
      },
      String(manifestObj.connector_id)
    );
  }
}

export function scanLocalDirectory(params: {
  targetPath: string;
  mode?: ScanMode;
  uploadedToCloud?: boolean;
  failOnSeverity?: ScanSeverity;
}): ScanReport {
  const { targetPath, mode = 'LOCAL', uploadedToCloud = false, failOnSeverity = 'HIGH' } = params;
  const resolvedRoot = path.resolve(targetPath);
  const { targetFiles, skippedPrivacy, unscannedOthersCount } = collectCandidateFiles(resolvedRoot);

  const findings: ScannerFinding[] = [];
  const fingerprints: ScanReport['tool_fingerprints'] = [];
  const filesScanned: string[] = [];

  for (const relFile of targetFiles) {
    const absPath = path.join(
      fs.statSync(resolvedRoot).isFile() ? path.dirname(resolvedRoot) : resolvedRoot,
      fs.statSync(resolvedRoot).isFile() ? path.basename(resolvedRoot) : relFile
    );
    let content = '';
    try {
      content = fs.readFileSync(absPath, 'utf-8');
      filesScanned.push(relFile);
    } catch {
      continue;
    }

    // Inline secret pattern check across non-secret config files (value redacted)
    if (INLINE_SECRET_REGEX.test(content)) {
      findings.push({
        finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
        rule_id: 'CCK-SEC-002',
        severity: 'CRITICAL',
        certainty: 'CONFIRMED',
        file: relFile,
        title: 'Embedded credential or private key pattern detected in config file',
        description: 'Static file contains a token/private-key pattern that risks accidental exposure in VCS or agent prompts.',
        evidence: 'Matched token/key regex pattern (literal value suppressed for safety).',
        recommendation: 'Remove embedded credentials and provision ephemeral access via CCK Secret Broker.',
        confidence: 0.97,
        limitation: 'Regex-based static detection.',
        scanner_version: CCK_SCANNER_VERSION,
      });
    }

    if (relFile.toLowerCase().endsWith('.json')) {
      try {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        inspectToolEntriesFromJson({ parsed, relFile, findings, fingerprints });
      } catch {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-CFG-001',
          severity: 'LOW',
          certainty: 'CONFIRMED',
          file: relFile,
          title: 'Invalid JSON syntax in configuration file',
          description: 'Configuration file could not be parsed as valid JSON, preventing full static schema verification.',
          evidence: `Failed JSON.parse on ${relFile}`,
          recommendation: 'Fix malformed JSON syntax before deploying tool or MCP definitions.',
          confidence: 1.0,
          limitation: 'Syntax error blocks deeper AST/schema inspection of this file.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      }
    } else if (relFile.toLowerCase() === 'cck.config.yaml') {
      if (/shadow_mode:\s*true/i.test(content)) {
        findings.push({
          finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
          rule_id: 'CCK-POL-001',
          severity: 'MEDIUM',
          certainty: 'CONFIRMED',
          file: relFile,
          title: 'CCK shadow_mode enabled in configuration',
          description: 'Action Gate is configured for shadow/observe mode; policy violations will not block execution.',
          evidence: 'shadow_mode: true in cck.config.yaml',
          recommendation: 'Set shadow_mode: false for production Fail-Closed enforcement.',
          confidence: 0.95,
          limitation: 'Static YAML configuration check.',
          scanner_version: CCK_SCANNER_VERSION,
        });
      }
    }
  }

  if (filesScanned.length === 0) {
    findings.push({
      finding_id: `fnd-${crypto.randomUUID().slice(0, 8)}`,
      rule_id: 'CCK-SCAN-000',
      severity: 'INFO',
      certainty: 'CONFIRMED',
      file: '.',
      title: 'No MCP, tool manifest, connector, or CCK configuration files detected',
      description: 'Scanner found zero recognizable MCP/tool/connector manifest files in the target path.',
      evidence: `Discovered 0 scannable manifest files (${unscannedOthersCount} non-manifest files skipped).`,
      recommendation: 'Run cck scan against a directory containing mcp.json, tools.json, or connector.manifest.json.',
      confidence: 1.0,
      limitation: 'Static scanner inspects supported configuration/manifest formats only.',
      scanner_version: CCK_SCANNER_VERSION,
    });
  }

  const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const medium = findings.filter((f) => f.severity === 'MEDIUM').length;
  const low = findings.filter((f) => f.severity === 'LOW').length;
  const info = findings.filter((f) => f.severity === 'INFO').length;

  let exitCode = 0;
  if (critical > 0) exitCode = 2;
  else if (high > 0 && (failOnSeverity === 'HIGH' || failOnSeverity === 'MEDIUM' || failOnSeverity === 'LOW')) exitCode = 1;
  else if (medium > 0 && (failOnSeverity === 'MEDIUM' || failOnSeverity === 'LOW')) exitCode = 1;

  const statusStatement =
    findings.filter((f) => f.severity !== 'INFO').length === 0
      ? `Static configuration scan completed (${filesScanned.length} file(s)): 0 configuration issues flagged within scanned static rules. Does not establish runtime proof.`
      : `Static scan detected ${critical} CRITICAL, ${high} HIGH, ${medium} MEDIUM, ${low} LOW finding(s) across ${filesScanned.length} scanned file(s).`;

  const partialReport = {
    scan_id: `scan-${crypto.randomUUID().slice(0, 10)}`,
    scanner_version: CCK_SCANNER_VERSION,
    mode,
    target_path: mode === 'LOCAL' ? resolvedRoot : path.basename(resolvedRoot),
    scanned_at: new Date().toISOString(),
    static_analysis_only: true as const,
    uploaded_to_cloud: mode === 'UPLOAD_SANITIZED' && uploadedToCloud,
    files_discovered: targetFiles.length,
    files_scanned: filesScanned,
    files_skipped_privacy: skippedPrivacy,
    unscanned_summary: [
      `${unscannedOthersCount} source/asset file(s) outside supported MCP/tool/connector manifest formats were not parsed`,
      `${skippedPrivacy.length} secret-bearing file(s) skipped for local privacy protection`,
    ],
    tool_fingerprints: fingerprints,
    findings,
    summary: {
      critical,
      high,
      medium,
      low,
      info,
      total: findings.length,
      recommended_exit_code: exitCode,
      status_statement: statusStatement,
    },
    scope_and_limitations: [
      'Local read-only static inspection of MCP configurations, tool schemas, connector manifests, and CCK configs.',
      'Does NOT execute untrusted tools or verify live runtime side-effects.',
      'Never emits an absolute "Safe" or "100% Secure" guarantee.',
    ],
  };

  const deterministicPayload = {
    scanner_version: CCK_SCANNER_VERSION,
    mode,
    files_discovered: targetFiles.length,
    files_scanned: filesScanned,
    files_skipped_privacy: skippedPrivacy,
    tool_fingerprints: fingerprints,
    canonical_findings: findings.map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      certainty: f.certainty,
      file: f.file,
      location: f.location,
      title: f.title,
      evidence: f.evidence,
    })),
    summary: partialReport.summary,
  };
  const digest = crypto.createHash('sha256').update(JSON.stringify(deterministicPayload)).digest('hex');
  return {
    ...partialReport,
    report_digest_sha256: digest,
  };
}

export function scanReportToSarif(report: ScanReport): Record<string, unknown> {
  const levelMap: Record<ScanSeverity, 'error' | 'warning' | 'note'> = {
    CRITICAL: 'error',
    HIGH: 'error',
    MEDIUM: 'warning',
    LOW: 'note',
    INFO: 'note',
  };

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'cck-scanner',
            version: report.scanner_version,
            informationUri: 'https://github.com/ghazghazibahaeddin-arch/cck',
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.rule_id,
          level: levelMap[f.severity],
          message: { text: `${f.title}: ${f.description} (${f.certainty})` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: 1 },
              },
            },
          ],
          properties: {
            severity: f.severity,
            certainty: f.certainty,
            confidence: f.confidence,
            limitation: f.limitation,
          },
        })),
      },
    ],
  };
}

export function formatScanTerminalSummary(report: ScanReport): string {
  const lines = [
    `CCK Local Scanner v${report.scanner_version} (Mode: ${report.mode}, Static-Only)`,
    `Scan ID: ${report.scan_id} | Digest: ${report.report_digest_sha256.slice(0, 16)}...`,
    `Files Scanned: ${report.files_scanned.length} | Skipped Privacy Files: ${report.files_skipped_privacy.length}`,
    `Tool Fingerprints Computed: ${report.tool_fingerprints.length}`,
    `Summary: ${report.summary.status_statement}`,
  ];
  for (const f of report.findings) {
    lines.push(`  [${f.severity}][${f.certainty}] ${f.rule_id} (${f.file}): ${f.title}`);
  }
  return lines.join('\n');
}

export function sanitizeScanReportForUpload(report: ScanReport): Omit<ScanReport, 'target_path'> & { target_path: string } {
  return {
    ...report,
    target_path: path.basename(report.target_path),
    files_scanned: report.files_scanned.map((f) => path.basename(f)),
    files_skipped_privacy: [],
    findings: report.findings.map((f) => ({
      ...f,
      file: path.basename(f.file),
      evidence: redactEvidenceText(f.evidence),
    })),
  };
}
