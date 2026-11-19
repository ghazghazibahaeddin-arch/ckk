#!/usr/bin/env node
/**
 * CCK Command Line Interface (Node/TypeScript)
 *
 * Commands:
 * - cck scan [path] [--format summary|json|sarif|html] [--out file] [--fail-on CRITICAL|HIGH|MEDIUM] [--upload --base-url URL]
 * - cck pr-guard --base-tools base.json --head-tools head.json [--repo name] [--base-sha sha] [--head-sha sha] [--fail-on CRITICAL|HIGH]
 * - cck connector-test <manifest.json> [--out report.json]
 *
 * Guarantees:
 * - ZERO account / login required for `scan`, `pr-guard`, or `connector-test`
 * - Local Read-Only by default (0 external network calls unless --upload is explicitly passed)
 */

import fs from 'fs';
import path from 'path';
import {
  formatScanTerminalSummary,
  sanitizeScanReportForUpload,
  scanLocalDirectory,
  scanReportToSarif,
} from '../intelligence/scanner.ts';
import { evaluatePullRequestGuardian, type PrToolSnapshotEntry } from '../intelligence/pr_guardian.ts';
import {
  createDeclarativeSdkConnector,
  runConnectorTestHarness,
} from '../intelligence/connector_sdk.ts';
import type { ConnectorManifest, ScanSeverity } from '../intelligence/types.ts';

function parseArgs(argv: string[]): { positional: string[]; flags: Record<string, string | boolean> } {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function renderHtmlReport(jsonReport: ReturnType<typeof scanLocalDirectory>): string {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const rows = jsonReport.findings
    .map(
      (f) =>
        `<tr><td>${esc(f.severity)}</td><td>${esc(f.certainty)}</td><td><code>${esc(f.rule_id)}</code></td><td>${esc(f.file)}</td><td>${esc(f.title)}</td><td>${esc(f.recommendation)}</td></tr>`
    )
    .join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CCK Scan Report ${esc(jsonReport.scan_id)}</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#0f172a}table{width:100%;border-collapse:collapse;margin-top:1rem}th,td{border:1px solid #cbd5e1;padding:.5rem;text-align:left;font-size:.875rem}th{background:#f1f5f9}</style>
</head><body>
<h1>CCK Static Configuration Scan</h1>
<p><strong>Scan ID:</strong> ${esc(jsonReport.scan_id)} &middot; <strong>Mode:</strong> ${esc(jsonReport.mode)} &middot; <strong>Digest:</strong> <code>${esc(jsonReport.report_digest_sha256)}</code></p>
<p>${esc(jsonReport.summary.status_statement)}</p>
<table><thead><tr><th>Severity</th><th>Certainty</th><th>Rule</th><th>File</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table>
</body></html>`;
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const { positional, flags } = parseArgs(args.slice(1));

  if (!command || command === '--help' || command === 'help') {
    console.log(
      [
        'CCK CLI — Decision Integrity Infrastructure',
        '',
        'Usage:',
        '  cck scan [targetDir] [--format summary|json|sarif|html] [--out path] [--fail-on CRITICAL|HIGH|MEDIUM] [--upload --base-url URL]',
        '  cck pr-guard --base-tools base.json --head-tools head.json [--repo owner/repo] [--fail-on CRITICAL|HIGH]',
        '  cck connector-test <manifest.json> [--out report.json]',
      ].join('\n')
    );
    process.exit(0);
  }

  if (command === 'scan') {
    const target = positional[0] || '.';
    const format = String(flags.format || 'summary').toLowerCase();
    const failOn = (String(flags['fail-on'] || 'HIGH').toUpperCase() as ScanSeverity) || 'HIGH';
    const doUpload = Boolean(flags.upload);
    const mode = doUpload ? 'UPLOAD_SANITIZED' : 'LOCAL';

    const report = scanLocalDirectory({
      targetPath: target,
      mode,
      uploadedToCloud: false,
      failOnSeverity: failOn,
    });

    if (doUpload && typeof flags['base-url'] === 'string') {
      const sanitized = sanitizeScanReportForUpload(report);
      try {
        const res = await fetch(`${flags['base-url'].replace(/\/$/, '')}/api/v1/scanner/reports`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ report: sanitized, consent_upload: true }),
        });
        if (res.ok) {
          report.uploaded_to_cloud = true;
        }
      } catch {
        // Upload failure never aborts local scan results
      }
    }

    let outputText = '';
    if (format === 'json') {
      outputText = JSON.stringify(report, null, 2);
    } else if (format === 'sarif') {
      outputText = JSON.stringify(scanReportToSarif(report), null, 2);
    } else if (format === 'html') {
      outputText = renderHtmlReport(report);
    } else {
      outputText = formatScanTerminalSummary(report);
    }

    if (typeof flags.out === 'string') {
      fs.writeFileSync(path.resolve(flags.out), outputText, 'utf-8');
    }
    console.log(outputText);
    process.exit(report.summary.recommended_exit_code);
  }

  if (command === 'pr-guard') {
    const repo = String(flags.repo || process.env.GITHUB_REPOSITORY || 'local/repo');
    const baseSha = String(flags['base-sha'] || process.env.GITHUB_BASE_REF || 'base0000');
    const headSha = String(flags['head-sha'] || process.env.GITHUB_SHA || 'head0000');
    const failOn = (String(flags['fail-on'] || 'CRITICAL').toUpperCase() === 'HIGH' ? 'HIGH' : 'CRITICAL') as 'CRITICAL' | 'HIGH';
    const changedFiles =
      typeof flags['changed-files'] === 'string'
        ? flags['changed-files'].split(',').map((s) => s.trim()).filter(Boolean)
        : [];

    let coverageOk = true;
    const readSnapshotList = (p?: string | boolean): PrToolSnapshotEntry[] => {
      if (typeof p !== 'string') return [];
      try {
        const raw = JSON.parse(fs.readFileSync(path.resolve(p), 'utf-8'));
        return Array.isArray(raw) ? raw : Array.isArray(raw.tools) ? raw.tools.map((t: Record<string, unknown>) => ({ file: p, tool: t })) : [];
      } catch {
        coverageOk = false;
        return [];
      }
    };

    const baseTools = readSnapshotList(flags['base-tools']);
    const headTools = readSnapshotList(flags['head-tools']);

    const report = evaluatePullRequestGuardian({
      repository: repo,
      baseSha,
      headSha,
      changedFiles: changedFiles.length > 0 ? changedFiles : [...baseTools.map((b) => b.file), ...headTools.map((h) => h.file)],
      baseTools,
      headTools,
      coverageAvailable: coverageOk,
      failOnSeverity: failOn,
    });

    if (typeof flags.out === 'string') {
      fs.writeFileSync(path.resolve(flags.out), JSON.stringify(report, null, 2), 'utf-8');
    }
    if (String(flags.format || 'json').toLowerCase() === 'markdown') {
      console.log(report.markdown_summary);
    } else {
      console.log(JSON.stringify(report, null, 2));
    }
    process.exit(report.merge_blocked ? 1 : 0);
  }

  if (command === 'connector-test') {
    const manifestPath = positional[0];
    if (!manifestPath) {
      console.error('Usage: cck connector-test <manifest.json>');
      process.exit(2);
    }
    const manifest = JSON.parse(fs.readFileSync(path.resolve(manifestPath), 'utf-8')) as ConnectorManifest;
    const connector = createDeclarativeSdkConnector({ manifest });
    const report = await runConnectorTestHarness({ connector, tenantId: 'local_cli_harness' });
    const text = JSON.stringify(report, null, 2);
    if (typeof flags.out === 'string') {
      fs.writeFileSync(path.resolve(flags.out), text, 'utf-8');
    }
    console.log(text);
    process.exit(report.passed ? 0 : 1);
  }

  console.error(`Unknown CCK command: ${command}`);
  process.exit(2);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(2);
});
