/**
 * Batch 3: Privacy-Respecting Growth & Adoption Analytics
 *
 * Measures developer adoption metrics cleanly without tracking source code,
 * prompts, credentials, payloads, or hidden telemetry. Respects explicit opt-out.
 */

import type { AdoptionAnalyticsRecord } from './types.ts';

export type AdoptionEventType =
  | 'CLI_SCAN'
  | 'LOCAL_TO_INTEGRATION'
  | 'GITHUB_GUARDIAN_INSTALL'
  | 'REPORT_PUBLISHED'
  | 'REPORT_SHARED'
  | 'NEW_DEV_FROM_SHARE'
  | 'CONNECTOR_SUBMITTED'
  | 'CONNECTOR_VERIFIED'
  | 'REPEATED_USAGE';

export function recordAdoptionEvent(params: {
  analytics: AdoptionAnalyticsRecord;
  eventType: AdoptionEventType;
  activeProjectsCount?: number;
  hasAttributionConsent?: boolean;
}): { recorded: boolean; analytics: AdoptionAnalyticsRecord } {
  const { analytics, eventType, activeProjectsCount, hasAttributionConsent } = params;
  if (typeof activeProjectsCount === 'number') {
    analytics.active_projects_count = activeProjectsCount;
  }

  if (!analytics.analytics_enabled) {
    return { recorded: false, analytics };
  }

  const nowIso = new Date().toISOString();
  switch (eventType) {
    case 'CLI_SCAN':
      analytics.cli_scans += 1;
      break;
    case 'LOCAL_TO_INTEGRATION':
      analytics.local_to_integration_conversions += 1;
      break;
    case 'GITHUB_GUARDIAN_INSTALL':
      analytics.github_guardian_installations += 1;
      break;
    case 'REPORT_PUBLISHED':
      analytics.published_reports += 1;
      break;
    case 'REPORT_SHARED':
      analytics.report_shares += 1;
      break;
    case 'NEW_DEV_FROM_SHARE':
      if (hasAttributionConsent) {
        analytics.new_devs_from_shared_reports += 1;
      } else {
        return { recorded: false, analytics };
      }
      break;
    case 'CONNECTOR_SUBMITTED':
      analytics.connector_submissions += 1;
      break;
    case 'CONNECTOR_VERIFIED':
      analytics.verified_connector_versions += 1;
      break;
    case 'REPEATED_USAGE':
      analytics.repeated_usage_events += 1;
      break;
  }
  analytics.last_event_at = nowIso;
  return { recorded: true, analytics };
}
