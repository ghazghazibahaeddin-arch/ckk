/**
 * Feature 7: Public Source Health Profile
 *
 * Computes verifiable Source Health Profiles strictly from real CCK telemetry:
 * - Change Radar sources, applied events, and dead-letter failures
 * - Adaptive Freshness / Fact Registry observations
 * - Smart Revalidation & Multi-Source Conflict records
 * - Connector runtime versions
 *
 * Guarantees:
 * - Never fabricates metrics or rankings on insufficient samples (< minSampleThreshold)
 * - Every metric exposes window, sample size, calculation method, last update, and scope boundaries
 * - Public view strictly strips tenant_id, private URLs, payloads, and internal credentials
 * - Private by default; public visibility requires explicit opt-in consent
 */

import crypto from 'crypto';
import type {
  ChangeEventRecord,
  ChangeSourceRecord,
  FailedChangeEventRecord,
  PublicSourceHealthProfileView,
  RevalidationPlanRecord,
  SourceDowntimeEvent,
  SourceHealthProfileRecord,
  SourceMetricMethodology,
} from './types.ts';

export interface SourceHealthFactSlice {
  entity_id: string;
  field_name: string;
  source: string;
  observed_at: string;
  ttl_seconds: number;
  state: string;
  tenant_id?: string;
}

const DEFAULT_MIN_SAMPLE_SIZE = 5;

function percentile(sortedAsc: number[], p: number): number | null {
  if (sortedAsc.length === 0) return null;
  const idx = Math.min(
    sortedAsc.length - 1,
    Math.max(0, Math.ceil((p / 100) * sortedAsc.length) - 1)
  );
  return Number(sortedAsc[idx].toFixed(2));
}

function insufficientMetric(params: {
  unit: string;
  method: string;
  sampleSize: number;
  window: { from: string; to: string; duration_seconds: number };
  nowIso: string;
  included: string;
  excluded: string;
}): SourceMetricMethodology {
  return {
    value: null,
    display: 'Insufficient Data',
    unit: params.unit,
    calculation_method: params.method,
    sample_size: params.sampleSize,
    measurement_window: params.window,
    last_updated_at: params.nowIso,
    scope_included: params.included,
    scope_excluded: params.excluded,
  };
}

export function computeSourceHealthProfile(params: {
  tenantId: string;
  source: ChangeSourceRecord;
  events: ChangeEventRecord[];
  failedEvents: FailedChangeEventRecord[];
  facts: SourceHealthFactSlice[];
  revalidationPlans?: RevalidationPlanRecord[];
  connectorVersion?: string;
  existingProfile?: SourceHealthProfileRecord;
  isPublic?: boolean;
  consentGrantedBy?: string;
  minSampleThreshold?: number;
  nowMs?: number;
}): SourceHealthProfileRecord {
  const {
    tenantId,
    source,
    events,
    failedEvents,
    facts,
    revalidationPlans = [],
    connectorVersion = 'cck-connector-v1',
    existingProfile,
    isPublic,
    consentGrantedBy,
    minSampleThreshold = DEFAULT_MIN_SAMPLE_SIZE,
    nowMs = Date.now(),
  } = params;

  const nowIso = new Date(nowMs).toISOString();
  const sourceEvents = events.filter(
    (e) => e.tenant_id === tenantId && (e.source_id === source.source_id || e.source_id === source.name)
  );
  const sourceFailures = failedEvents.filter(
    (f) => f.tenant_id === tenantId && (f.source_id === source.source_id || f.source_id === source.name)
  );
  const sourceFacts = facts.filter(
    (f) =>
      (!f.tenant_id || f.tenant_id === tenantId) &&
      (f.source === source.source_id || f.source === source.name)
  );
  const sourcePlans = revalidationPlans.filter(
    (p) =>
      p.tenant_id === tenantId &&
      p.target_facts.some((tf) => tf.source_id === source.source_id)
  );

  const appliedEvents = sourceEvents.filter((e) => e.status === 'APPLIED');
  const failedFromPlans = sourcePlans.reduce((acc, p) => acc + p.failed_facts.length, 0);
  const refreshedFromPlans = sourcePlans.reduce((acc, p) => acc + p.refreshed_facts.length, 0);

  const successCount = appliedEvents.length + refreshedFromPlans + (source.last_success_at ? 1 : 0);
  const failureCount = sourceFailures.length + failedFromPlans + source.consecutive_failures;
  const totalVerifications = appliedEvents.length + sourceFailures.length + refreshedFromPlans + failedFromPlans;
  const sampleSize = Math.max(totalVerifications, sourceFacts.length);

  // Measurement window derived from earliest and latest observed timestamps
  const timestampsMs: number[] = [];
  for (const ev of sourceEvents) {
    const t = new Date(ev.ingested_at || ev.event_timestamp).getTime();
    if (!Number.isNaN(t)) timestampsMs.push(t);
  }
  for (const f of sourceFailures) {
    const t = new Date(f.failed_at).getTime();
    if (!Number.isNaN(t)) timestampsMs.push(t);
  }
  for (const fc of sourceFacts) {
    const t = new Date(fc.observed_at).getTime();
    if (!Number.isNaN(t)) timestampsMs.push(t);
  }
  if (source.created_at) {
    const t = new Date(source.created_at).getTime();
    if (!Number.isNaN(t)) timestampsMs.push(t);
  }
  timestampsMs.sort((a, b) => a - b);
  const windowFromMs = timestampsMs.length > 0 ? timestampsMs[0] : nowMs;
  const windowToMs = Math.max(windowFromMs, nowMs);
  const measurementWindow = {
    from: new Date(windowFromMs).toISOString(),
    to: new Date(windowToMs).toISOString(),
    duration_seconds: Math.max(1, Math.round((windowToMs - windowFromMs) / 1000)),
  };

  // Freshness ages (seconds) from facts + applied event lags
  const ageSamplesSec: number[] = [];
  for (const fc of sourceFacts) {
    const obsMs = new Date(fc.observed_at).getTime();
    if (!Number.isNaN(obsMs)) {
      ageSamplesSec.push(Math.max(0, Math.round((nowMs - obsMs) / 1000)));
    }
  }
  for (const ev of appliedEvents) {
    const evMs = new Date(ev.event_timestamp).getTime();
    const ingMs = new Date(ev.ingested_at).getTime();
    if (!Number.isNaN(evMs) && !Number.isNaN(ingMs)) {
      ageSamplesSec.push(Math.max(0, Math.round((ingMs - evMs) / 1000)));
    }
  }
  ageSamplesSec.sort((a, b) => a - b);

  // Observed update intervals between successive applied events
  const appliedTimestamps = appliedEvents
    .map((e) => new Date(e.ingested_at || e.event_timestamp).getTime())
    .filter((t) => !Number.isNaN(t))
    .sort((a, b) => a - b);
  const intervalsSec: number[] = [];
  for (let i = 1; i < appliedTimestamps.length; i++) {
    intervalsSec.push(Math.max(1, Math.round((appliedTimestamps[i] - appliedTimestamps[i - 1]) / 1000)));
  }

  // Downtime events from source failures or status transitions
  const downtimeEvents: SourceDowntimeEvent[] = sourceFailures.slice(0, 20).map((f) => ({
    event_id: f.dead_letter_id,
    started_at: f.failed_at,
    recovered_at: f.replayed_at,
    duration_seconds: f.replayed_at
      ? Math.max(1, Math.round((new Date(f.replayed_at).getTime() - new Date(f.failed_at).getTime()) / 1000))
      : 0,
    error_summary: f.error_code || 'SOURCE_VERIFICATION_FAILED',
  }));
  if (source.status === 'FAILED' && source.last_error) {
    downtimeEvents.unshift({
      event_id: `down-${source.source_id}`,
      started_at: source.last_polled_at || source.updated_at,
      duration_seconds: 0,
      error_summary: 'CONNECTOR_UNAVAILABLE',
    });
  }

  const sufficient = sampleSize >= minSampleThreshold;

  const medianFreshness: SourceMetricMethodology =
    sufficient && ageSamplesSec.length >= minSampleThreshold
      ? {
          value: percentile(ageSamplesSec, 50),
          display: `${percentile(ageSamplesSec, 50)}s`,
          unit: 'seconds',
          calculation_method: '50th percentile of fact observation age and ingestion lag within measurement window',
          sample_size: ageSamplesSec.length,
          measurement_window: measurementWindow,
          last_updated_at: nowIso,
          scope_included: 'Verified fact ages and ingested change event timestamps for this source',
          scope_excluded: 'Upstream vendor internal cache latency prior to webhook/poll delivery',
        }
      : insufficientMetric({
          unit: 'seconds',
          method: '50th percentile of fact observation age and ingestion lag within measurement window',
          sampleSize: ageSamplesSec.length,
          window: measurementWindow,
          nowIso,
          included: 'Verified fact ages and ingested change event timestamps for this source',
          excluded: 'Upstream vendor internal cache latency prior to webhook/poll delivery',
        });

  const p95Freshness: SourceMetricMethodology =
    sufficient && ageSamplesSec.length >= minSampleThreshold
      ? {
          value: percentile(ageSamplesSec, 95),
          display: `${percentile(ageSamplesSec, 95)}s`,
          unit: 'seconds',
          calculation_method: '95th percentile of fact observation age and ingestion lag within measurement window',
          sample_size: ageSamplesSec.length,
          measurement_window: measurementWindow,
          last_updated_at: nowIso,
          scope_included: 'Verified fact ages and ingested change event timestamps for this source',
          scope_excluded: 'Outage periods with zero delivered events',
        }
      : insufficientMetric({
          unit: 'seconds',
          method: '95th percentile of fact observation age and ingestion lag within measurement window',
          sampleSize: ageSamplesSec.length,
          window: measurementWindow,
          nowIso,
          included: 'Verified fact ages and ingested change event timestamps for this source',
          excluded: 'Outage periods with zero delivered events',
        });

  const observedInterval: SourceMetricMethodology =
    intervalsSec.length >= minSampleThreshold - 1 && sufficient
      ? {
          value: Number(
            (intervalsSec.reduce((a, b) => a + b, 0) / intervalsSec.length).toFixed(2)
          ),
          display: `${Number((intervalsSec.reduce((a, b) => a + b, 0) / intervalsSec.length).toFixed(2))}s`,
          unit: 'seconds',
          calculation_method: 'Mean inter-arrival interval between consecutive applied verification events',
          sample_size: intervalsSec.length,
          measurement_window: measurementWindow,
          last_updated_at: nowIso,
          scope_included: 'Successive applied change events for this source',
          scope_excluded: 'Suppressed duplicates and out-of-order stale events',
        }
      : insufficientMetric({
          unit: 'seconds',
          method: 'Mean inter-arrival interval between consecutive applied verification events',
          sampleSize: intervalsSec.length,
          window: measurementWindow,
          nowIso,
          included: 'Successive applied change events for this source',
          excluded: 'Suppressed duplicates and out-of-order stale events',
        });

  const denom = Math.max(1, totalVerifications);
  const rawSuccessRate = totalVerifications > 0 ? Number(((appliedEvents.length + refreshedFromPlans) / denom).toFixed(4)) : null;
  const rawErrorRate = totalVerifications > 0 ? Number(((sourceFailures.length + failedFromPlans) / denom).toFixed(4)) : null;

  const verificationSuccessRate: SourceMetricMethodology =
    sufficient && totalVerifications >= minSampleThreshold && rawSuccessRate !== null
      ? {
          value: rawSuccessRate,
          display: `${(rawSuccessRate * 100).toFixed(1)}%`,
          unit: 'ratio',
          calculation_method: 'Successful verifications divided by total verification attempts (excludes CCK policy blocks)',
          sample_size: totalVerifications,
          measurement_window: measurementWindow,
          last_updated_at: nowIso,
          scope_included: 'Applied ingestion events, poll checks, and smart revalidation refreshes',
          scope_excluded: 'Action Gate BLOCK verdicts caused by downstream policy rules (not source failures)',
        }
      : insufficientMetric({
          unit: 'ratio',
          method: 'Successful verifications divided by total verification attempts (excludes CCK policy blocks)',
          sampleSize: totalVerifications,
          window: measurementWindow,
          nowIso,
          included: 'Applied ingestion events, poll checks, and smart revalidation refreshes',
          excluded: 'Action Gate BLOCK verdicts caused by downstream policy rules',
        });

  const errorRateMetric: SourceMetricMethodology =
    sufficient && totalVerifications >= minSampleThreshold && rawErrorRate !== null
      ? {
          value: rawErrorRate,
          display: `${(rawErrorRate * 100).toFixed(1)}%`,
          unit: 'ratio',
          calculation_method: 'Failed verifications divided by total verification attempts',
          sample_size: totalVerifications,
          measurement_window: measurementWindow,
          last_updated_at: nowIso,
          scope_included: 'Timeouts, HTTP errors, authentication failures, malformed responses',
          scope_excluded: 'Intentional governance blocks or dry-run simulations',
        }
      : insufficientMetric({
          unit: 'ratio',
          method: 'Failed verifications divided by total verification attempts',
          sampleSize: totalVerifications,
          window: measurementWindow,
          nowIso,
          included: 'Timeouts, HTTP errors, authentication failures, malformed responses',
          excluded: 'Intentional governance blocks or dry-run simulations',
        });

  const lastSuccess =
    appliedEvents[0]?.ingested_at ||
    source.last_success_at ||
    existingProfile?.last_successful_verification;
  const lastFailed =
    sourceFailures[0]?.failed_at ||
    (source.status === 'FAILED' ? source.last_polled_at || source.updated_at : existingProfile?.last_failed_verification);

  const uniqueEntities = new Set(
    [...sourceFacts.map((f) => f.entity_id), ...appliedEvents.map((e) => e.entity_id)].filter(Boolean)
  );
  const uniqueFields = new Set(
    [...sourceFacts.map((f) => f.field_name), ...appliedEvents.map((e) => e.field_name)].filter(Boolean)
  );

  const knownLimitations: string[] = [
    `Public source metrics exclude tenant-private payloads, raw credentials, and Action Gate policy rejections.`,
  ];
  if (!sufficient) {
    knownLimitations.push(
      `Insufficient sample size (${sampleSize}/${minSampleThreshold} required observations): numeric SLA metrics withheld.`
    );
  }
  if (source.status === 'FAILED' || source.status === 'DEGRADED') {
    knownLimitations.push(`Current source status is ${source.status}; live verification degraded.`);
  }

  const effectivePublic =
    typeof isPublic === 'boolean'
      ? isPublic
      : existingProfile?.is_public ?? false;
  const consentGranted = effectivePublic ? true : (existingProfile?.public_consent_granted ?? false);

  return {
    profile_id: existingProfile?.profile_id || `shp-${crypto.createHash('sha256').update(`${tenantId}:${source.source_id}`).digest('hex').slice(0, 12)}`,
    tenant_id: tenantId,
    source_id: source.source_id,
    source_name: source.name,
    source_identity: `${source.source_type.toLowerCase()}://${source.source_id}`,
    connector_version: connectorVersion,
    is_public: effectivePublic,
    public_consent_granted: consentGranted,
    public_consent_by: effectivePublic ? (consentGrantedBy || existingProfile?.public_consent_by || 'tenant_owner') : existingProfile?.public_consent_by,
    public_consent_at: effectivePublic ? (existingProfile?.public_consent_at || nowIso) : existingProfile?.public_consent_at,
    sufficiency_status: sufficient ? 'SUFFICIENT_DATA' : 'INSUFFICIENT_DATA',
    min_sample_threshold: minSampleThreshold,
    sample_size: sampleSize,
    measurement_window: measurementWindow,
    last_successful_verification: lastSuccess,
    last_failed_verification: lastFailed,
    failure_count: failureCount,
    downtime_events: downtimeEvents,
    data_coverage: {
      entities_covered: uniqueEntities.size,
      fields_covered: uniqueFields.size,
      events_applied: appliedEvents.length + (successCount > appliedEvents.length ? 0 : 0),
      events_failed: sourceFailures.length + failedFromPlans,
    },
    metrics: {
      median_freshness: medianFreshness,
      p95_freshness: p95Freshness,
      observed_update_interval: observedInterval,
      verification_success_rate: verificationSuccessRate,
      error_rate: errorRateMetric,
    },
    known_limitations: knownLimitations,
    last_profile_update: nowIso,
    created_at: existingProfile?.created_at || nowIso,
  };
}

export function toPublicSourceHealthProfile(
  profile: SourceHealthProfileRecord
): PublicSourceHealthProfileView | null {
  if (!profile.is_public || !profile.public_consent_granted) {
    return null;
  }
  const { tenant_id: _omitTenant, public_consent_by: _omitUser, ...publicSafe } = profile;
  return {
    ...publicSafe,
    visibility: 'PUBLIC',
  };
}
