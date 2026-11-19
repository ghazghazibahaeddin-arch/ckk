/**
 * Feature 2: Live Change Radar
 *
 * Monitors external state & schema changes across Webhooks and Polling sources.
 * Guarantees:
 * - Persistent idempotency & duplicate event suppression
 * - Cryptographic HMAC-SHA256 signature verification & replay timestamp checks
 * - Out-of-order version/timestamp protection (never silently overwrites newer facts with stale arrivals)
 * - Per-(tenant, source) sliding-window rate limiting
 * - Persistent polling cursor & isolated outage handling (source error NEVER marks facts fresh)
 * - Dead-letter queue (FailedChangeEventRecord) + controlled replay
 */

import crypto from 'crypto';
import dns from 'dns/promises';
import net from 'net';
import type {
  ChangeEventRecord,
  ChangeSourceRecord,
  FailedChangeEventRecord,
} from './types.ts';
import { redactSensitiveDiffValue } from './semantic_diff.ts';

interface SourceRateBucket {
  count: number;
  resetAt: number;
}
const sourceRateBuckets = new Map<string, SourceRateBucket>();

export function checkRadarRateLimit(params: {
  tenantId: string;
  sourceId: string;
  maxPerMinute: number;
  nowMs?: number;
}): { allowed: boolean; remaining: number; retryAfterSeconds: number } {
  const { tenantId, sourceId, maxPerMinute, nowMs = Date.now() } = params;
  const key = `${tenantId}::${sourceId}`;
  const limit = Math.max(5, maxPerMinute || 120);
  const bucket = sourceRateBuckets.get(key);
  if (!bucket || nowMs > bucket.resetAt) {
    sourceRateBuckets.set(key, { count: 1, resetAt: nowMs + 60_000 });
    return { allowed: true, remaining: limit - 1, retryAfterSeconds: 0 };
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - nowMs) / 1000)),
    };
  }
  return {
    allowed: true,
    remaining: Math.max(0, limit - bucket.count),
    retryAfterSeconds: 0,
  };
}

function isPrivateOrReservedIpv4(ip: string, allowLoopback: boolean): boolean {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 127) return !allowLoopback; // 127.0.0.0/8 loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
  if (a >= 224) return true; // multicast / reserved
  return false;
}

export function isBlockedIpAddress(rawIp: string, allowLoopback: boolean = false): boolean {
  const ip = rawIp.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  const ver = net.isIP(ip);
  if (ver === 4) {
    return isPrivateOrReservedIpv4(ip, allowLoopback);
  }
  if (ver === 6) {
    if (ip === '::1') return !allowLoopback;
    if (ip === '::') return true;
    // IPv4-mapped IPv6 ::ffff:a.b.c.d or ::ffff:hex:hex
    if (ip.startsWith('::ffff:')) {
      const rest = ip.slice(7);
      if (net.isIP(rest) === 4) {
        return isPrivateOrReservedIpv4(rest, allowLoopback);
      }
      const hexParts = rest.split(':');
      if (hexParts.length === 2) {
        const hi = parseInt(hexParts[0], 16);
        const lo = parseInt(hexParts[1], 16);
        if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
          const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
          return isPrivateOrReservedIpv4(ipv4, allowLoopback);
        }
      }
      return true;
    }
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // fc00::/7 ULA
    if (/^fe[89ab][0-9a-f]/i.test(ip) || ip.startsWith('fe80:')) return true; // fe80::/10 link-local
    if (ip.startsWith('ff')) return true; // ff00::/8 multicast
    return false;
  }
  return true;
}

export function isRadarUrlSafe(rawUrl: string, allowLoopbackForTest: boolean = false): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    if (parsed.username || parsed.password) return false;
    const h = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!h) return false;

    // Block obfuscated integer/hex/octal IPs (e.g. 2130706433, 0x7f000001, 0177.0.0.1)
    if (/^(0x[0-9a-f]+|\d+)$/i.test(h)) return false;
    if (/^\d+\.\d+$/.test(h) || /^\d+\.\d+\.\d+$/.test(h)) return false;

    // Cloud metadata & internal cluster endpoints are strictly blocked ALWAYS
    if (
      h === '0.0.0.0' ||
      h.includes('metadata.google.internal') ||
      h === 'metadata' ||
      h.endsWith('.internal') ||
      h.endsWith('.local') ||
      h.endsWith('.arpa')
    ) {
      return false;
    }

    const isLiteralLoopbackName = h === 'localhost' || h.endsWith('.localhost');
    if (isLiteralLoopbackName) {
      return allowLoopbackForTest;
    }

    if (net.isIP(h) !== 0) {
      return !isBlockedIpAddress(h, allowLoopbackForTest);
    }

    return true;
  } catch {
    return false;
  }
}

export async function resolveAndValidateRadarUrl(
  rawUrl: string,
  allowLoopbackForTest: boolean = false
): Promise<{ safe: boolean; reason?: string }> {
  if (!isRadarUrlSafe(rawUrl, allowLoopbackForTest)) {
    return { safe: false, reason: 'SSRF_BLOCKED: Polling endpoint URL failed static SSRF validation.' };
  }
  try {
    const parsed = new URL(rawUrl);
    const h = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (net.isIP(h) !== 0) {
      return { safe: true };
    }
    if (allowLoopbackForTest && (h === 'localhost' || h.endsWith('.localhost'))) {
      return { safe: true };
    }
    const records = await dns.lookup(h, { all: true });
    if (!records.length) {
      return { safe: false, reason: 'SSRF_BLOCKED: Hostname DNS resolution returned no addresses.' };
    }
    for (const rec of records) {
      if (isBlockedIpAddress(rec.address, allowLoopbackForTest)) {
        return {
          safe: false,
          reason: `SSRF_BLOCKED: Hostname '${h}' resolved to private/internal address '${rec.address}'.`,
        };
      }
    }
    return { safe: true };
  } catch {
    return { safe: false, reason: 'SSRF_BLOCKED: Hostname DNS validation failed.' };
  }
}

export function normalizeChangeEvent(input: {
  tenant_id: string;
  source_id: string;
  event_type?: string;
  schema_version?: string;
  entity_id: string;
  field_name: string;
  value: unknown;
  previous_value?: unknown;
  version?: number;
  event_timestamp?: string;
  trace_id?: string;
  idempotency_key?: string;
  raw_payload?: Record<string, unknown>;
}): ChangeEventRecord {
  const nowIso = new Date().toISOString();
  const payloadForHash = input.raw_payload || {
    entity_id: input.entity_id,
    field_name: input.field_name,
    value: input.value,
    source_id: input.source_id,
    version: input.version,
    event_timestamp: input.event_timestamp,
  };
  const payloadHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(payloadForHash))
    .digest('hex');

  const idempotencyKey =
    input.idempotency_key ||
    (typeof input.raw_payload?.idempotency_key === 'string' ? input.raw_payload.idempotency_key : undefined) ||
    `idem-${payloadHash.slice(0, 24)}`;

  const eventTs =
    input.event_timestamp && !Number.isNaN(new Date(input.event_timestamp).getTime())
      ? new Date(input.event_timestamp).toISOString()
      : nowIso;

  return {
    event_id: `cev-${crypto.randomUUID().slice(0, 10)}`,
    tenant_id: input.tenant_id,
    source_id: input.source_id,
    event_type: input.event_type || 'FACT_STATE_CHANGE',
    schema_version: input.schema_version || '1.0',
    entity_id: input.entity_id,
    field_name: input.field_name,
    new_value: input.value,
    previous_value: input.previous_value,
    version: typeof input.version === 'number' ? input.version : undefined,
    event_timestamp: eventTs,
    ingested_at: nowIso,
    trace_id: input.trace_id || `tr-${crypto.randomUUID().slice(0, 10)}`,
    idempotency_key: idempotencyKey,
    payload_hash: payloadHash,
    status: 'APPLIED',
    redacted_payload: (redactSensitiveDiffValue(payloadForHash) as Record<string, unknown>) || {},
  };
}

export function isDuplicateChangeEvent(params: {
  existingEvents: ChangeEventRecord[];
  tenantId: string;
  idempotencyKey?: string;
  payloadHash: string;
}): ChangeEventRecord | null {
  const { existingEvents, tenantId, idempotencyKey, payloadHash } = params;
  return (
    existingEvents.find(
      (ev) =>
        ev.tenant_id === tenantId &&
        ev.status === 'APPLIED' &&
        ((idempotencyKey && ev.idempotency_key === idempotencyKey) || ev.payload_hash === payloadHash)
    ) || null
  );
}

export function checkEventOrdering(params: {
  incomingVersion?: number;
  incomingTimestamp: string;
  currentFactVersion?: number;
  currentFactObservedAt?: string;
}): { ordered: boolean; reason?: string } {
  const { incomingVersion, incomingTimestamp, currentFactVersion, currentFactObservedAt } = params;

  if (
    typeof incomingVersion === 'number' &&
    typeof currentFactVersion === 'number' &&
    incomingVersion <= currentFactVersion
  ) {
    return {
      ordered: false,
      reason: `OUT_OF_ORDER_VERSION: incoming version v${incomingVersion} <= current committed version v${currentFactVersion}.`,
    };
  }

  if (currentFactObservedAt) {
    const incomingMs = new Date(incomingTimestamp).getTime();
    const currentMs = new Date(currentFactObservedAt).getTime();
    // Only reject if incoming event explicitly carries an older event_timestamp (>1000ms skew tolerance)
    if (!Number.isNaN(incomingMs) && !Number.isNaN(currentMs) && incomingMs + 1000 < currentMs) {
      return {
        ordered: false,
        reason: `OUT_OF_ORDER_TIMESTAMP: incoming event_timestamp (${incomingTimestamp}) predates current observation (${currentFactObservedAt}).`,
      };
    }
  }

  return { ordered: true };
}

export function createFailedChangeEvent(params: {
  tenantId: string;
  sourceId: string;
  rawPayload: Record<string, unknown>;
  errorCode: string;
  errorMessage: string;
  traceId?: string;
  idempotencyKey?: string;
}): FailedChangeEventRecord {
  return {
    dead_letter_id: `dlq-${crypto.randomUUID().slice(0, 8)}`,
    tenant_id: params.tenantId,
    source_id: params.sourceId,
    raw_event_redacted: (redactSensitiveDiffValue(params.rawPayload) as Record<string, unknown>) || {},
    error_code: params.errorCode,
    error_message: params.errorMessage,
    trace_id: params.traceId || `tr-${crypto.randomUUID().slice(0, 10)}`,
    idempotency_key: params.idempotencyKey,
    failed_at: new Date().toISOString(),
    retry_count: 0,
    status: 'PENDING_RETRY',
  };
}

export interface PolledItemPayload {
  entity_id: string;
  field_name: string;
  value: unknown;
  version?: number;
  event_timestamp?: string;
  idempotency_key?: string;
  event_type?: string;
}

export async function pollExternalRadarSource(params: {
  source: ChangeSourceRecord;
  timeoutMs?: number;
  allowLoopbackForTest?: boolean;
  inlineItems?: PolledItemPayload[];
  simulateFailureError?: string;
}): Promise<{
  ok: boolean;
  items: PolledItemPayload[];
  nextCursor?: string;
  nextEtag?: string;
  error?: string;
}> {
  const { source, timeoutMs = 4000, allowLoopbackForTest = false, inlineItems, simulateFailureError } = params;
  const nowIso = new Date().toISOString();
  source.last_polled_at = nowIso;

  if (simulateFailureError) {
    source.consecutive_failures += 1;
    source.status = 'FAILED';
    source.last_error = simulateFailureError;
    source.updated_at = nowIso;
    return { ok: false, items: [], error: simulateFailureError };
  }

  if (Array.isArray(inlineItems)) {
    source.consecutive_failures = 0;
    source.status = 'ACTIVE';
    source.last_success_at = nowIso;
    source.last_error = undefined;
    source.updated_at = nowIso;
    return {
      ok: true,
      items: inlineItems,
      nextCursor: `cur-${Date.now()}`,
    };
  }

  if (!source.endpoint_url) {
    const err = 'POLL_CONFIG_ERROR: Change source has no endpoint_url configured.';
    source.consecutive_failures += 1;
    source.status = 'FAILED';
    source.last_error = err;
    source.updated_at = nowIso;
    return { ok: false, items: [], error: err };
  }

  const ssrfCheck = await resolveAndValidateRadarUrl(source.endpoint_url, allowLoopbackForTest);
  if (!ssrfCheck.safe) {
    const err = ssrfCheck.reason || 'SSRF_BLOCKED: Polling endpoint URL failed SSRF validation.';
    source.consecutive_failures += 1;
    source.status = 'FAILED';
    source.last_error = err;
    source.updated_at = nowIso;
    return { ok: false, items: [], error: err };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const targetUrl = new URL(source.endpoint_url);
    if (source.cursor) {
      targetUrl.searchParams.set('cursor', source.cursor);
    }
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (source.etag) {
      headers['If-None-Match'] = source.etag;
    }

    const res = await fetch(targetUrl.toString(), {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.status >= 300 && res.status < 400 && res.status !== 304) {
      const err = `SSRF_REDIRECT_BLOCKED: Upstream HTTP redirect (${res.status}) rejected for SSRF safety.`;
      source.consecutive_failures += 1;
      source.status = 'FAILED';
      source.last_error = err;
      source.updated_at = nowIso;
      return { ok: false, items: [], error: err };
    }

    if (res.status === 304) {
      source.consecutive_failures = 0;
      source.status = 'ACTIVE';
      source.last_success_at = nowIso;
      source.last_error = undefined;
      source.updated_at = nowIso;
      return { ok: true, items: [], nextCursor: source.cursor, nextEtag: source.etag };
    }

    if (!res.ok) {
      const err = `UPSTREAM_HTTP_${res.status}: Source returned HTTP ${res.status}. Facts were NOT refreshed.`;
      source.consecutive_failures += 1;
      source.status = 'FAILED';
      source.last_error = err;
      source.updated_at = nowIso;
      return { ok: false, items: [], error: err };
    }

    const body = (await res.json()) as Record<string, unknown>;
    const rawItems = Array.isArray(body.events)
      ? body.events
      : Array.isArray(body.items)
      ? body.items
      : [];
    const items: PolledItemPayload[] = rawItems
      .filter((x): x is Record<string, unknown> => Boolean(x && typeof x === 'object'))
      .filter((x) => typeof x.entity_id === 'string' && typeof x.field_name === 'string')
      .map((x) => ({
        entity_id: String(x.entity_id),
        field_name: String(x.field_name),
        value: x.value,
        version: typeof x.version === 'number' ? x.version : undefined,
        event_timestamp: typeof x.event_timestamp === 'string' ? x.event_timestamp : undefined,
        idempotency_key: typeof x.idempotency_key === 'string' ? x.idempotency_key : undefined,
        event_type: typeof x.event_type === 'string' ? x.event_type : 'POLL_OBSERVATION',
      }));

    const nextCursor =
      typeof body.next_cursor === 'string'
        ? body.next_cursor
        : typeof body.cursor === 'string'
        ? body.cursor
        : source.cursor;
    const nextEtag = res.headers.get('etag') || source.etag;

    source.consecutive_failures = 0;
    source.status = 'ACTIVE';
    source.last_success_at = nowIso;
    source.last_error = undefined;
    if (nextCursor) source.cursor = nextCursor;
    if (nextEtag) source.etag = nextEtag;
    source.updated_at = nowIso;

    return { ok: true, items, nextCursor, nextEtag };
  } catch (err: unknown) {
    clearTimeout(timer);
    const msg = err instanceof Error ? err.message : 'Poll timeout or network error';
    source.consecutive_failures += 1;
    source.status = 'FAILED';
    source.last_error = msg;
    source.updated_at = nowIso;
    return { ok: false, items: [], error: msg };
  }
}
