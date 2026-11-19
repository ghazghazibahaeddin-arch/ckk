# CCK Batch 3 — Developer Adoption, Open Connectors, GitHub Distribution & Trust Registry

CCK remains **Decision Integrity Infrastructure**:
- Action Gate verdicts stay `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, and `REVALIDATE`.
- Protected mutations stay **fail-closed**.
- Batch 3 builds verifiable adoption, open connector tooling, CI/CD checks, and cryptographically signed Trust Profiles on top of Batch 1 and Batch 2 engines.

---

## 1. Feature 7 — Public Source Health Profile

- **Engine**: `src/intelligence/source_health.ts`
- **Core Rule**: Metrics are computed strictly from real `ChangeEvent` records, `FailedChangeEvent` records, `FactRecord` ages, and `RevalidationPlan` results.
- **Minimum Sample Threshold**: Requires `>= 5` total verification samples (`INSUFFICIENT_DATA` otherwise, with `value: null` for SLA/rate numbers — never fabricated guesses).
- **Privacy & Consent**: Private-by-default per tenant (`visibility: 'PRIVATE'`, `is_public: false`). Publishing requires explicit operator consent (`PATCH /api/v1/sources/:sourceId/health/visibility` with `{ is_public: true, explicit_consent: true }`). Public views strip `tenant_id` and raw payloads.

## 2. Feature 8 — Connector SDK & 12-Check Test Harness

- **Engine**: `src/intelligence/connector_sdk.ts`
- **Unified Contract**: Declarative `ConnectorManifest` aligned with `src/cck/connectors/interface.py` (`declared_capabilities`, `required_permissions`, `required_secrets_refs`, `network_requirements`, `compatibility_range`).
- **Capability Integrity**: `declared_capabilities` and `harness_verified_capabilities` are stored separately so a connector never gains elevated privilege from self-declaration alone.
- **12 Automated Harness Checks**:
  1. Manifest schema & semantic version
  2. Declared vs harness-verified capabilities
  3. Health check pass/fail handling
  4. Timeout & exponential retry resilience
  5. Rate-limit backoff safety
  6. Auth / token-redacted failure behavior (`credentials_leaked === false`)
  7. Malformed response fail-closed rejection
  8. Conditional write support validation
  9. Compensation / rollback hook check
  10. Secret-safe logging (no secret echo)
  11. Schema validation & fact normalization
  12. Deterministic ingestion compatibility (Facts + Evidence + Change Radar)
- **Sandbox Execution**: Submitted packages are strictly declarative JSON + normalization mappings; arbitrary user code strings are never `eval`'d or executed on the host.

## 3. Feature 18 — One-Command CCK Scanner (`cck scan`)

- **CLI Entry Points**:
  - TypeScript/Node CLI: `npm run cck -- scan [dir] [--format summary|json|sarif|html] [--upload --url <cck-url> --token <token>]`
  - Direct tsx invocation: `npx tsx src/cli/cck.ts scan . --format sarif`
  - Python CLI: `python3 -m cck.cli.main scan [dir] [--format summary|json|sarif|html]`
- **Behavior**:
  - Runs 100% locally and read-only by default (zero network calls, zero login/API key required).
  - Automatically skips `.env*`, `*.pem`, `*.key`, `.git`, `node_modules`, `dist`.
  - Distinguishes `CONFIRMED` findings (plaintext secrets, hardcoded dangerous URLs, overly broad tools) from `POTENTIAL` heuristic findings.
  - Emits valid SARIF v2.1.0, repeatable canonical SHA-256 digests, and HTML/Terminal summaries.
  - Never claims `"Safe"`, `"Fully Secure"`, or `"100% Secure"`.
  - Non-zero exit codes: `2` for `CRITICAL`, `1` for `HIGH`/`MEDIUM`, `0` otherwise.

## 4. Feature 19 — CCK GitHub PR Guardian

- **Engine & CLI**: `src/intelligence/pr_guardian.ts` (`npm run cck -- pr-guard --base <file> --head <file> [--format markdown|json]`)
- **GitHub Action & Workflow**:
  - `.github/actions/cck-pr-guardian/action.yml`
  - `.github/workflows/cck-pr-guardian.yml`
- **Least-Privilege Permissions**:
  - Workflow grants `contents: read` and `security-events: write` only (`pull-requests: read` at job level); never uses `write-all` or unsafe `pull_request_target` execution of untrusted fork code.
- **Verdicts**: `PASS`, `WARNING`, `BLOCKING_FINDING`, `NEEDS_HUMAN_REVIEW`, `INSUFFICIENT_COVERAGE` (never returns a false `PASS` when diff coverage or manifest data is missing/broken).

## 5. Feature 20 — CCK Trust Profile & Public Registry

- **Engine**: `src/intelligence/trust_registry.ts`
- **Cryptographic Proof**: Canonical SHA-256 report digest signed with **Ed25519** (`crypto.sign` / `crypto.verify`).
- **Publisher Ownership**: Explicitly separates `UNVERIFIED_CLAIM` from `VERIFIED_PUBLISHER` (requires HMAC ownership challenge token bound to `{tenantId, artifactIdentity, publisherName}` and prevents cross-tenant hijacking).
- **Pre-Publish DLP Guard (Fail-Closed)**: Blocks `PUBLIC` publication if payloads contain API keys, `tenant_*` identifiers, localhost/metadata IPs (`169.254.169.254`), SSNs, or emails (`400 PUBLIC_DATA_LEAKAGE_BLOCKED`).
- **Anti-Claim Guard**: Rejects absolute guarantees (`"Safe"`, `"100% Safe"`, `"Fully Secure"`, `"Zero Risk"`).
- **Lifecycle & Badges**: Dynamic SVG badges (`GET /api/v1/trust/profiles/:id/badge.svg`) reflect `VERIFIED_FOR_A_DEFINED_SCOPE`, `REVIEW_REQUIRED`, `SUPERSEDED`, `EXPIRED`, and `REVOKED` automatically.

## 6. REST Endpoints Summary

- `GET/POST /api/v1/sources/health`, `POST /api/v1/sources/health/recompute`
- `PATCH /api/v1/sources/:sourceId/health/visibility`
- `GET /api/v1/public/sources/health`, `GET /api/v1/public/sources/health/:sourceId`
- `POST /api/v1/connectors/harness/run`, `GET /api/v1/connectors/harness/reports`
- `POST/GET /api/v1/connectors/submissions`, `POST /api/v1/connectors/submissions/:id/consume-ingest`
- `POST/GET /api/v1/scanner/reports`
- `POST/GET /api/v1/pr-guardian/evaluate`, `GET /api/v1/pr-guardian/reports`
- `POST /api/v1/trust/publisher-challenge`, `POST/GET /api/v1/trust/profiles`
- `POST /api/v1/trust/profiles/:id/revoke`
- `GET /api/v1/trust/registry`, `GET/POST /api/v1/public/trust/profiles/:id`
- `GET /api/v1/trust/profiles/:id/badge.svg`
- `GET/POST /api/v1/analytics/adoption`, `POST /api/v1/analytics/events`, `PUT /api/v1/analytics/privacy-settings`
