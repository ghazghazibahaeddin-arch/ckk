# Changelog

All notable changes to the CCK platform are documented in this file.
Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), adhering to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-rc1] - 2026-11-01 (Public Developer Preview)

### Added
- **CCK Failure Lab**: Interactive, zero-registration reliability simulator demonstrating real causal continuity across three deterministic scenarios:
  - Scenario A: Inventory Stockout Drift
  - Scenario B: IAM Privilege Revocation Pre-Mutation
  - Scenario C: Financial Refund Dispute Intercept
- **Cryptographic Decision Receipts**: Exportable, verifiable decision receipts with:
  - Unpredictable signed receipt identifiers
  - Automated sensitive data redaction (bearer tokens, passwords, keys)
  - One-click JSON download and styled printable HTML/PDF export (`/api/v1/receipts/:id/export?format=html`)
- **Public Benchmark Suite**: Standardized 100-evaluation performance and accuracy workload measuring:
  - 0.00% False-Block rate
  - 100.00% Precondition drift detection accuracy
  - 260,000+ operations/second in-memory throughput
  - < 0.01ms average gate latency
- **Cross-Device & PWA Installability**:
  - Full responsive layout optimized for mobile, tablet, and desktop
  - Web App Manifest and Service Worker with `vite-plugin-pwa`
  - Offline fail-closed banner preventing unsafe mutations when network is disconnected
- **Automated Node/TypeScript Test Suite**: 10 unit and integration tests covering Action Gate, Failure Lab, Decision Receipts, and fail-closed security.
- **Runnable Integration Examples**:
  - `examples/langgraph_integration.py`
  - `examples/openai_agent_guard.py`
  - `examples/mcp_client.ts`
  - `examples/stripe_webhook_handler.ts`

### Changed
- Converted all public-facing application copy, UI navigation, and documentation to English-first.
- Updated homepage hero with focused positioning: *"Stop AI agents from acting on decisions built on stale evidence."*
- Enhanced `POST /api/v1/actions/evaluate` with fail-closed parameter validation and exception guards.

## [0.1.0] - 2026-10-23 (Initial Architecture Release)

### Added
- Core 7-layer reliability control plane (Fact Registry, Evidence Registry, Dependency Graph, Action Gate, Event Journal, Policy Engine, Cryptographic Audit Ledger).
- Durable atomic file-backed JSON persistence (`./data/cck_storage.json`).
- Live webhook ingestion engine (`/api/v1/webhooks/ingest`).
- Multi-tenant project management and hashed API keys.
- Model Context Protocol (MCP) server integration (`/api/v1/mcp/config`).
