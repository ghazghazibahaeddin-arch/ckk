# CCK Hosted Cloud Architecture & Deployment Guide

CCK Cloud is the multi-tenant, hosted enterprise edition of CCK for teams, organizations, and cloud platforms.

---

## 1. Cloud Architecture Overview

- **Storage:** High-availability PostgreSQL database storing actions, audit records, tamper-evident chains, and policies.
- **Tenant Isolation:** Enforced at the query and service boundary using `tenant_id` validation.
- **API Security:** Bearer token authentication, project scoping, and cryptographic webhook signing.
- **Human Approvals:** Central dashboard queue with real-time state drift detection.
- **High Throughput:** Async I/O engine capable of thousands of action evaluations per second.

---

## 2. Running CCK Cloud via Docker Compose

```bash
docker-compose -f docker-compose.cloud.yml up -d
```

### Services Started:
1. `postgres`: PostgreSQL 16 database with persistent storage.
2. `cck-cloud-api`: CCK API configured for PostgreSQL and production guardrails.
3. `cck-dashboard`: Production React Dashboard and governance console.

---

## 3. Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | Environment name | `production` |
| `CCK_DATABASE_URL` | PostgreSQL connection URL | `postgresql://cck:cck_secret@postgres:5432/cck_cloud` |
| `CCK_SHADOW_MODE` | Observe mode flag | `false` |
| `CCK_JWT_SECRET` | Secret key for API authentication | (Required in production) |
| `WEBHOOK_SECRET` | Secret key for HMAC webhook signing | (Required in production) |

---

## 4. Open Source vs Cloud Edition Matrix

| Feature | CCK Open Source (Core) | CCK Cloud (Hosted) |
|---|---|---|
| Reliability Engine & Action Gate | Yes | Yes |
| Data Contracts & Versioning | Yes | Yes |
| Python & TypeScript SDKs | Yes | Yes |
| CLI & MCP Server | Yes | Yes |
| SQLite Local Journal | Yes | Yes |
| Scenarios Testing Lab | Yes | Yes |
| Observe / Shadow Mode | Yes | Yes |
| PostgreSQL Persistent Storage | Community Adapter | Native High-Availability |
| Multi-Tenancy & Project Quotas | Self-hosted | Fully Managed |
| Webhook Notifications & Alerts | Self-hosted | Automated Real-Time |
| Central Web Governance UI | Local UI | Hosted Team Console with SSO |
