# CCK — Command & Control Kit
### Agent Reliability & Causal Continuity Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![Architecture: Modular Monolith](https://img.shields.io/badge/Architecture-Modular%20Monolith-emerald)](docs/architecture.md)
[![Zero-Bypass Policy](https://img.shields.io/badge/Zero--Bypass-Enforced-success)](src/cck/reliability/action_gate.py)

---

## 📌 Overview: What is CCK?

**CCK (Command & Control Kit)** is an **Agent Reliability and Causal Continuity Platform**. It acts as a sovereign governance and execution control layer that prevents autonomous AI agents from performing irreversible real-world mutations (database writes, HTTP requests, cloud infrastructure calls, shell commands) based on facts or evidence that have become **stale, invalid, contradictory, or unsafe**.

### The Core Problem: Fact Drift & Hallucinated Mutations
Autonomous LLM agents maintain decisions inside volatile context windows. When an agent reads an external record (e.g., *Order #1099 is paid and ready for shipment*), external reality often shifts before or during execution (e.g., *the customer initiates a chargeback or refund*). Because the LLM context remains unaware of this drift, the agent erroneously dispatches courier parcels or mutates production records.

**CCK solves this by enforcing causal continuity between:**
1. **Entities & Real-World Resources**: Identifiable domain models tracked across systems.
2. **Grounded Facts & Evidence**: Facts verified by cryptographic SHA-256 evidence tokens with TTL timestamps.
3. **Dependency Preconditions**: Deterministic rules binding protected action capabilities to required fact states.
4. **Zero-Bypass Action Gate**: Enforced policy gate returning explicit verdicts (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `REVALIDATE`).
5. **Cryptographic Audit Ledger**: Immutable SHA-256 Merkle-linked hash chain recording every decision and execution outcome.

---

## 🏛️ The 7 CCK Architecture Layers

```
                               ┌──────────────────────────────────────────────┐
                               │       Autonomous Agent / LLM Client          │
                               └──────────────────────┬───────────────────────┘
                                                      │
                       ┌──────────────────────────────▼──────────────────────────────┐
                       │                   CCK Control Plane Gateway                 │
                       │             (FastAPI / Express Gateway / MCP Server)        │
                       └──────────────────────────────┬──────────────────────────────┘
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         │                                            │                                            │
┌────────▼──────────────┐             ┌───────────────▼───────────────┐            ┌───────────────▼───────────────┐
│  Layer 1: Reliability │             │   Layer 3: Control & Policy   │            │   Layer 4: Audit & Recovery   │
│  - Entity Registry    │             │   - POL-SEC Rules Engine      │            │   - SHA-256 Hash Ledger       │
│  - Grounded Facts     │             │   - Blast Radius Rate Limits  │            │   - Decision Replay Engine    │
│  - Evidence Minting   │             │   - Human Approval Workflows  │            │   - Compensation Rollback     │
│  - Action Gate (Eval) │             │   - Multi-Tenant RBAC         │            │   - Observability & Tracing   │
└────────┬──────────────┘             └───────────────┬───────────────┘            └───────────────┬───────────────┘
         │                                            │                                            │
         └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                      │
                                      ┌───────────────▼───────────────┐
                                      │  Layer 2: Execution Adapters  │
                                      │  - Zero-Bypass Connector Gate │
                                      │  - CAS (Conditional Writes)   │
                                      │  - Idempotency Deduplication  │
                                      └───────────────┬───────────────┘
                                                      │
                               ┌──────────────────────▼───────────────────────┐
                               │           External Real-World Target         │
                               │   (Databases, Stripe, FedEx, Cloud Infra)   │
                               └──────────────────────────────────────────────┘
```

1. **Layer 1: Core Reliability Engine** — Entity and Fact registries, Evidence token hashing, Freshness tracking, and Action Gate precondition checks.
2. **Layer 2: Execution Adapters & Connectors** — Isolating agents from raw APIs. Supports Conditional Writes (Compare-And-Swap), Compensation rollbacks, and secret sanitation.
3. **Layer 3: Control Plane & Governance** — Active security policies (`POL-SEC`), blast-radius limits, human supervisor review queues, and multi-tenant project isolation.
4. **Layer 4: Audit, Observability & Recovery** — Cryptographically chained SHA-256 event ledger, automated decision replay, and impact analysis.
5. **Layer 5: Testing & Fault Injection Lab** — CLI scenarios runner (`cck test ./scenarios`), network timeout simulation, and non-destructive replay.
6. **Layer 6: Integrations & Developer Platform** — Model Context Protocol (MCP) server, native Python and TypeScript SDKs, and REST API endpoints.
7. **Layer 7: Multi-Tenancy & Enterprise Cloud** — Tenant workspace boundaries, SQLite WAL mode for local high-performance operations, and documented PostgreSQL enterprise schema.

---

## 🚀 Quickstart & Local Installation

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Python**: v3.10, v3.11, or v3.12 (optional for standalone CLI)
- **Git**

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ghazghazibahaeddin-arch/cck.git
cd cck

# 2. Install dependencies
npm install

# 3. Start the Full-Stack Developer Console & API Gateway
npm run dev
```

The web console and API server will be available at:
- **Web SaaS Console**: [http://localhost:3000](http://localhost:3000)
- **API Health Check**: [http://localhost:3000/health](http://localhost:3000/health)
- **System Metrics & Audit Status**: [http://localhost:3000/api/v1/system/status](http://localhost:3000/api/v1/system/status)

---

## 🔌 Model Context Protocol (MCP) Integration

CCK natively implements the **Model Context Protocol (MCP)** specification (Protocol Version: `2024-11-05`), allowing LLMs (Claude Desktop, Cursor, Custom Agents) to connect directly to CCK over `stdio`.

### Configure in Claude Desktop / Cursor
Add CCK to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cck": {
      "command": "cck",
      "args": ["mcp"]
    }
  }
}
```

Or via Docker:
```json
{
  "mcpServers": {
    "cck": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "cck:latest", "cck", "mcp"]
    }
  }
}
```

### Exposed MCP Tools
- `cck_evaluate_action`: Evaluates a planned agent action against policies, fact freshness, and preconditions before execution.
- `cck_record_evidence`: Mints a cryptographic evidence token with payload digest.
- `cck_query_fact`: Inspects the current state, version, and validity of a real-world entity fact.
- `cck_execute_via_connector`: Executes a verified action through a safe connector adapter with zero bypass.

---

## 💻 Developer SDKs

### Python SDK

```python
from cck.sdk import CCKClient

client = CCKClient(api_key="cck_live_...")

# Pre-execution check
verdict = client.evaluate_action(
    capability="logistics.ship",
    target="courier.fedex",
    command="dispatch_parcel(order_id='1099')"
)

if verdict.is_allowed:
    # Safe to invoke external mutation
    execute_shipment()
else:
    print(f"Action Blocked by CCK: {verdict.reason}")
    print(f"Risk Score: {verdict.risk_score}")
```

### TypeScript SDK

```typescript
import { CCKClient } from '@cck/sdk';

const cck = new CCKClient({ apiKey: 'cck_live_...' });

const verdict = await cck.evaluateAction({
  capability: 'logistics.ship',
  target: 'courier.fedex',
  command: 'dispatch_parcel(order_id="1099")'
});

if (verdict.decision === 'ALLOW') {
  await courier.dispatch();
} else {
  console.warn(`Blocked: ${verdict.reason}`);
}
```

---

## 🔒 Security & Cryptographic Audit Ledger

Every action evaluated by CCK appends an entry to a tamper-evident **SHA-256 Merkle-linked hash chain**:

$$\text{ActionHash}_n = \text{SHA256}(\text{ActionHash}_{n-1} \parallel \text{AuditID}_n \parallel \text{ActionID}_n \parallel \text{Decision}_n \parallel \text{Timestamp}_n)$$

### Verifying Integrity via API:
```bash
curl -X GET http://localhost:3000/api/v1/audits/verify-chain
```
**Response:**
```json
{
  "verified": true,
  "total_records": 12,
  "algorithm": "SHA-256",
  "latest_hash": "a1b2c3d4...",
  "tamper_detected": false
}
```

---

## 🧪 Scenarios Testing Lab (`cck test`)

Run the automated acceptance scenarios suite:

```bash
# Run via API
curl -X POST http://localhost:3000/api/v1/scenarios/run

# Or via Python CLI (when installed)
cck test ./scenarios
```

### Verified Test Suite:
1. `scen_stale_fact_01.json` — Order Status Drift (`paid` $\to$ `refunded` $\to$ `BLOCK`).
2. `scen_timeout_fault_injection.json` — Network Timeout Fault Injection & Idempotency.
3. `scen_destructive_blocked.json` — Destructive Root Shell Command (`rm -rf /`) Blocked.
4. `scen_system_mutation_approval.json` — System Mutation Demands Human Approval (`systemctl stop`).
5. `scen_disconnect_fault.json` — Post-Dispatch Network Disconnection Recovery.
6. `scen_safe_read_and_execute.json` — Safe Read & Inventory Inspection (`ALLOW`).

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env`:

```env
PORT=3000
ENVIRONMENT=production
DATABASE_URL=sqlite:///cck.db
ENABLE_TAMPER_EVIDENT_CHAIN=true
DEFAULT_TENANT_ID=tenant-corp-acme
```

---

## 📄 License

CCK is distributed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
