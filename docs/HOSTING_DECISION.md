# CCK Architecture & Hosting Decision: Google AI Studio vs. Cloudflare

**Document Version:** 1.0.0  
**Target Platform:** Causal Continuity Kernel (CCK) Agent Reliability Platform  
**Owner:** Bahaeddin Ghazghazi (`bahaghazghazi@gmail.com`)  
**Repository:** `https://github.com/ghazghazibahaeddin-arch/cck`  

---

## 1. Executive Summary

This document evaluates the two viable hosting architectures for deploying the production Causal Continuity Kernel (CCK) developer SaaS platform:

- **Option A (Recommended & Active):** Google AI Studio Build + Cloud Run (Starter Tier) + Firebase Authentication + Cloud Firestore.
- **Option B (Secondary / Edge Evaluated):** Cloudflare Pages + Workers (with D1 SQLite & Python Workers/Pyodide).

**Verdict & Decision:**  
**Option A is selected as the primary authoritative production runtime for the CCK Developer Platform.**  
The TypeScript Control Plane and Action Gate provide 100% contract compliance, zero native dependency friction, verified Firebase Auth JWT session security, native Firestore document persistence, and seamless 1-click publishing within the Google Cloud / AI Studio Starter Tier with zero billing requirements.

---

## 2. In-Depth Technical Evaluation

### Architecture Option A: Google AI Studio + Cloud Run + Firebase

| Dimension | Assessment | Details |
| :--- | :--- | :--- |
| **Backend Runtime** | **Verified (Node.js 22 LTS / tsx)** | Express engine in `server.ts` natively supports Vite dev server proxying and standalone production execution. |
| **Authoritative Engine** | **TypeScript Engine (`server.ts`)** | Full zero-bypass Action Gate implementation: cryptographic SHA-256 evidence minting, immutable decision receipts, hash-chained audit ledger, and webhook signature verification. |
| **Python Runtime Dependency** | **Not Required at Runtime** | The hosted SaaS Control Plane does not require Python at runtime. Python is provided as a client consumer SDK (`packages/cck-python-sdk`). |
| **Authentication** | **Verified (Firebase Auth)** | Native client Google Sign-In with popup/redirect, JWT ID tokens, persistent browser sessions, and backend header validation (`Bearer cck_live_...` for agents, Bearer ID tokens for dashboard). |
| **Persistence** | **Verified (Cloud Firestore)** | Document-based multi-tenant storage backed by deployed rules (`firestore.rules`) and blueprint schema (`firebase-blueprint.json`). Project: `intense-chimera-50z9n`. |
| **Quota & Free Tier** | **Optimal** | Free tier allows 50,000 document reads, 20,000 writes, and 20,000 deletes per day; Cloud Run Starter tier gives 2 million requests/month free with scale-to-zero. |
| **Deployment Simplicity** | **High (Native Publish)** | Directly publishable from Google AI Studio Build UI to hosted Cloud Run without complex CI/CD setup or paid billing credentials. |

### Architecture Option B: Cloudflare Pages / Workers + D1

| Dimension | Assessment | Details |
| :--- | :--- | :--- |
| **Python Workers Support** | **Restricted / Experimental** | Cloudflare Python Workers run on WebAssembly (Pyodide). Heavy dependencies with native C extensions or specific POSIX syscalls encounter package compatibility gaps. |
| **FastAPI on Workers** | **Partial** | FastAPI requires ASGI adapters (`asgi-service-worker`) with request buffering, latency overhead, and 128 MB RAM constraints on free workers. |
| **D1 Storage Adapter** | **Feasible but Relational** | D1 provides edge SQLite, but requires manual schema migrations, lacks native cryptographic hash verification triggers, and requires custom multi-tenant isolation logic. |
| **CPU Time Limits** | **Strict (10ms free, 50ms paid)** | Computing cryptographic SHA-256 chains and validating complex policy graphs on large evidence trees risks hitting strict Cloudflare Worker CPU limits. |
| **Current Status** | **Preserved as Edge Proxy / DNS** | Cloudflare configuration and DNS remain attached, but the authoritative application logic is hosted on Cloud Run. |

---

## 3. Runtime Verification Matrix

```
Customer Agent (LangGraph / OpenAI / CrewAI / MCP)
      │
      ▼ (Authenticated with Bearer cck_live_...)
CCK Control Plane API (server.ts on Cloud Run)
      ├── 1. Agent Authentication & Project Scoping (SHA-256 Key Hash)
      ├── 2. Fact Validity & Evidence Freshness (TTL Verification)
      ├── 3. Precondition Dependency Graph (Causal Continuity Check)
      ├── 4. Action Gate Verdict (ALLOW / BLOCK / REQUIRE_APPROVAL)
      ├── 5. Immutable Decision Receipt Minting (SHA-256 Hash Chain)
      └── 6. Real-time Audit Ledger Persistence (Firestore / SQLite)
```

1. **Agent Connection Lifecycle:**
   - Registration creates agent with status `DISCONNECTED`.
   - A secret project-scoped key (`cck_live_...`) is generated once and hashed with SHA-256.
   - Only when `POST /api/v1/agents/:id/heartbeat` is invoked with valid credentials does the agent status transition to `CONNECTED`.
2. **Fail-Closed Guarantee:**
   - If evidence is invalidated, stale, or CCK Control Plane is offline, actions are BLOCKED. No external mutations are dispatched.
3. **Demo Isolation:**
   - Failure Lab simulation records are flagged with `is_demo: true` and excluded from production customer audit counters.
