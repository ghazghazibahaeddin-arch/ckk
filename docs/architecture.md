# CCK System Architecture

CCK is organized as a **Modular Monolith** divided into 7 distinct functional layers:

---

## The 7 Layers of CCK

```
┌─────────────────────────────────────────────────────────────┐
│ 7. Enterprise & Hosted Cloud                                │
│    Multi-tenancy, PostgreSQL, Quotas, Central Audit Log     │
├─────────────────────────────────────────────────────────────┤
│ 6. Integrations & Developer Platform                         │
│    Python SDK, TypeScript SDK, CLI, MCP Server, Webhooks    │
├─────────────────────────────────────────────────────────────┤
│ 5. Testing & Failure Injection Lab                          │
│    Scenario Definitions, Network Faults, Replay Engine      │
├─────────────────────────────────────────────────────────────┤
│ 4. Audit, Observability & Recovery Engine                   │
│    Cryptographic Hash Chain, OpenTelemetry, Blast Radius    │
├─────────────────────────────────────────────────────────────┤
│ 3. Control Plane, Governance & Policies                     │
│    Policy Engine, Versioning, RBAC/ABAC, Human Approvals    │
├─────────────────────────────────────────────────────────────┤
│ 2. Connectors & Execution Adapters                          │
│    Read/Write Adapters, Target Validator, Idempotency       │
├─────────────────────────────────────────────────────────────┤
│ 1. Core Reliability Engine                                  │
│    Entity & Fact Registries, Freshness Engine, Action Gate  │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Zero-Bypass Invariant

All external actions originating from an LLM or autonomous agent must be evaluated by the `ActionGate`. The `ActionGate`:
1. Re-validates all claimed facts against real-time TTL and fine-grained field fingerprints.
2. Checks that claimed evidence IDs were minted by the system, rejecting unauthenticated IDs.
3. Evaluates matched safety policies.
4. Generates an immutable verdict (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `REVALIDATE`).

---

## 2. Cryptographic Hash Chain

Every evaluated action, verdict, and execution outcome is serialized into an `AuditRecord` and chained using SHA-256 hash pointers:
$$H_i = \text{SHA256}(R_i \parallel H_{i-1})$$
Any retroactive modification of logs breaks the chain and triggers tamper detection alerts.
