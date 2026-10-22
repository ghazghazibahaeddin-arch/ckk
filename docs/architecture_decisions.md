# Architecture Decision Records (ADR) - CCK Platform

## ADR-001: Modular Monolith over Distributed Microservices

### Context
CCK is designed as a control, governance, and reliability platform for external AI agents. It must inspect, evaluate, and audit high-frequency actions with sub-millisecond overhead, absolute consistency, and strict transactionality.

### Decision
We adopt a **Modular Monolith** architecture:
- Single codebase structured into high-cohesion, low-coupling modules (`core`, `contracts`, `storage`, `policies`, `audit`, `runtime`, `api`, `cli`).
- Clear boundaries defined through typed protocols and Python abstractions.
- No distributed microservices or network serialization between internal domains unless crossing the external API boundary.

### Consequences
- **Positive:** Zero network hops during policy evaluation; atomic audit updates; single deployable artifact; simple local and CI/CD testing.
- **Negative:** Shared process space; scaling requires scaling the whole monolith or extracting specific worker processes if required in future phases.

---

## ADR-002: Storage Boundaries with Repository Pattern (SQLite -> PostgreSQL)

### Context
Developers need zero-dependency local development and rapid test suite execution (in-memory or file-based SQLite), while enterprise production environments require horizontal scale, high availability, and concurrent connection pools (PostgreSQL).

### Decision
We decouple persistence behind an abstract `StorageBackend` interface:
- All business domains (`runtime`, `policies`, `audit`) depend exclusively on the abstract `StorageBackend` protocol.
- First-class async SQLite implementation using `aiosqlite` with WAL mode and foreign key constraints.
- DDL and data modeling structured to map 1:1 to PostgreSQL `JSONB`, `TIMESTAMPTZ`, and `UUID` primitives.

### Consequences
- **Positive:** Tests run in seconds without external Docker containers; seamless transition to PostgreSQL by supplying a `PostgreSQLStorageBackend` without modifying business logic.
- **Negative:** Must avoid engine-specific dialects in domain queries.

---

## ADR-003: Action Interception Lifecycle & Guardrail Gate

### Context
External agents propose actions (shell commands, file modifications, HTTP webhooks, DB mutations). If actions are executed without validation, irreversible damage can occur.

### Decision
Every action passes through a 3-step control gate before physical execution:
1. **Intake & Canonicalization:** Action is validated against strict Pydantic schemas and assigned a unique ID and canonical hash.
2. **Policy Evaluation:** Guardrails match capability, target, and payload against active security policies. Yields an `ExecutionVerdict` (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`).
3. **Immutable Audit Chaining:** The action, verdict, and timestamp are registered into a cryptographic SHA-256 hash chain before any downstream dispatch.

### Consequences
- **Positive:** Guaranteed audit trail before execution; deterministic security guardrails; support for human-in-the-loop approvals.

---

## ADR-004: Unified Strict Schema Contracts with Pydantic v2

### Context
Data exchanged between AI orchestrators, CLI tools, REST APIs, and persistence layers must have strict type safety, zero ambiguity, and schema evolution guarantees.

### Decision
All domain models are defined using **Pydantic v2**:
- Frozen models for immutable identity (`AgentIdentity`).
- Extra attributes forbidden (`extra="forbid"`) to prevent silent payload pollution or evasion attacks.
- Strict numeric and string bounds (`ge=0.0, le=1.0` for risk scores).

---

## ADR-005: System-Minted Evidence IDs and Cryptographic Provenance

### Context
Autonomous AI agents tend to fabricate citations, hallucinate proof strings, or pass subjective arguments as objective truth. Accepting arbitrary evidence identifiers from an LLM breaks governance.

### Decision
- Evidence IDs are generated **strictly by the CCK system** (`evi_<uuid4_hex>`).
- Every evidence record is cryptographically bound to its raw payload via an immutable SHA-256 digest (`payload_hash`).
- Unverified, arbitrary, or hallucinated evidence identifiers presented by agents are rejected with an immediate `BLOCK` verdict.

### Consequences
- **Positive:** Zero trust for LLM-fabricated citations; deterministic forensic trail for all claims.
- **Negative:** Upstream orchestrators must route raw API responses through CCK before citing them.

---

## ADR-006: Fine-Grained Field Fingerprinting & Invalidation Decoupling

### Context
Invalidating all entity dependencies whenever any field changes causes massive false-positive action blocks (e.g. changing `customer.phone` should never invalidate a dependency on `order.status == 'paid'`).

### Decision
- Facts are stored and tracked per `(entity_id, field_name)`.
- Each fact stores a deterministic `field_fingerprint` (SHA-256 of canonical value).
- When a new observation arrives, downstream invalidation is triggered **only if the target field's fingerprint genuinely changed**.
- Out-of-order delayed events (version < current) are rejected with `VersionConflictError`, while duplicate events with identical fingerprints are processed idempotently without triggering spurious invalidations.

---

## ADR-007: Zero-Bypass Action Gate & Temporal Freshness Decay

### Context
A fact observed in the past degrades over time. Absence of a subsequent update does NOT prove that the external system state remains unchanged.

### Decision
- Actions are protected by a centralized `ActionGate` enforcing a zero-bypass policy.
- Facts define an optional `ttl_seconds`. When elapsed, the fact degrades to `STALE`.
- If an action requires a `STALE` fact, the gate emits `REVALIDATE` (prompting the agent or orchestrator to perform a live re-read).
- If a fact is `INVALIDATED`, the gate strictly emits `BLOCK`.

---

## ADR-008: Isolated Sandbox Replay with Zero External Side-Effects

### Context
Auditors and operators must be able to replay historical event journals to verify whether decisions were correct, without triggering real external mutations (e.g. sending real emails, discharging payments, or modifying cloud resources).

### Decision
- The `ReplayEngine` operates in an isolated, temporary in-memory sandbox.
- It steps through historical observations and reproduces gate verdicts against specified policy versions.
- External action dispatchers are completely stubbed/disabled in replay mode, mathematically guaranteeing `external_actions_executed == 0`.

