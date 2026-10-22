# CCK Contracts and Schemas Specification

This document details the core data contracts and schemas governing the CCK platform.

## 1. AgentAction (`cck.contracts.action.AgentAction`)
The canonical envelope describing an external action proposed by an autonomous agent.

```json
{
  "action_id": "c62040c5-55ff-4f40-97eb-38b48858db14",
  "agent": {
    "agent_id": "agt-deployer-01",
    "name": "ProductionDeployer",
    "version": "1.0.0",
    "tenant_id": "infra-ops",
    "trust_tier": "standard"
  },
  "session_id": "sess-889102",
  "capability": "bash.execute",
  "target": "server.prod.web01",
  "parameters": {
    "command": "systemctl restart nginx"
  },
  "severity": "MUTATION",
  "idempotency_key": "idem-77281",
  "metadata": {
    "prompt_id": "p-102",
    "reasoning": "Deploying updated site configuration"
  },
  "timestamp": "2026-10-18T09:30:00Z"
}
```

### Fields
| Field | Type | Description |
|---|---|---|
| `action_id` | UUID string | Globally unique identifier for this action execution attempt |
| `agent` | `AgentIdentity` | Immutable agent metadata and trust tier |
| `session_id` | string | Correlating trace or workflow session ID |
| `capability` | string | Action category (`bash.execute`, `filesystem.write`, `api.http`) |
| `target` | string | Exact target resource name or URI |
| `parameters` | object | Execution parameters passed to downstream runner |
| `severity` | string | `INFORMATIONAL`, `STANDARD`, `MUTATION`, `DESTRUCTIVE` |
| `idempotency_key` | string (optional) | De-duplication key |
| `timestamp` | ISO-8601 UTC | Formulation timestamp |

---

## 2. ExecutionVerdict (`cck.contracts.verdict.ExecutionVerdict`)
Authoritative evaluation produced by the CCK policy gatekeeper.

```json
{
  "verdict_id": "vrd-990182",
  "action_id": "c62040c5-55ff-4f40-97eb-38b48858db14",
  "decision": "REQUIRE_APPROVAL",
  "risk_level": "HIGH",
  "risk_score": 0.70,
  "reason": "Human approval required by [POL-SEC-003]: Command modifies privileged system state",
  "matched_policies": [
    {
      "rule_id": "POL-SEC-003",
      "rule_name": "Require Approval for System Mutations",
      "effect": "REQUIRE_APPROVAL",
      "reason": "Command matches pattern: systemctl",
      "risk_score": 0.70
    }
  ],
  "remediation_suggestions": [
    "Request supervisor authorization token before executing system configuration changes."
  ],
  "evaluated_at": "2026-10-18T09:30:00.050Z"
}
```

---

## 3. PolicyRule (`cck.contracts.policy.PolicyRule`)
Declarative rule definition loaded into the CCK policy engine.

```json
{
  "rule_id": "POL-SEC-001",
  "name": "Block Destructive Shell Invocations",
  "description": "Prevents catastrophic root and disk removals",
  "capability_pattern": "bash.*",
  "target_pattern": "*",
  "action_effect": "BLOCK",
  "risk_level": "CRITICAL",
  "is_active": true,
  "conditions": {
    "forbidden_command_patterns": [
      "\\brm\\s+-[rRfF]*\\s+/",
      "\\bmkfs\\b"
    ]
  }
}
```

---

## 4. AuditRecord (`cck.contracts.audit.AuditRecord`)
Cryptographically chained ledger entry preserving action provenance and auditability.

```json
{
  "audit_id": "aud-102938",
  "action_id": "c62040c5-55ff-4f40-97eb-38b48858db14",
  "agent_id": "agt-deployer-01",
  "action_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "previous_hash": "7d793037a0760186574b0282f2f435e7090a6ff0ec353ff0021b36e8b4e7ec97",
  "verdict": { ... },
  "execution_status": "EVALUATED",
  "execution_result": null,
  "recorded_at": "2026-10-18T09:30:00.055Z"
}
```

---

## 5. Entity Identity (`cck.contracts.entity.Entity`)
Immutable domain entity contract preventing name-collision bugs.

```json
{
  "entity_id": "order:1099",
  "entity_type": "order",
  "name": "Customer Checkout Order #1099",
  "attributes": {
    "customer_id": "cust_441",
    "amount": 120.0
  },
  "created_at": "2026-10-18T09:00:00Z",
  "updated_at": "2026-10-18T09:00:00Z"
}
```

---

## 6. Fact (`cck.contracts.fact.Fact`)
Authoritative attribute fact tied to an entity and field with TTL freshness and fingerprint.

```json
{
  "entity_id": "order:1099",
  "field_name": "status",
  "value": "paid",
  "source": "stripe_webhook",
  "observed_at": "2026-10-18T09:05:00Z",
  "version": 1,
  "state": "VALID",
  "evidence_id": "evi_7d82a10bf9e34c568912",
  "ttl_seconds": 300.0,
  "field_fingerprint": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
}
```

---

## 7. Evidence (`cck.contracts.evidence.Evidence`)
System-minted provenance record holding exact raw payload and cryptographic SHA-256 hash.

```json
{
  "evidence_id": "evi_7d82a10bf9e34c568912",
  "entity_id": "order:1099",
  "field_name": "status",
  "raw_payload": {
    "order_id": "1099",
    "status": "paid",
    "charge_id": "ch_3M4910"
  },
  "source": "stripe_webhook",
  "observed_at": "2026-10-18T09:05:00Z",
  "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "metadata": {
    "ip_address": "54.187.205.10"
  }
}
```

---

## 8. ActionDependencySpec (`cck.contracts.dependency.ActionDependencySpec`)
Precondition dependencies demanded by an action before the ActionGate will issue an `ALLOW`.

```json
{
  "action_id": "act-ship-01",
  "decision_id": "dec-ship-01",
  "required_facts": [
    ["order:1099", "status"]
  ],
  "claimed_evidence_ids": [
    "evi_7d82a10bf9e34c568912"
  ],
  "policy_version": "1.0.0"
}
```

