# CCK Policy & Governance Guide

This guide details how CCK evaluates, versions, and enforces safety guardrails, RBAC, ABAC, and human approval workflows on external agent actions.

---

## 1. Core Evaluation Philosophy

CCK operates on a **zero-trust execution model**. No external action reaches an API, shell, database, or cloud infrastructure without:
1. Validating fact freshness (TTL and version fingerprinting).
2. Verifying system-minted evidence authenticity.
3. Checking policy engine rule matches.
4. Checking agent trust tier, role, and attributes.
5. Verifying idempotency keys and state preconditions.

---

## 2. Verdict Decisions

| Verdict | Meaning | Agent Next Step |
|---|---|---|
| `ALLOW` | Safe to execute externally. | Connector executes action, records outcome in journal. |
| `BLOCK` | Forbidden by safety guardrail or policy. | Abort action immediately, agent receives remediation suggestions. |
| `REQUIRE_APPROVAL` | High risk or privileged action. | Action suspended in `PENDING` state, notification sent to human reviewers. |
| `REVALIDATE` | Precondition fact is stale or invalidated. | Agent must re-observe the world and re-issue action. |
| `SIMULATE_ONLY` | Observe / Shadow Mode active. | Simulated verdict returned without actual external side effects. |

---

## 3. Built-in Security Policies

CCK ships with default baseline policies:

1. **POL-SEC-001 (Destructive Bash Prevention):**
   - Matches: `bash.*`
   - Conditions: Prevents `rm -rf /`, `mkfs`, `dd if=/dev/zero`, fork bombs.
   - Verdict: `BLOCK` (Risk: `CRITICAL`).

2. **POL-SEC-002 (Sensitive Filesystem Protection):**
   - Matches: `fs.*`
   - Conditions: Blocks direct read/write to `/etc/shadow`, `/etc/sudoers`, `.ssh/id_rsa`, `.aws/credentials`.
   - Verdict: `BLOCK` (Risk: `HIGH`).

3. **POL-SEC-003 (Privileged Service Mutations):**
   - Matches: Privileged commands (`useradd`, `userdel`, `iptables`, `systemctl stop`).
   - Verdict: `REQUIRE_APPROVAL` (Risk: `HIGH`).

---

## 4. Writing Custom Policies

Policies can be declared in YAML or JSON:

```yaml
rule_id: "POL-FIN-001"
name: "High Value Wire Transfer Gate"
description: "Demands CFO approval for transfers exceeding $10,000"
capability_pattern: "finance.wire_transfer"
target_pattern: "account:*"
action_effect: "REQUIRE_APPROVAL"
risk_level: "HIGH"
is_active: true
conditions:
  max_unapproved_amount: 10000.0
```

Registering via CLI:
```bash
cck inspect-action scenarios/my_action.json
```

Registering via REST API:
```bash
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "POL-FIN-001",
    "name": "High Value Wire Transfer Gate",
    "description": "Demands CFO approval for transfers exceeding $10,000",
    "capability_pattern": "finance.wire_transfer",
    "target_pattern": "*",
    "action_effect": "REQUIRE_APPROVAL",
    "risk_level": "HIGH",
    "is_active": true,
    "conditions": {}
  }'
```

---

## 5. Observe / Shadow Mode

In observe mode, CCK evaluates incoming actions through the entire policy pipeline, computes risk tiers, records audit entries, but overrides the decision to `ALLOW` with `[SHADOW_MODE_PERMITTED]` reason.

Enable via CLI:
```bash
cck serve --shadow
```

Or via environment variable:
```bash
export CCK_SHADOW_MODE=true
```
