# Observe / Shadow Mode Guide for CCK

Observe Mode (also known as Shadow Mode) allows operations and security teams to deploy new safety policies, guardrails, and risk thresholds into active agent pipelines **without risking production downtime**.

---

## 1. How Observe / Shadow Mode Works

When CCK runs in **Shadow Mode**:
1. Incoming agent actions and dependency specs are evaluated against the active policy rules and facts.
2. If an action violates a policy or has stale preconditions:
   - CCK calculates the real verdict (`VerdictDecision.BLOCK` or `VerdictDecision.REQUIRE_APPROVAL`).
   - CCK logs the violation to the cryptographic `EventJournal` and fires telemetry alerts.
   - However, CCK returns `VerdictDecision.ALLOW` with a metadata flag:
     `{"shadow_mode": True, "simulated_decision": "BLOCK", "reason": "..."}`
3. Teams can audit logs to see what *would* have been blocked before turning on enforcement mode.

---

## 2. Enabling Shadow Mode

### Via Environment Variable
```bash
export CCK_SHADOW_MODE=true
```

### Via Python API
```python
control_plane.settings.shadow_mode = True
```

### Via HTTP REST API
```bash
curl -X POST http://localhost:8000/api/v1/settings/shadow-mode \
     -H "Content-Type: application/json" \
     -d '{"enabled": true}'
```

---

## 3. Best Practices

- Run all new policy rule sets in Shadow Mode for at least 72 hours in staging or production.
- Monitor CCK Alert Webhooks to inspect false positives.
- Once risk scores and rule matches are validated, switch `shadow_mode=False` for strict zero-bypass enforcement.
