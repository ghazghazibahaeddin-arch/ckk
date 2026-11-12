# CCK Platform — Penetration Testing & Red-Team Assessment Report

**Assessment Type:** Authorized Red-Team Offensive Penetration Test  
**Date of Assessment:** November 5, 2026  
**Status:** Completed & Defenses Verified  
**Target Environment:** CCK Control Plane Server & Action Gate Engine (`http://127.0.0.1:3000`)  
**Lead Penetration Tester:** Senior Application Security & Red-Team Engineer  

---

## 1. Scope & Rules of Engagement

The penetration test was conducted under strict rules of engagement to discover vulnerabilities, test defensive boundaries, execute realistic attack payloads, and verify that the platform fails closed under adverse conditions.

### Threat Actor Profiles Simulated:
1. **Unauthenticated External Adversary:** Remote internet attacker attempting to forge webhooks, execute commands, or bypass authentication.
2. **Malicious Tenant / Cross-Tenant Attacker:** Authenticated customer tenant attempting to read, modify, or delete resources of other tenants (IDOR / Multi-tenant boundary traversal).
3. **Malicious Insider / Compromised Operator:** Low-privilege user attempting privilege escalation to approve restricted actions.
4. **Compromised AI Agent:** Agent submitting dangerous command payloads, fork bombs, or filesystem destruction commands.

---

## 2. Attack Scenarios, Execution & Proof of Defense

### Attack RED-01: Webhook Ingestion Backdoor Exploitation
- **Target:** `POST /api/v1/webhooks/ingest`
- **Objective:** Ingest forged sensor facts without knowing the shared HMAC secret.
- **Attack Payload:**
  ```http
  POST /api/v1/webhooks/ingest HTTP/1.1
  Host: 127.0.0.1:3000
  Content-Type: application/json
  x-cck-signature: test_bypass

  {
    "entity_id": "order:exploit_wh",
    "field_name": "payment_status",
    "value": "paid"
  }
  ```
- **Pre-Remediation Result:** VULNERABLE. The server accepted the payload with `200 OK` due to hardcoded `signatureHeader !== 'test_bypass'`.
- **Post-Remediation Result:** DEFENDED. The server rejected the request with `HTTP 401 Unauthorized` (`{"error": "INVALID_SIGNATURE"}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 1).

---

### Attack RED-02: Webhook Replay Attack with Intercepted Payload
- **Target:** `POST /api/v1/webhooks/ingest`
- **Objective:** Replay an intercepted valid signed webhook 10 minutes after initial transmission.
- **Attack Payload:** Valid HMAC-SHA256 signature paired with timestamp `now - 600 seconds`.
- **Pre-Remediation Result:** VULNERABLE. Accepted if not identical in hash or if hash cache expired.
- **Post-Remediation Result:** DEFENDED. Rejected with `HTTP 401 Unauthorized` (`{"error": "EXPIRED_TIMESTAMP"}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 2).

---

### Attack RED-03: Key Hash Theft for Offline Password Cracking
- **Target:** `GET /api/v1/projects/:id/keys`
- **Objective:** Steal SHA-256 hashes of client tokens to run hashcat/John-the-Ripper offline.
- **Attack Payload:** Standard GET request with read permission.
- **Pre-Remediation Result:** VULNERABLE. Returned `key_hash` strings in cleartext JSON.
- **Post-Remediation Result:** DEFENDED. Sanitized output ensures `key_hash` is undefined in all responses.
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 3).

---

### Attack RED-04: Cross-Project IDOR Key Revocation
- **Target:** `DELETE /api/v1/projects/:projId/keys/:keyId`
- **Objective:** Project B user revokes active API key of Project A by passing Project A's `key_id` to Project B's URL.
- **Pre-Remediation Result:** VULNERABLE. Key was revoked unconditionally because project ownership was not checked.
- **Post-Remediation Result:** DEFENDED. Server validates `key.project_id === req.params.projId`. Rejected with `HTTP 403 Forbidden` (`{"error": "FORBIDDEN"}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 4).

---

### Attack RED-05: Cross-Tenant Resource Deletion
- **Target:** `DELETE /api/v1/projects/:id`
- **Objective:** Tenant Bravo sends deletion request against Tenant Alpha's project ID.
- **Pre-Remediation Result:** VULNERABLE. Project was removed and dependencies cascade-deleted.
- **Post-Remediation Result:** DEFENDED. Rejected with `HTTP 403 Forbidden` (`{"error": "FORBIDDEN", "detail": "Cross-tenant project deletion prohibited."}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 5).

---

### Attack RED-06: Forged Agent Token on Action Gate
- **Target:** `POST /api/v1/actions/evaluate`
- **Objective:** Submit action evaluation using forged bearer token `cck_live_forged_fake_token_1234567890`.
- **Pre-Remediation Result:** VULNERABLE. Endpoint executed evaluation anonymously without checking key validity.
- **Post-Remediation Result:** DEFENDED. Rejected with `HTTP 401 Unauthorized` (`{"error": "INVALID_CREDENTIALS"}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 6).

---

### Attack RED-07: Revoked Token Reuse Attack
- **Target:** `POST /api/v1/actions/evaluate`
- **Objective:** Re-use a revoked API key to execute database query actions.
- **Pre-Remediation Result:** VULNERABLE. Key revocation state was ignored on evaluation.
- **Post-Remediation Result:** DEFENDED. Rejected with `HTTP 403 Forbidden` (`{"error": "REVOKED"}`).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 7).

---

### Attack RED-08: Malicious Command Injection & Denial-of-Service Payloads
- **Target:** Action Gate Engine
- **Objective:** Inject OS destruction and crash commands:
  - Fork bomb: `:(){ :|:& };:`
  - Password hash extraction: `cat /etc/shadow`
  - Raw drive wipe: `dd if=/dev/zero of=/dev/sda`
  - Filesystem wipe: `rm -rf /`
  - Windows drive format: `format c: /q`
- **Defense Mechanism:** Intercepted by `POL-SEC-001` with risk score `1.0`, decision `BLOCK`, and zero mutation dispatched.
- **Post-Remediation Result:** DEFENDED (100% blocked).
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 8).

---

### Attack RED-09: Unauthorized Approval Resolution (Privilege Escalation)
- **Target:** `POST /api/v1/approvals/:id/resolve`
- **Objective:** An operator or viewer approves a pending critical mutation.
- **Attack Payload:** `{"approved": true, "notes": "Unauthorized approval"}` with `x-user-role: operator`.
- **Pre-Remediation Result:** VULNERABLE. Anyone calling the endpoint could resolve approvals.
- **Post-Remediation Result:** DEFENDED. Rejected with `HTTP 403 Forbidden` (`{"error": "FORBIDDEN"}`). Only `admin` and `supervisor` roles are permitted.
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 9).

---

### Attack RED-10: Clickjacking, MIME-Sniffing & Transport Insecurity
- **Target:** Global Server Responses
- **Objective:** Probe for missing security headers allowing iframe embedding, MIME-type confusion, or unencrypted downgrades.
- **Post-Remediation Result:** DEFENDED. All endpoints return:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Content-Security-Policy: default-src 'self' ...`
- **Verification Test:** `tests/ts_tests/security_red_team.test.ts` (Subtest 10).

---

## 3. Penetration Test Summary Matrix

| Test ID | Exploit Category | Target Endpoint | Result |
| :--- | :--- | :--- | :--- |
| **RED-01** | Webhook Backdoor Exploitation | `/api/v1/webhooks/ingest` | **BLOCKED (401)** |
| **RED-02** | Webhook Timestamp Replay | `/api/v1/webhooks/ingest` | **BLOCKED (401)** |
| **RED-03** | Key Hash Exposure / Offline Cracking | `/api/v1/projects/:id/keys` | **BLOCKED (Redacted)** |
| **RED-04** | Cross-Project IDOR Key Revocation | `/api/v1/projects/:p/keys/:k` | **BLOCKED (403)** |
| **RED-05** | Cross-Tenant Project Deletion | `/api/v1/projects/:id` | **BLOCKED (403)** |
| **RED-06** | Action Gate Forged Bearer Token | `/api/v1/actions/evaluate` | **BLOCKED (401)** |
| **RED-07** | Action Gate Revoked Key Reuse | `/api/v1/actions/evaluate` | **BLOCKED (403)** |
| **RED-08** | Command Injections & Fork Bombs | `/api/v1/actions/evaluate` | **BLOCKED (Risk 1.0)** |
| **RED-09** | Approval RBAC Privilege Escalation | `/api/v1/approvals/:id/resolve` | **BLOCKED (403)** |
| **RED-10** | Missing Security Response Headers | Global Middleware | **ENFORCED (100%)** |

**Penetration Test Sign-Off:** All attack vectors closed. System demonstrates resilient fail-closed behavior across all test dimensions.
