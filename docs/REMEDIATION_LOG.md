# CCK Platform — Security Remediation & Hardening Changelog

**Document Version:** 1.0.0  
**Date:** November 5, 2026  
**Auditor / Engineer:** Principal Security & Reliability Engineer  
**Branch:** `security-hardening`  

---

## 1. Overview

This log details the surgical security remediations, bug fixes, defensive middleware implementations, and architectural hardening applied across the CCK repository. Every modification corresponds to an identified vulnerability from the Security Audit and is accompanied by automated regression tests.

---

## 2. File-by-File Remediation Log

### 1. `server.ts` — Webhook Signature Verification Hardening
- **Vulnerability Ref:** VULN-001 (CRITICAL)
- **Changes Made:**
  - Removed line containing `signatureHeader !== 'test_bypass'`.
  - Implemented `crypto.timingSafeEqual` between expected and provided HMAC buffers to defend against side-channel timing attacks.
  - Added timestamp validation (`x-cck-timestamp`) enforcing a strict 300-second freshness window.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-01, RED-02).

---

### 2. `server.ts` — API Key Hash Sanitization & Secret Redaction
- **Vulnerability Ref:** VULN-002 (HIGH)
- **Changes Made:**
  - Modified `GET /api/v1/projects/:id/keys` handler.
  - Mapped key records to explicitly omit `key_hash`.
  - Only safe public metadata is returned: `{ key_id, project_id, name, key_prefix, created_at, is_active }`.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-03).

---

### 3. `server.ts` — Cross-Project Key Revocation Defense
- **Vulnerability Ref:** VULN-003 (HIGH)
- **Changes Made:**
  - Updated `DELETE /api/v1/projects/:projId/keys/:keyId`.
  - Added strict check: `if (key.project_id !== req.params.projId) return res.status(403)`.
  - Prevents attackers from using their own project route to revoke keys belonging to foreign projects.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-04).

---

### 4. `server.ts` — Cross-Tenant Project Deletion Protection
- **Vulnerability Ref:** VULN-005 (HIGH)
- **Changes Made:**
  - Updated `DELETE /api/v1/projects/:id`.
  - Enforced tenant boundary: verifies `callerTenant === proj.tenant_id`.
  - Returns `403 Forbidden` if a caller attempts cross-tenant project deletion.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-05).

---

### 5. `server.ts` — Action Gate Authentication & Revocation Enforcement
- **Vulnerability Ref:** VULN-004 (HIGH)
- **Changes Made:**
  - Added authentication layer to `POST /api/v1/actions/evaluate`.
  - Validates `Authorization: Bearer <token>` or `x-api-key: <token>`.
  - Unknown tokens return `401 Unauthorized`.
  - Tokens associated with revoked keys (`!matchedKey.is_active`) return `403 Forbidden`.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-06, RED-07).

---

### 6. `server.ts` — Malicious Command & Fork Bomb Injection Filtering
- **Vulnerability Ref:** Defense-in-Depth / POL-SEC-001
- **Changes Made:**
  - Expanded command inspection to catch:
    - `:(){ :|:& };:` (Bash fork bomb)
    - `cat /etc/shadow` (Credential extraction)
    - `dd if=/dev/zero of=/dev/sda` (Drive zeroing)
    - `format c: /q` (Windows volume wipe)
    - `truncate -s 0 /etc/passwd` (Account corruption)
  - Unconditionally blocks mutations and records audit ledger entry with risk score `1.0`.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-08).

---

### 7. `server.ts` — Human Approvals RBAC Authorization
- **Vulnerability Ref:** VULN-007 (HIGH)
- **Changes Made:**
  - Updated `POST /api/v1/approvals/:id/resolve`.
  - Prohibits unprivileged roles (`operator`, `viewer`, `guest`) from approving system mutations.
  - Requires `admin` or `supervisor` role; unauthorized callers receive `403 Forbidden`.
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-09).

---

### 8. `server.ts` — Defensive Security Headers & Rate Limiting
- **Vulnerability Ref:** VULN-008 & VULN-009 (MEDIUM)
- **Changes Made:**
  - Added global middleware setting:
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: SAMEORIGIN`
    - `X-XSS-Protection: 1; mode=block`
    - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
    - `Referrer-Policy: strict-origin-when-cross-origin`
    - `Content-Security-Policy: default-src 'self' ...`
  - Bounded request body parsers: `limit: '1mb'`.
  - Implemented in-memory sliding-window rate limiter (300 req/min per IP/prefix).
- **Verification:** `tests/ts_tests/security_red_team.test.ts` (RED-10).

---

### 9. `server.ts` & `src/App.tsx` — TypeScript Compiler Typing Alignments
- **Changes Made:**
  - Added `matchedPolicies?: Array<{ rule_id: string; name: string }>;` to `mintDecisionReceipt` params in `server.ts`.
  - Added `workspaces: []` to `getInitialCleanDatabase()`.
  - Fixed agent status filter in `src/App.tsx` to compare with `'CONNECTED'` instead of `'ACTIVE'`.
  - Fixed optional database ID parameter in `src/firebase.ts`.
- **Verification:** `lint_applet` (`tsc --noEmit`) passes with 0 errors.

---

### 10. `firestore.rules` — 8 Pillars of Production Security
- **Vulnerability Ref:** VULN-010 (MEDIUM)
- **Changes Made:**
  - Completely re-authored `firestore.rules`.
  - Enforced document ID matching (`request.resource.data.id == docId`).
  - Immutability guards on `evidence`, `receipts`, and `audit_events`.
  - Document field count and string length constraints (`isDocSizeValid`).
  - Owner-scoped workspace rules.

---

### 11. `tests/ts_tests/security_red_team.test.ts` — New Automated Test Suite
- **Changes Made:**
  - Created 10 automated red-team test cases covering all exploit attempts.
  - Integrated into standard `npm test` pipeline.
- **Verification:** 10/10 tests pass deterministically.
