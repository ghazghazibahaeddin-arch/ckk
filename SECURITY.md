# Security Policy

CCK (**Command & Control Kit**) is an Agent Reliability & Causal Continuity Platform designed to protect external systems from unauthorized, stale, or harmful autonomous mutations. We treat security and reliability vulnerabilities with the highest priority.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.2.x` | :white_check_mark: |
| `0.1.x` | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability—such as an Action Gate bypass, failure in the SHA-256 cryptographic audit chain, or unhandled fail-open state—please **do not** open a public issue.

Instead, please send an encrypted or private report to:
- **Email**: `security@cck.local` or through private GitHub Vulnerability Reporting.

Please include:
1. Detailed description of the vulnerability.
2. Steps or scripts to reproduce the issue.
3. Impact assessment (e.g., potential unauthorized mutations or evidence tampering).
4. Any relevant Decision Receipts.

## Security Guarantees & Non-Goals

### Guarantees
- **Fail-Closed Execution**: If an evaluation crashes or dependencies cannot be resolved, CCK unconditionally issues a `BLOCK` verdict.
- **Tamper-Evident Ledger**: Every decision is linked via SHA-256 hash chains (`previous_hash` &rarr; `action_hash`). Any modification breaks the chain.
- **Credential Protection**: Plaintext API keys and tokens are never stored in durable storage; only SHA-256 hashes and prefixes are persisted. Decision receipts apply configurable automated redaction.

### Explicit Boundaries (Non-Goals)
- CCK cannot prevent agent failures in external systems it does not observe or through tools that bypass its execution gate.
- CCK enforces causal continuity over observed evidence; it does not replace domain-level data validation or application firewalls.
