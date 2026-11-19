# CCK MCP Runtime Enforcement Gateway Architecture & Boundaries

## 1. Execution Interception Pipeline
When an AI agent or MCP client calls `/api/v1/mcp`, `/mcp`, `/api/v1/mcp/gateway/invoke`, or runs `src/mcp/stdio_server.ts` connected to the CCK Control Plane, every downstream tool invocation executes the following fail-closed chain **before** any downstream transport call occurs:

1. **Tenant & Caller Verification**: Validates `tenant_id`, API key status (`cck_live_...`), and prevents cross-tenant upstream invocation.
2. **Upstream Registry & Status Check**: Verifies the target tool is registered in `mcpUpstreams` for the caller's tenant and is in `ACTIVE` status (`SUSPENDED`, `REVOKED`, or unregistered tools are blocked immediately).
3. **Tool Identity Fingerprint & Drift Policy (Features 9 & 10)**: Checks the canonical SHA-256 fingerprint (`cck-tool-canon-v1`) and blocks/holds unapproved CRITICAL/HIGH drift (new permissions, added endpoints, schema changes, publisher downgrade).
4. **Permission Graph & Least Privilege (Feature 11)**: Evaluates `DECLARED` vs `GRANTED` vs `EFFECTIVE` permissions. Tool manifest claims NEVER auto-grant permissions; missing, expired, or revoked grants block dispatch.
5. **Dependency & Invalidation Cascade (Feature 4)**: Verifies no upstream `SOURCE`, `FACT`, `EVIDENCE`, `CONTRACT`, or `TOOL` node feeding this protected action is `INVALIDATED` or `REVALIDATE_REQUIRED`.
6. **Adaptive Fact Freshness (Feature 1)**: Evaluates prerequisite fact age against bounded adaptive TTL policies (`FRESH | STALE | EXPIRED | INVALIDATED | UNKNOWN`).
7. **Core Action Gate**: Evaluates emergency kill switches, business invariants, action contracts, multi-hop delegations, runtime budgets, custom policy rules, and prompt injection / SSRF guards.
8. **Physical Downstream Dispatch**: Downstream HTTP JSON-RPC (`AbortController` timeouts + idempotent-only bounded retries) or local adapter execution is dispatched **ONLY** when the final verdict is `ALLOW`. On `BLOCK`, `REQUIRE_APPROVAL`, `REVALIDATE`, or gateway errors, **0 downstream calls are dispatched**.
9. **Audit Chain & Redacted Receipt**: Every invocation appends to `mcpGatewayInvocations`, SHA-256 `auditLedger`, and redacted `DecisionReceipt`.

## 2. Enforced vs Bypassable Paths (Truthful Threat Model)

### Strictly Enforced Paths (Physical Interception Guaranteed)
- Agents configured with their MCP endpoint pointed at CCK (`/api/v1/mcp` or `/mcp`) or invoked via `POST /api/v1/mcp/gateway/invoke`.
- Stdio MCP clients launching `src/mcp/stdio_server.ts` pointed at CCK (`CCK_BASE_URL` + `CCK_API_KEY`). If CCK is unreachable, the stdio bridge fails closed with `BLOCK`.
- Applications dispatching tool calls through CCK TypeScript/Python SDK `mcp_gateway_call` / `mcpGatewayCall` or `CCKGuard`.

### Paths Outside CCK Proxy Control (Deployment Requirements)
- If an external downstream MCP server is exposed directly on the public internet or local network without network-level isolation (mTLS, VPC firewall, reverse-proxy auth, or private loopback binding), a rogue client holding direct downstream credentials could bypass CCK by calling that downstream server directly.
- **Required Production Hardening**:
  - Bind downstream MCP servers on private subnets/security groups accepting requests ONLY from the CCK Gateway identity or signed gateway mutual-TLS/HMAC headers.
  - Never distribute raw downstream MCP service credentials directly to untrusted agent runtimes; store downstream auth strictly inside the gateway boundary.
