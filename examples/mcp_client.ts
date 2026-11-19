/**
 * CCK Official Model Context Protocol (MCP) Client + Runtime Gateway Example
 *
 * Demonstrates:
 * 1. Initializing an MCP session against CCK
 * 2. Discovering available tools (including registered upstream tools)
 * 3. Evaluating actions via cck_evaluate_action
 * 4. Recording evidence via cck_record_evidence
 * 5. Dispatching a downstream MCP tool call physically through cck_gateway_call
 */

async function main() {
  const baseUrl = process.env.CCK_BASE_URL || 'http://localhost:3000';
  const tenantId = process.env.CCK_TENANT_ID || 'tenant_default';
  console.log(`[MCP Client] Connecting to CCK MCP Gateway at ${baseUrl}/api/v1/mcp ...`);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-tenant-id': tenantId,
  };
  if (process.env.CCK_API_KEY) {
    headers['Authorization'] = `Bearer ${process.env.CCK_API_KEY}`;
  }

  // 1. Initialize MCP Session
  const initRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-init-1',
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', clientInfo: { name: 'ClaudeDesktop', version: '1.0.0' } },
    }),
  });
  const initData = await initRes.json();
  console.log('[MCP Init Response]:', initData.result?.serverInfo);

  // 2. Discover MCP Tools
  const toolsRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-tools-2',
      method: 'tools/list',
      params: {},
    }),
  });
  const toolsData = await toolsRes.json();
  console.log('[Discovered MCP Tools]:', toolsData.result?.tools?.map((t: any) => t.name));

  // 3. Execute cck_evaluate_action via MCP tools/call
  const callRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-call-3',
      method: 'tools/call',
      params: {
        name: 'cck_evaluate_action',
        arguments: {
          capability: 'logistics.ship',
          target: 'courier.fedex',
          parameters: { order_id: '1099' },
          session_id: 'mcp-claude-session-99',
        },
      },
    }),
  });
  const callData = await callRes.json();
  const verdictText = callData.result?.content?.[0]?.text;
  const verdict = verdictText ? JSON.parse(verdictText) : null;
  console.log('[MCP Gate Verdict]:', verdict?.decision, '| Reason:', verdict?.reason);

  // 4. Fail-closed verification: attempt unregistered tool via cck_gateway_call -> must BLOCK physically
  const blockedGwRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-gw-4',
      method: 'tools/call',
      params: {
        name: 'cck_gateway_call',
        arguments: {
          tool_name: 'unregistered_dangerous_tool',
          target: 'prod.database',
          arguments: { query: 'DROP TABLE orders' },
        },
      },
    }),
  });
  const blockedGwData = await blockedGwRes.json();
  const blockedPayload = blockedGwData.result?.content?.[0]?.text
    ? JSON.parse(blockedGwData.result.content[0].text)
    : null;
  console.log('[MCP Gateway Fail-Closed Check]:', {
    decision: blockedPayload?.decision,
    downstream_dispatched: blockedPayload?.downstream_dispatched,
    isError: blockedGwData.result?.isError,
  });

  // 5. Ingest new evidence via cck_record_evidence
  const eviRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-call-5',
      method: 'tools/call',
      params: {
        name: 'cck_record_evidence',
        arguments: {
          entity_id: 'order:1099',
          field_name: 'status',
          value: 'paid',
        },
      },
    }),
  });
  const eviData = await eviRes.json();
  console.log('[MCP Evidence Ingestion]:', eviData.result?.content?.[0]?.text);
  console.log('[MCP Test Complete]: Success!');
}

main().catch(console.error);
