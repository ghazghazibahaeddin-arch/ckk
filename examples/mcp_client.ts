/**
 * CCK Official Model Context Protocol (MCP) Client
 *
 * Demonstrates invoking CCK verification tools over JSON-RPC 2.0.
 */

async function main() {
  const baseUrl = process.env.CCK_BASE_URL || 'http://localhost:3000';
  console.log(`[MCP Client] Connecting to CCK MCP Server at ${baseUrl}/api/v1/mcp ...`);

  // 1. Initialize MCP Session
  const initRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
    headers: { 'Content-Type': 'application/json' },
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
    headers: { 'Content-Type': 'application/json' },
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

  // 4. Ingest new evidence via cck_record_evidence
  const eviRes = await fetch(`${baseUrl}/api/v1/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'mcp-call-4',
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
