/**
 * CCK Model Context Protocol (MCP) Client Example.
 *
 * Demonstrates invoking CCK verification tools over stdio/HTTP proxy.
 */

import { CCKClient } from '../src/sdk/client';

async function main() {
  const cck = new CCKClient({ baseUrl: 'http://localhost:3000' });

  console.log('[MCP Client] Checking CCK Control Plane health...');
  const health = await cck.health();
  console.log('[CCK Status]:', health);

  console.log('\n[MCP Client] Submitting action to CCK Action Gate...');
  const verdict = await cck.evaluateAction({
    session_id: 'mcp-session-001',
    agent: {
      agent_id: 'agt-mcp-claude',
      name: 'Claude Desktop Agent',
      trust_tier: 'standard',
    },
    capability: 'logistics.ship',
    target: 'courier.fedex',
    parameters: { order_id: '1099' },
    severity: 'MUTATION',
  });

  console.log('[CCK Gate Verdict]:', verdict.decision);
  console.log('[Reasoning]:', verdict.reason);
  console.log('[Risk Score]:', verdict.risk_score);
}

main().catch(console.error);
