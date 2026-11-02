# @cck/sdk

Official TypeScript/JavaScript SDK for **Causal Continuity Kernel (CCK)** — Agent Reliability, Action Gate, and Causal Invariance Platform.

## Installation

```bash
npm install @cck/sdk
```

## Quick Start

```typescript
import { CCKClient, withCCKGuard } from '@cck/sdk';

// Initialize client with your project-scoped agent key
const cck = new CCKClient({
  baseUrl: process.env.CCK_BASE_URL || 'http://localhost:3000',
  apiKey: process.env.CCK_API_KEY, // e.g. cck_live_...
});

// 1. Send live heartbeat to establish CONNECTED status
const ping = await cck.heartbeat('agt-order-guard');
console.log('CCK Connection Status:', ping.status); // 'CONNECTED'

// 2. Wrap consequential agent actions with fail-closed guard
try {
  const result = await withCCKGuard(
    {
      client: cck,
      action: {
        session_id: 'session-order-982',
        agent: { agent_id: 'agt-order-guard', name: 'OrderAgent' },
        capability: 'logistics.ship',
        target: 'courier.fedex',
        parameters: { order_id: '1099' },
        severity: 'MUTATION',
      },
    },
    async () => {
      // Protected tool logic executed ONLY if CCK returns ALLOW
      return await dispatchParcelViaFedEx('1099');
    }
  );
  console.log('Action Succeeded:', result);
} catch (err) {
  if (err.name === 'CCKActionBlockedError') {
    console.error('CCK BLOCKED Action:', err.message, err.verdict.reason);
  } else {
    throw err;
  }
}
```
