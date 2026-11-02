# cck-python-sdk

Official Python SDK for **Causal Continuity Kernel (CCK)** — Agent Reliability, Action Gate, and Causal Invariance Platform.

## Installation

```bash
pip install cck-python-sdk
```

## Quick Start

```python
import os
from cck_sdk import CCKClient, AgentAction, AgentIdentity, ActionSeverity, with_cck_guard, CCKActionBlockedError

# 1. Initialize client
cck = CCKClient(
    base_url=os.getenv("CCK_BASE_URL", "http://localhost:3000"),
    api_key=os.getenv("CCK_API_KEY"),  # cck_live_...
)

# 2. Send live heartbeat to establish CONNECTED status
ping = cck.heartbeat("agt-order-guard")
print("Status:", ping["status"])  # 'CONNECTED'

# 3. Guard consequential actions fail-closed
def refund_customer(order_id: str, amount: float):
    return {"order_id": order_id, "refunded": amount}

action = AgentAction(
    agent=AgentIdentity(agent_id="agt-order-guard", name="RefundAgent"),
    session_id="session-ref-100",
    capability="orders.refund",
    target="order:1099",
    parameters={"order_id": "1099", "amount": 49.99},
    severity=ActionSeverity.MUTATION,
)

try:
    result = with_cck_guard(cck, action, refund_customer, "1099", 49.99)
    print("Refund succeeded:", result)
except CCKActionBlockedError as ex:
    print(f"Action was BLOCKED by CCK: {ex.verdict.reason}")
```
