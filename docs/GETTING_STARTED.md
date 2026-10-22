# Getting Started with CCK (Command & Control Kit)

CCK is an open-source reliability, governance, and action control platform for autonomous AI agents. It ensures AI agent actions conform to safety policies, validates preconditions, verifies cryptographic evidence, and prevents destructive or unauthorized external operations.

---

## 1. Installation

Install CCK using pip or uv:

```bash
# Using pip
pip install cck

# Or using uv (recommended for ultra-fast installs)
uv pip install cck
```

For development with testing tools:

```bash
git clone https://github.com/cck-project/cck.git
cd cck
uv pip install -e ".[dev]"
```

---

## 2. Quickstart: CLI Verification

Initialize the local SQLite database schema and seed standard safety policies:

```bash
# Initialize local database
cck init-db

# Check platform status and configuration
cck info

# Run built-in test scenarios
cck test ./scenarios
```

Output:
```text
CCK Testing Lab Evaluation Report
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Scenario ID        ┃ Title                          ┃ Duration (ms) ┃ Result ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ scen_stale_fact_01 │ Order status changed between   │ 0.12          │ PASSED │
│                    │ read and write                 │               │        │
└────────────────────┴────────────────────────────────┴───────────────┴────────┘
Total: 1 | Passed: 1 | Failed: 0
```

---

## 3. Quickstart: Python SDK Example

Integrate CCK into your AI agent loop to gate external mutating actions:

```python
import asyncio
from cck.contracts.action import AgentAction, AgentIdentity
from cck.contracts.verdict import VerdictDecision
from cck.core.types import ActionSeverity
from cck.runtime.engine import CCKControlPlane
from cck.sdk.client import CCKClient

async def main():
    # 1. Initialize CCK Control Plane
    control_plane = CCKControlPlane()
    await control_plane.initialize()

    client = CCKClient(control_plane=control_plane)

    # 2. Evaluate a safe read action
    verdict_safe = await client.evaluate(
        capability="filesystem.read",
        target="/var/log/app.log",
        parameters={"lines": 50},
        severity=ActionSeverity.INFORMATIONAL,
    )
    print(f"Safe Action Decision: {verdict_safe.decision}")
    # Output: VerdictDecision.ALLOW

    # 3. Evaluate a dangerous shell action
    verdict_danger = await client.evaluate(
        capability="bash.execute",
        target="system.root",
        parameters={"command": "rm -rf /"},
        severity=ActionSeverity.DESTRUCTIVE,
    )
    print(f"Dangerous Action Decision: {verdict_danger.decision}")
    # Output: VerdictDecision.BLOCK
    print(f"Reason: {verdict_danger.reason}")

    # Clean shutdown
    await control_plane.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 4. Model Context Protocol (MCP) Integration

CCK includes built-in MCP server support to intercept tool calls from LLMs:

```bash
# Start CCK REST & MCP HTTP Gateway
cck run-server --port 8000
```

The MCP Server exposes the `cck_evaluate_action` tool which intercepts proposed agent tool arguments and returns structured verdicts before execution.

---

## 5. Next Steps

- [Developing a Custom Connector](CONNECTOR_DEVELOPMENT.md)
- [Deploying in Observe/Shadow Mode](OBSERVE_MODE.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Production Release & Disaster Recovery](RELEASE_AND_ROLLBACK.md)
