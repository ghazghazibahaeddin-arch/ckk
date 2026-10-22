# CCK Quickstart Guide

Start using CCK to guard your AI Agents in under 3 minutes.

---

## 1. Fast Installation

Install via `pip` or `uv`:

```bash
# Recommended with uv:
uv pip install cck

# Or standard pip:
pip install cck
```

---

## 2. Initialize CCK Workspace

Run `cck init` in your project folder to bootstrap configuration, policies, and test scenarios:

```bash
cck init
```

Output:
```text
✓ CCK workspace initialized successfully!
 • Config: ./cck.config.yaml
 • Database: ./cck.db
 • Policies: ./policies (3 baseline loaded)
 • Scenarios: ./scenarios
```

---

## 3. Run Built-in Test Scenarios

Verify system resilience against stale facts, timeout faults, and destructive commands:

```bash
cck test ./scenarios
```

You should see all 6 test scenarios execute and pass with millisecond latency.

---

## 4. Run Local Server

Start the CCK REST API & Governance engine:

```bash
cck serve --port 8000
```

Inspect API endpoints at `http://localhost:8000/docs` or check system health:

```bash
curl http://localhost:8000/health
```

---

## 5. First Python Agent Integration

```python
import asyncio
from cck.sdk.client import CCKClient

async def main():
    async with CCKClient(base_url="http://localhost:8000") as client:
        # Evaluate an action before executing
        verdict = await client.evaluate_action(
            capability="bash.execute",
            target="server.root",
            parameters={"command": "rm -rf /"},
            severity="DESTRUCTIVE",
        )
        print(f"Decision: {verdict.decision.value} (Risk: {verdict.risk_level.value})")
        if verdict.decision.value == "BLOCK":
            print(f"Action blocked safely: {verdict.reason}")

asyncio.run(main())
```
