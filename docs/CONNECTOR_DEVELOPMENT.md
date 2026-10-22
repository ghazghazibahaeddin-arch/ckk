# Connector Development Guide for CCK

Connectors link external systems (Databases, REST APIs, CRM, Payment Gateways) with the CCK Core Reliability Engine.

Every connector in CCK must implement the `Connector` abstract base class and declare its supported capabilities truthfully.

---

## 1. Connector Interface Requirements

```python
from typing import Any
from cck.connectors.interface import (
    Connector,
    ConnectorCapability,
    ReadResult,
    WriteResult,
    CompensationResult,
    ConnectorHealthStatus,
)

class MyCustomConnector(Connector):
    def __init__(self, connector_id: str = "custom-api", name: str = "Custom Service"):
        super().__init__(connector_id=connector_id, name=name)

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        """Declare only capabilities that this connector actually implements."""
        return {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.CONDITIONAL_WRITE,
            ConnectorCapability.IDEMPOTENCY,
            ConnectorCapability.COMPENSATION,
            ConnectorCapability.HEALTH_CHECK,
        }

    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        """Perform a read and return normalized ReadResult."""
        ...

    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        """Execute mutating action. If expected_version is provided, enforce CAS logic."""
        ...

    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        """Execute rollback if the action is reversible."""
        ...

    async def check_health(self) -> ConnectorHealthStatus:
        """Perform a liveness and responsiveness probe."""
        ...
```

---

## 2. Zero-Bypass Write Pipeline

Mutating actions must **never** bypass CCK's Action Gate. When using `WriteAdapter`:

```python
from cck.connectors.adapters.write_adapter import WriteAdapter

write_adapter = WriteAdapter(action_gate=gate, idempotency_adapter=idem)

# Dispatches safely through:
# 1. Action Gate evaluation (Must be VerdictDecision.ALLOW)
# 2. Target validation (Verifies target exists and version matches)
# 3. Idempotency deduplication
# 4. Connector dispatch
# 5. Event Journaling with secret scrubbing
write_result = await write_adapter.execute_write(
    connector=my_connector,
    action=agent_action,
    expected_version=1,
    idempotency_key="tx-123",
)
```

---

## 3. Security Guidelines for Connectors

1. **Secret Scrubbing**: Never log API keys, Bearer tokens, or passwords. CCK provides `scrub_secrets(payload)` which automatically redacts credentials.
2. **Network Drops & Unknown Outcoms**: If a connection drops after mutating an external service, mark the attempt as `UNKNOWN_OUTCOME` in the idempotency adapter. **Never automatically retry unsafe actions** with unknown outcomes.
3. **Honest Stubs**: If building a connector stub (like Stripe or Salesforce), declare its unconfigured status and do not pretend live integration works without credentials.
