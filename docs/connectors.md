# Developing a CCK Connector

Connectors bridge CCK's reliability gate with external systems (REST APIs, databases, message queues, cloud CLIs, or file systems).

---

## 1. Core Principles

1. **Zero-Bypass Policy:**
   Write operations must never bypass the CCK Action Gate.
2. **Honest Capability Disclosures:**
   Connectors must explicitly declare supported features (`CONDITIONAL_WRITE`, `COMPENSATION`, `IDEMPOTENCY_KEY`). Never simulate a guarantee that the underlying system does not provide.
3. **Secret Scrubbing:**
   All logs, journals, and traces must automatically redact API keys, bearer tokens, passwords, and private secrets.
4. **Normalized Error Handling:**
   Convert network and service errors into standard CCK categories (`AUTHENTICATION`, `PERMISSION_DENIED`, `RATE_LIMITING`, `TIMEOUT`, `UNKNOWN_OUTCOME`).

---

## 2. Implementing the `ConnectorInterface`

Create a new file in `src/cck/connectors/implementations/my_connector.py`:

```python
from typing import Any
from cck.connectors.interface import ConnectorInterface, ReadResult, WriteResult
from cck.core.types import ConnectorCapability
from cck.connectors.capabilities import CapabilityRegistry

class StripePaymentConnector(ConnectorInterface):
    """Production connector for Stripe API with idempotency and error normalization."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._capabilities = {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.IDEMPOTENCY_KEY,
            ConnectorCapability.ERROR_NORMALIZATION,
        }

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        return self._capabilities

    async def read(self, target: str) -> ReadResult:
        # target format: 'charge:ch_123'
        charge_id = target.split(":")[-1]
        data = await self._fetch_charge(charge_id)
        return ReadResult(
            target=target,
            data=data,
            version=data.get("version", 1),
            is_reliable=True,
        )

    async def write(
        self,
        target: str,
        action_name: str,
        parameters: dict[str, Any],
        idempotency_key: str | None = None,
        expected_version: int | None = None,
    ) -> WriteResult:
        # Execute charge creation with idempotency key header
        result = await self._post_charge(parameters, idempotency_key=idempotency_key)
        return WriteResult(
            target=target,
            success=True,
            data=result,
            new_version=result.get("version", 1),
        )
```

---

## 3. Registering Connector in CapabilityRegistry

```python
from cck.connectors.capabilities import CapabilityRegistry
from cck.core.types import ConnectorCapability

registry = CapabilityRegistry()
registry.register_connector_capabilities(
    "stripe_payments",
    {
        ConnectorCapability.READ,
        ConnectorCapability.WRITE,
        ConnectorCapability.IDEMPOTENCY_KEY,
    }
)

# Enforces that unsupported operations throw UnsupportedCapabilityError
registry.assert_supports("stripe_payments", ConnectorCapability.IDEMPOTENCY_KEY)
```
