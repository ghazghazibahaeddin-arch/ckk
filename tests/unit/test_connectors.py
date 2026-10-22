"""Unit tests for CCK Connectors & Execution Adapters (Layer 2).

Verifies:
1. Sandbox connector read/write operations and capability declarations.
2. Capability registry and unsupported capability assertion.
3. Target validator for version consistency and field conditions.
4. Idempotency adapter lifecycle (PENDING, COMPLETED, FAILED, UNKNOWN_OUTCOME) and duplicate detection.
5. Compensation adapter, reversibility catalog, and irreversible action rejection.
6. Error normalization (timeout, auth, permission, rate limit, connectivity, conflict).
7. Credential sanitization (zero secrets in logs/records).
8. Health monitor: separation of infrastructure faults from CCK policy blocks.
9. Stub connectors: honest capability declaration and unconfigured state handling.
"""

import pytest

from cck.connectors.capabilities import CapabilityRegistry
from cck.connectors.compensation import (
    CompensationAdapter,
)
from cck.connectors.errors import normalize_connector_error
from cck.connectors.health import ConnectorHealthMonitor
from cck.connectors.idempotency import IdempotencyAdapter
from cck.connectors.implementations.sandbox import InMemorySandboxConnector
from cck.connectors.implementations.stubs import (
    SalesforceConnectorStub,
    StripeConnectorStub,
    ZendeskConnectorStub,
)
from cck.connectors.security import scrub_secrets
from cck.connectors.target_validator import TargetValidator
from cck.core.exceptions import (
    IdempotencyConflictError,
    NonReversibleActionError,
    NormalizedConnectorError,
    TargetValidationError,
    UnsupportedCapabilityError,
)
from cck.core.types import (
    ConnectorCapability,
    IdempotencyStatus,
    NormalizedErrorCategory,
)


@pytest.mark.asyncio
async def test_sandbox_connector_read_and_write() -> None:
    """Test standard read and write on InMemorySandboxConnector."""
    connector = InMemorySandboxConnector()
    connector.seed_target("user:101", {"name": "Alice", "role": "admin"}, version=1)

    # 1. Read
    res = await connector.read("user:101")
    assert res.exists is True
    assert res.data["name"] == "Alice"
    assert res.version == 1
    assert res.is_trusted is True

    # 2. Write
    write_res = await connector.write("user:101", {"role": "superadmin"}, expected_version=1)
    assert write_res.success is True
    assert write_res.new_version == 2
    assert write_res.response_data["role"] == "superadmin"

    # 3. Read again to confirm updated state
    updated_res = await connector.read("user:101")
    assert updated_res.version == 2
    assert updated_res.data["role"] == "superadmin"


@pytest.mark.asyncio
async def test_sandbox_connector_missing_target() -> None:
    """Reading non-existent target returns exists=False."""
    connector = InMemorySandboxConnector()
    res = await connector.read("non_existent_key")
    assert res.exists is False
    assert res.data == {}
    assert res.version is None


@pytest.mark.asyncio
async def test_conditional_write_and_optimistic_concurrency() -> None:
    """Conditional write succeeds on version match and fails on version conflict."""
    connector = InMemorySandboxConnector()
    connector.seed_target("order:500", {"status": "pending"}, version=3)

    # Version mismatch raises NormalizedConnectorError with VERSION_CONFLICT
    with pytest.raises(NormalizedConnectorError) as exc_info:
        await connector.write("order:500", {"status": "paid"}, expected_version=2)
    assert exc_info.value.category == NormalizedErrorCategory.VERSION_CONFLICT.value

    # Correct version succeeds and increments version
    res = await connector.write("order:500", {"status": "paid"}, expected_version=3)
    assert res.success is True
    assert res.new_version == 4


@pytest.mark.asyncio
async def test_unsupported_conditional_write_declaration() -> None:
    """Connector configured without CONDITIONAL_WRITE explicitly rejects conditional writes."""
    connector = InMemorySandboxConnector(disable_conditional_writes=True)
    connector.seed_target("doc:1", {"title": "Test"}, version=1)

    assert ConnectorCapability.CONDITIONAL_WRITE not in connector.supported_capabilities

    with pytest.raises(UnsupportedCapabilityError) as exc_info:
        await connector.write("doc:1", {"title": "Updated"}, expected_version=1)
    assert "does not support CONDITIONAL_WRITE" in str(exc_info.value)


@pytest.mark.asyncio
async def test_target_validator_version_and_field_checks() -> None:
    """TargetValidator validates version and field preconditions against live connector state."""
    connector = InMemorySandboxConnector()
    connector.seed_target("account:77", {"balance": 1500, "currency": "USD"}, version=5)
    validator = TargetValidator()

    # Successful validation
    valid = await validator.validate_preconditions(
        connector=connector,
        target="account:77",
        expected_version=5,
        expected_values={"currency": "USD", "balance": 1500},
    )
    assert valid is True

    # Failed validation: version mismatch
    with pytest.raises(TargetValidationError) as exc_info:
        await validator.validate_preconditions(
            connector=connector,
            target="account:77",
            expected_version=4,
        )
    assert "Expected version 4, but live version is 5" in str(exc_info.value)

    # Failed validation: field value mismatch
    with pytest.raises(TargetValidationError) as exc_info:
        await validator.validate_preconditions(
            connector=connector,
            target="account:77",
            expected_values={"currency": "EUR"},
        )
    assert "Expected value 'EUR', but live value is 'USD'" in str(exc_info.value)

    # Failed validation: non-existent target
    with pytest.raises(TargetValidationError) as exc_info:
        await validator.validate_preconditions(
            connector=connector,
            target="account:missing",
        )
    assert "does not exist" in str(exc_info.value)


@pytest.mark.asyncio
async def test_idempotency_lifecycle_and_conflict_detection() -> None:
    """IdempotencyAdapter tracks attempt lifecycle and rejects concurrent duplicate attempts."""
    adapter = IdempotencyAdapter()
    key = "idem-key-abc-123"

    # 1. Start attempt
    rec1 = await adapter.start_attempt(key, action_id="act-001")
    assert rec1.status == IdempotencyStatus.PENDING

    # 2. Concurrently starting attempt with same key raises IdempotencyConflictError
    with pytest.raises(IdempotencyConflictError) as exc_info:
        await adapter.start_attempt(key, action_id="act-002")
    assert "is already in-flight" in str(exc_info.value)

    # 3. Complete attempt
    completed = await adapter.complete_attempt(key, result_data={"trans_id": "tx_999"})
    assert completed.status == IdempotencyStatus.COMPLETED
    assert completed.result == {"trans_id": "tx_999"}

    # 4. Subsequent start_attempt returns cached record without conflict
    rec_cached = await adapter.start_attempt(key, action_id="act-003")
    assert rec_cached.status == IdempotencyStatus.COMPLETED
    assert rec_cached.result == {"trans_id": "tx_999"}


@pytest.mark.asyncio
async def test_idempotency_unknown_outcome_blocks_unsafe_retry() -> None:
    """Network drop during execution marks UNKNOWN_OUTCOME and prohibits unsafe retry."""
    adapter = IdempotencyAdapter()
    key = "idem-key-disconnect"

    await adapter.start_attempt(key, action_id="act-disconnect")
    await adapter.mark_unknown_outcome(key, error_msg="Connection severed by peer")

    rec = await adapter.get_record(key)
    assert rec is not None
    assert rec.status == IdempotencyStatus.UNKNOWN_OUTCOME

    # Retry attempt must be blocked!
    with pytest.raises(IdempotencyConflictError) as exc_info:
        await adapter.start_attempt(key, action_id="act-retry")
    assert "UNKNOWN_OUTCOME" in str(exc_info.value)
    assert "Manual inspection required" in str(exc_info.value)


@pytest.mark.asyncio
async def test_compensation_adapter_reversibility() -> None:
    """CompensationAdapter allows reversible actions and rejects irreversible actions."""
    adapter = CompensationAdapter()

    assert adapter.is_reversible("database.update") is True
    assert adapter.is_reversible("inventory.reserve") is True
    assert adapter.is_reversible("email.send") is False
    assert adapter.is_reversible("wire_transfer.execute") is False

    # Attempting to register compensation for irreversible action raises NonReversibleActionError
    with pytest.raises(NonReversibleActionError) as exc_info:
        adapter.register_compensation(
            action_id="act-send-email",
            capability="email.send",
            compensation_payload={"cancel": True},
        )
    assert "permanently non-reversible" in str(exc_info.value) or "non-reversible" in str(exc_info.value)

    # Successful compensation on reversible action using sandbox connector
    connector = InMemorySandboxConnector()
    connector.seed_target("inventory:item-1", {"reserved_units": 10}, version=1)

    write_res = await connector.write("inventory:item-1", {"reserved_units": 20})
    assert write_res.response_data["reserved_units"] == 20

    # Compensate back to original state
    comp_res = await connector.compensate(
        target="inventory:item-1",
        original_action_id=write_res.execution_id,
        compensation_payload={},
    )
    assert comp_res.success is True

    # State restored
    restored = await connector.read("inventory:item-1")
    assert restored.data["reserved_units"] == 10


@pytest.mark.asyncio
async def test_compensation_rejected_when_connector_lacks_capability() -> None:
    """Connector without COMPENSATION capability raises UnsupportedCapabilityError."""
    connector = InMemorySandboxConnector(disable_compensation=True)
    adapter = CompensationAdapter()

    adapter.register_compensation(
        action_id="act-01",
        capability="database.update",
        compensation_payload={"revert": True},
    )

    with pytest.raises(UnsupportedCapabilityError) as exc_info:
        await adapter.execute_compensation(
            action_id="act-01",
            capability="database.update",
            connector=connector,
            target="db:table",
        )
    assert "does not support COMPENSATION" in str(exc_info.value)


def test_capability_registry() -> None:
    """CapabilityRegistry registers and asserts supported connector capabilities."""
    registry = CapabilityRegistry()
    registry.register_connector_capabilities(
        "custom-driver",
        {ConnectorCapability.READ, ConnectorCapability.WRITE},
    )

    assert registry.supports("custom-driver", ConnectorCapability.READ) is True
    assert registry.supports("custom-driver", ConnectorCapability.COMPENSATION) is False

    with pytest.raises(UnsupportedCapabilityError) as exc_info:
        registry.assert_supports("custom-driver", ConnectorCapability.COMPENSATION)
    assert "does not support capability 'COMPENSATION'" in str(exc_info.value)


def test_error_normalization() -> None:
    """Test normalization of diverse exceptions into standard CCK categories."""
    # 1. Timeout
    err_timeout = normalize_connector_error(TimeoutError("Read timeout"), connector_id="conn-1")
    assert err_timeout.category == NormalizedErrorCategory.TIMEOUT.value
    assert err_timeout.retryable is False  # Safety rule: No auto-retry with unknown state!

    # 2. Authentication (401)
    err_auth = normalize_connector_error(Exception("401 Unauthorized token"), connector_id="conn-2")
    assert err_auth.category == NormalizedErrorCategory.AUTHENTICATION.value

    # 3. Permission denied (403)
    err_perm = normalize_connector_error(Exception("403 Forbidden: Insufficient permissions"), connector_id="conn-3")
    assert err_perm.category == NormalizedErrorCategory.PERMISSION_DENIED.value

    # 4. Rate limiting (429)
    err_rate = normalize_connector_error(Exception("429 Too Many Requests"), connector_id="conn-4")
    assert err_rate.category == NormalizedErrorCategory.RATE_LIMITING.value
    assert err_rate.retryable is True

    # 5. Connectivity
    err_conn = normalize_connector_error(ConnectionResetError("Connection reset by peer"), connector_id="conn-5")
    assert err_conn.category == NormalizedErrorCategory.CONNECTIVITY.value

    # 6. Version conflict
    err_conflict = normalize_connector_error(Exception("409 Conflict: ETag mismatch"), connector_id="conn-6")
    assert err_conflict.category == NormalizedErrorCategory.VERSION_CONFLICT.value


def test_secret_scrubbing_never_leaks_credentials() -> None:
    """scrub_secrets eliminates API keys, bearer tokens, passwords from data payloads."""
    dirty_payload = {
        "user_id": "usr-88",
        "api_key": "sk-live-supersecrettoken999",
        "password": "MySuperSecretPassword!",
        "auth": {"token": "my-secret-token", "provider": "oauth"},
        "headers": ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_payload"],
        "metadata": {
            "conn_string": "postgres://user:password123@db.prod.internal/db?token=xyz123",
        },
    }

    clean = scrub_secrets(dirty_payload)

    assert clean["api_key"] == "[REDACTED_SECRET]"
    assert clean["password"] == "[REDACTED_SECRET]"
    assert clean["auth"]["token"] == "[REDACTED_SECRET]"
    assert clean["auth"]["provider"] == "oauth"
    assert "sk-live" not in str(clean)
    assert "MySuperSecretPassword!" not in str(clean)
    assert "Bearer [REDACTED_SECRET]" in clean["headers"][0]
    assert "token=[REDACTED_SECRET]" in clean["metadata"]["conn_string"]


def test_connector_health_monitoring_separation_of_concerns() -> None:
    """Health monitor distinguishes connector infrastructure failure from CCK policy blocks."""
    monitor = ConnectorHealthMonitor()
    cid = "test-external-api"

    # Initial state
    h0 = monitor.get_health(cid)
    assert h0.healthy is True
    assert h0.error_rate == 0.0

    # 1. Successful requests
    monitor.record_success(cid, latency_ms=10.0)
    monitor.record_success(cid, latency_ms=20.0)

    # 2. 10 Policy gate rejections occurred
    for _ in range(10):
        monitor.record_policy_block(cid)

    # Policy rejections MUST NOT degrade connector health or inflate connector error rate!
    h1 = monitor.get_health(cid)
    assert h1.healthy is True
    assert h1.error_rate == 0.0

    # 3. Infrastructure failures DO degrade connector health
    for _ in range(5):
        monitor.record_failure(cid, latency_ms=50.0, error_message="HTTP 500 Server Error")

    h2 = monitor.get_health(cid)
    assert h2.healthy is False  # 5 failures out of 7 calls (> 50% failure rate)
    assert h2.error_rate > 0.5
    assert "Degraded" in h2.message


@pytest.mark.asyncio
async def test_future_connector_stubs_honest_disclosures() -> None:
    """Stripe, Zendesk, and Salesforce connector stubs declare capabilities and fail honestly when unconfigured."""
    stripe = StripeConnectorStub(api_key=None)
    assert ConnectorCapability.IDEMPOTENCY in stripe.supported_capabilities
    assert ConnectorCapability.COMPENSATION in stripe.supported_capabilities

    # Unconfigured check_health returns healthy=False
    health = await stripe.check_health()
    assert health.healthy is False
    assert "Stub initialized" in health.message

    # Read without credentials raises NormalizedConnectorError (AUTHENTICATION)
    with pytest.raises(NormalizedConnectorError) as exc_info:
        await stripe.read("charges/ch_123")
    assert exc_info.value.category == NormalizedErrorCategory.AUTHENTICATION.value

    # Zendesk stub
    zendesk = ZendeskConnectorStub()
    with pytest.raises(NormalizedConnectorError) as exc_info:
        await zendesk.read("tickets/101")
    assert exc_info.value.category == NormalizedErrorCategory.AUTHENTICATION.value

    # Salesforce stub
    salesforce = SalesforceConnectorStub()
    with pytest.raises(NormalizedConnectorError) as exc_info:
        await salesforce.read("Contact/003")
    assert exc_info.value.category == NormalizedErrorCategory.AUTHENTICATION.value
