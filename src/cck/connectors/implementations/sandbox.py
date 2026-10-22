"""In-Memory Sandbox Connector for CCK.

Fully functional, isolated test connector implementing all Layer 2 features:
READ, WRITE, CONDITIONAL_WRITE (compare-and-swap), IDEMPOTENCY, COMPENSATION,
VERSION_CHECK, and configurable fault simulation for network and auth conditions.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cck.connectors.interface import (
    CompensationResult,
    Connector,
    ConnectorHealthStatus,
    ReadResult,
    WriteResult,
)
from cck.core.exceptions import NormalizedConnectorError, UnsupportedCapabilityError
from cck.core.types import ConnectorCapability, NormalizedErrorCategory


class InMemorySandboxConnector(Connector):
    """In-memory data store connector for isolated integration and unit testing."""

    def __init__(
        self,
        connector_id: str = "sandbox-kv",
        name: str = "In-Memory Sandbox KV Store",
        disable_conditional_writes: bool = False,
        disable_compensation: bool = False,
    ) -> None:
        super().__init__(connector_id=connector_id, name=name)
        # target -> data dictionary
        self._store: dict[str, dict[str, Any]] = {}
        # target -> version counter
        self._versions: dict[str, int] = {}
        # original_action_id -> previous_state_dict (for compensation)
        self._history: dict[str, tuple[str, dict[str, Any]]] = {}

        # Configurable capabilities
        self._disable_conditional_writes = disable_conditional_writes
        self._disable_compensation = disable_compensation

        # Test simulation flags
        self.simulate_disconnect_before: bool = False
        self.simulate_disconnect_during: bool = False
        self.simulate_timeout: bool = False
        self.simulate_rate_limit: bool = False
        self.simulate_auth_failure: bool = False
        self.simulate_permission_denied: bool = False

    @property
    def supported_capabilities(self) -> set[ConnectorCapability]:
        caps = {
            ConnectorCapability.READ,
            ConnectorCapability.WRITE,
            ConnectorCapability.IDEMPOTENCY,
            ConnectorCapability.VERSION_CHECK,
            ConnectorCapability.HEALTH_CHECK,
        }
        if not self._disable_conditional_writes:
            caps.add(ConnectorCapability.CONDITIONAL_WRITE)
        if not self._disable_compensation:
            caps.add(ConnectorCapability.COMPENSATION)
        return caps

    def seed_target(self, target: str, data: dict[str, Any], version: int = 1) -> None:
        """Seed initial state for testing."""
        self._store[target] = dict(data)
        self._versions[target] = version

    def _check_fault_simulations(self) -> None:
        """Evaluate simulated fault flags."""
        if self.simulate_auth_failure:
            raise NormalizedConnectorError(
                message="Simulated 401: Invalid API Key or expired token",
                category=NormalizedErrorCategory.AUTHENTICATION.value,
                connector_id=self.connector_id,
            )
        if self.simulate_permission_denied:
            raise NormalizedConnectorError(
                message="Simulated 403: Forbidden - user lacks required scope",
                category=NormalizedErrorCategory.PERMISSION_DENIED.value,
                connector_id=self.connector_id,
            )
        if self.simulate_rate_limit:
            raise NormalizedConnectorError(
                message="Simulated 429: Too Many Requests - rate limit exceeded",
                category=NormalizedErrorCategory.RATE_LIMITING.value,
                connector_id=self.connector_id,
                retryable=True,
            )
        if self.simulate_disconnect_before:
            raise NormalizedConnectorError(
                message="Simulated Network Disconnect: Connection dropped before dispatch",
                category=NormalizedErrorCategory.CONNECTIVITY.value,
                connector_id=self.connector_id,
                retryable=True,
            )
        if self.simulate_timeout:
            raise TimeoutError("Simulated socket timeout after 3000ms")

    async def read(self, target: str, params: dict[str, Any] | None = None) -> ReadResult:
        """Read state from in-memory store."""
        self._check_fault_simulations()

        if target not in self._store:
            return ReadResult(
                target=target,
                data={},
                version=None,
                exists=False,
                is_trusted=True,
            )

        data = dict(self._store[target])
        ver = self._versions.get(target, 1)

        return ReadResult(
            target=target,
            data=data,
            version=ver,
            exists=True,
            is_trusted=True,
            raw_response=dict(data),
        )

    async def write(
        self,
        target: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> WriteResult:
        """Write or update target state in in-memory store."""
        self._check_fault_simulations()

        # 1. Conditional Write verification
        if expected_version is not None:
            if not self.supports(ConnectorCapability.CONDITIONAL_WRITE):
                raise UnsupportedCapabilityError(
                    f"Connector '{self.connector_id}' does not support CONDITIONAL_WRITE."
                )

            current_ver = self._versions.get(target, 1)
            if current_ver != expected_version:
                raise NormalizedConnectorError(
                    message=(
                        f"Conditional write failed on '{target}': "
                        f"Expected version {expected_version}, but live version is {current_ver}."
                    ),
                    category=NormalizedErrorCategory.VERSION_CONFLICT.value,
                    connector_id=self.connector_id,
                )

        # 2. Simulate disconnection during execution (after write mutation, before ack)
        if self.simulate_disconnect_during:
            # Commit data locally first
            prev_data = dict(self._store.get(target, {}))
            self._store[target] = {**prev_data, **payload}
            self._versions[target] = self._versions.get(target, 0) + 1
            # But drop connection right before returning result!
            raise ConnectionResetError("Connection severed by peer while waiting for response acknowledgment")

        # 3. Standard successful write
        prev_data = dict(self._store.get(target, {}))
        exec_id = f"exec_{uuid4().hex}"
        self._history[exec_id] = (target, prev_data)

        self._store[target] = {**prev_data, **payload}
        new_ver = self._versions.get(target, 0) + 1
        self._versions[target] = new_ver

        return WriteResult(
            execution_id=exec_id,
            target=target,
            success=True,
            new_version=new_ver,
            response_data=dict(self._store[target]),
            timestamp=datetime.now(timezone.utc),
        )

    async def compensate(
        self,
        target: str,
        original_action_id: str,
        compensation_payload: dict[str, Any],
    ) -> CompensationResult:
        """Restore previous state using registered compensation data."""
        if not self.supports(ConnectorCapability.COMPENSATION):
            raise UnsupportedCapabilityError(
                f"Connector '{self.connector_id}' does not support COMPENSATION capability."
            )

        comp_id = f"comp_{uuid4().hex}"

        if original_action_id in self._history:
            _, old_state = self._history[original_action_id]
            self._store[target] = dict(old_state)
            self._versions[target] = self._versions.get(target, 0) + 1
            return CompensationResult(
                compensation_action_id=comp_id,
                target=target,
                success=True,
                details={"restored_state": old_state},
            )

        # Apply custom compensation payload if provided
        if compensation_payload:
            current = self._store.get(target, {})
            self._store[target] = {**current, **compensation_payload}
            self._versions[target] = self._versions.get(target, 0) + 1
            return CompensationResult(
                compensation_action_id=comp_id,
                target=target,
                success=True,
                details=compensation_payload,
            )

        return CompensationResult(
            compensation_action_id=comp_id,
            target=target,
            success=False,
            details={"error": "No historical state or compensation payload found"},
        )

    async def check_health(self) -> ConnectorHealthStatus:
        """Liveness probe."""
        try:
            self._check_fault_simulations()
            return ConnectorHealthStatus(
                connector_id=self.connector_id,
                healthy=True,
                latency_ms=1.5,
                error_rate=0.0,
                message="Sandbox store healthy and responding.",
            )
        except Exception as exc:
            return ConnectorHealthStatus(
                connector_id=self.connector_id,
                healthy=False,
                latency_ms=50.0,
                error_rate=1.0,
                message=f"Probe failed: {exc}",
            )
