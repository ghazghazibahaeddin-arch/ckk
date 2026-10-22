"""Connector Health Monitoring for CCK.

Monitors connectivity, latency, and failure rates, making a strict architectural
distinction between connector infrastructure failures (network/auth/timeout)
and CCK governance gate blocks (policy/freshness rejections).
"""

from collections import defaultdict
from datetime import datetime, timezone

from cck.connectors.interface import ConnectorHealthStatus


class ConnectorMetrics:
    """Internal metrics accumulator for a single connector."""

    def __init__(self) -> None:
        self.total_calls: int = 0
        self.successful_calls: int = 0
        self.connector_failures: int = 0
        self.policy_gate_blocks: int = 0  # Governance blocks do NOT degrade connector health!
        self.total_latency_ms: float = 0.0
        self.last_checked: datetime = datetime.now(timezone.utc)
        self.last_error: str | None = None


class ConnectorHealthMonitor:
    """Monitors health status and operational metrics across connectors."""

    def __init__(self) -> None:
        self._metrics: dict[str, ConnectorMetrics] = defaultdict(ConnectorMetrics)

    def record_success(self, connector_id: str, latency_ms: float) -> None:
        """Record a successful connector execution."""
        m = self._metrics[connector_id]
        m.total_calls += 1
        m.successful_calls += 1
        m.total_latency_ms += latency_ms
        m.last_checked = datetime.now(timezone.utc)

    def record_failure(self, connector_id: str, latency_ms: float, error_message: str) -> None:
        """Record an actual connector/infrastructure error."""
        m = self._metrics[connector_id]
        m.total_calls += 1
        m.connector_failures += 1
        m.total_latency_ms += latency_ms
        m.last_error = error_message
        m.last_checked = datetime.now(timezone.utc)

    def record_policy_block(self, connector_id: str) -> None:
        """Record a CCK policy or freshness gate rejection.

        Crucial distinction:
        A policy block is a governance rejection by CCK, NOT a breakdown
        of the connector's connectivity or remote service health.
        """
        m = self._metrics[connector_id]
        m.policy_gate_blocks += 1

    def get_health(self, connector_id: str) -> ConnectorHealthStatus:
        """Compute live health status for a connector."""
        m = self._metrics[connector_id]
        if m.total_calls == 0:
            return ConnectorHealthStatus(
                connector_id=connector_id,
                healthy=True,
                latency_ms=0.0,
                error_rate=0.0,
                message="No requests recorded yet.",
            )

        avg_latency = m.total_latency_ms / m.total_calls
        error_rate = m.connector_failures / m.total_calls
        healthy = error_rate < 0.5

        msg = "Healthy" if healthy else f"Degraded: High failure rate ({error_rate * 100:.1f}%)"
        if m.last_error and not healthy:
            msg += f" - Last error: {m.last_error}"

        return ConnectorHealthStatus(
            connector_id=connector_id,
            healthy=healthy,
            latency_ms=avg_latency,
            error_rate=error_rate,
            last_checked=m.last_checked,
            message=msg,
        )
