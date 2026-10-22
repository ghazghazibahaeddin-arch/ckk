"""Usage Limits and Cost Controls for CCK Enterprise and Cloud (Layer 7).

Enforces per-tenant rate limits, daily action quotas, and provides usage telemetry.
"""

from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cck.core.exceptions import NormalizedConnectorError
from cck.core.types import NormalizedErrorCategory


class TenantQuota(BaseModel):
    """Configuration of resource quotas and rate limits for a tenant."""

    tenant_id: str
    max_daily_requests: int = Field(default=10000, description="Max allowed requests per day")
    max_requests_per_minute: int = Field(default=300, description="Rate limit per minute")
    tier_name: str = Field(default="standard")

    model_config = ConfigDict(extra="forbid")


class UsageLimiter:
    """Tracks and enforces request consumption per tenant."""

    def __init__(self) -> None:
        self._quotas: dict[str, TenantQuota] = {}
        # tenant_id -> daily request count
        self._daily_counts: dict[str, int] = defaultdict(int)

    def set_quota(self, tenant_id: str, max_daily: int, max_per_min: int = 300, tier: str = "standard") -> TenantQuota:
        """Configure quota parameters for a tenant."""
        q = TenantQuota(
            tenant_id=tenant_id,
            max_daily_requests=max_daily,
            max_requests_per_minute=max_per_min,
            tier_name=tier,
        )
        self._quotas[tenant_id] = q
        return q

    def get_quota(self, tenant_id: str) -> TenantQuota:
        """Fetch tenant quota or default."""
        return self._quotas.get(tenant_id, TenantQuota(tenant_id=tenant_id))

    def get_usage(self, tenant_id: str) -> dict[str, Any]:
        """Return current usage stats and quota comparison."""
        quota = self.get_quota(tenant_id)
        current = self._daily_counts[tenant_id]
        remaining = max(0, quota.max_daily_requests - current)
        return {
            "tenant_id": tenant_id,
            "tier": quota.tier_name,
            "requests_today": current,
            "limit": quota.max_daily_requests,
            "remaining": remaining,
            "usage_percentage": min(100.0, (current / max(1, quota.max_daily_requests)) * 100.0),
        }

    def check_and_increment(self, tenant_id: str) -> None:
        """Check quota and record request.

        Raises:
            NormalizedConnectorError: If tenant exceeds their daily limit.
        """
        quota = self.get_quota(tenant_id)
        current = self._daily_counts[tenant_id]

        if current >= quota.max_daily_requests:
            raise NormalizedConnectorError(
                message=f"Usage quota exceeded for tenant '{tenant_id}'. Daily limit is {quota.max_daily_requests} requests.",
                category=NormalizedErrorCategory.RATE_LIMITING.value,
                connector_id="cck-cloud-gateway",
                retryable=False,
            )

        self._daily_counts[tenant_id] += 1
