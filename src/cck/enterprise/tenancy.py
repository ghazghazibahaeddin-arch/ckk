"""Multi-Tenancy and Tenant Isolation for CCK Enterprise (Layer 7).

Manages tenant isolation scopes, project namespaces, and validates cross-tenant
access prevention.
"""

from pydantic import BaseModel, ConfigDict, Field

from cck.core.exceptions import PolicyViolationError


class TenantContext(BaseModel):
    """Tenant isolation scope context for queries and operations."""

    tenant_id: str = Field(..., description="Unique tenant organization ID")
    project_id: str = Field(default="default", description="Project namespace within tenant")
    tier: str = Field(default="enterprise", description="Subscription tier")

    model_config = ConfigDict(frozen=True)


class TenantIsolationEnforcer:
    """Enforces strict tenant boundary isolation across operations."""

    @staticmethod
    def assert_tenant_access(request_tenant: str, resource_tenant: str) -> None:
        """Verify that requesting tenant matches resource tenant.

        Raises:
            PolicyViolationError: If cross-tenant access is attempted.
        """
        if request_tenant != resource_tenant:
            raise PolicyViolationError(
                f"Cross-tenant access violation: Tenant '{request_tenant}' attempted to access "
                f"resources belonging to tenant '{resource_tenant}'."
            )
