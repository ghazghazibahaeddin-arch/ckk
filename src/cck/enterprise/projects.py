"""Projects Management for CCK Cloud Service (Layer 7).

Manages project workspaces, connector associations, and tenant scoping.
"""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ProjectRecord(BaseModel):
    """Metadata record of an isolated project within a tenant organization."""

    project_id: str = Field(default_factory=lambda: f"proj_{uuid4().hex[:8]}")
    name: str = Field(..., description="Project name")
    description: str = Field(default="", description="Project description")
    tenant_id: str = Field(..., description="Owner tenant organization")
    connectors: list[str] = Field(default_factory=list, description="Associated connector IDs")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="forbid")


class ProjectManager:
    """Manages project workspaces per tenant."""

    def __init__(self) -> None:
        self._projects: dict[str, ProjectRecord] = {}

    def create_project(self, name: str, tenant_id: str, description: str = "", connectors: list[str] | None = None) -> ProjectRecord:
        """Create a new project workspace under a tenant."""
        proj = ProjectRecord(
            name=name,
            tenant_id=tenant_id,
            description=description,
            connectors=connectors or ["sandbox-kv"],
        )
        self._projects[proj.project_id] = proj
        return proj

    def list_projects(self, tenant_id: str) -> list[ProjectRecord]:
        """List all projects belonging strictly to a tenant (tenant isolation)."""
        return [p for p in self._projects.values() if p.tenant_id == tenant_id]

    def get_project(self, project_id: str, tenant_id: str) -> ProjectRecord | None:
        """Retrieve project ensuring tenant ownership matches."""
        proj = self._projects.get(project_id)
        if proj and proj.tenant_id == tenant_id:
            return proj
        return None
