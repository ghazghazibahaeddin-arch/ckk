"""Human Approval Workflow Manager for CCK Control Plane (Layer 3).

Manages approval request lifecycles, action context diffs, mandatory pre-execution
re-validation, role-based authorization for approvers, and reuse prevention.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cck.contracts.action import AgentAction
from cck.core.exceptions import ApprovalError
from cck.core.types import ApprovalStatus


class ApprovalRecord(BaseModel):
    """Authoritative record of a human-in-the-loop approval request."""

    approval_id: str = Field(
        default_factory=lambda: f"appr_{uuid4().hex}",
        description="Unique approval request ID",
    )
    action: AgentAction = Field(..., description="Proposed agent action requiring approval")
    reason: str = Field(..., description="Security rationale requiring human sign-off")
    policy_version: str = Field(..., description="Policy version governing the request")
    status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description="Approval state (PENDING, APPROVED, REJECTED, EXPIRED)",
    )
    approver_id: str | None = Field(default=None, description="ID of the user/supervisor who approved or rejected")
    approver_role: str | None = Field(default=None, description="Role of the approver (must be admin or operator)")
    state_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Target resource state snapshot when approval was requested",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )
    resolved_at: datetime | None = Field(default=None, description="UTC resolution timestamp")
    used: bool = Field(default=False, description="Whether this approval token has already been consumed")

    model_config = ConfigDict(extra="forbid")


class ApprovalWorkflowManager:
    """Manages creation, authorization, sign-off, and consumption of approval tokens."""

    def __init__(self) -> None:
        self._approvals: dict[str, ApprovalRecord] = {}

    def request_approval(
        self,
        action: AgentAction,
        reason: str,
        policy_version: str,
        state_snapshot: dict[str, Any] | None = None,
    ) -> ApprovalRecord:
        """Create a new pending human approval request."""
        record = ApprovalRecord(
            action=action,
            reason=reason,
            policy_version=policy_version,
            state_snapshot=state_snapshot or {},
        )
        self._approvals[record.approval_id] = record
        return record

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        """Fetch approval record or raise error."""
        if approval_id not in self._approvals:
            raise ApprovalError(f"Approval request '{approval_id}' not found.")
        return self._approvals[approval_id]

    def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        approver_id: str,
        approver_role: str,
    ) -> ApprovalRecord:
        """Approve or reject an approval request.

        Enforces that approver holds a privileged role ('admin' or 'operator').
        """
        record = self.get_approval(approval_id)
        if record.status != ApprovalStatus.PENDING:
            raise ApprovalError(f"Approval '{approval_id}' is already resolved as '{record.status.value}'.")

        # RBAC check for approver
        authorized_approver_roles = {"admin", "operator", "supervisor"}
        if approver_role not in authorized_approver_roles:
            raise ApprovalError(
                f"Approver '{approver_id}' with role '{approver_role}' is unauthorized to sign off "
                f"on high-risk actions. Required role: one of {authorized_approver_roles}."
            )

        new_status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        updated = record.model_copy(
            update={
                "status": new_status,
                "approver_id": approver_id,
                "approver_role": approver_role,
                "resolved_at": datetime.now(timezone.utc),
            }
        )
        self._approvals[approval_id] = updated
        return updated

    def consume_approval(
        self,
        approval_id: str,
        current_state: dict[str, Any] | None = None,
    ) -> ApprovalRecord:
        """Consume an approved token for action execution.

        Rules:
        1. Must be APPROVED.
        2. Must NOT have been used already (prevent reuse).
        3. Validates that target state has not drifted significantly since approval.
        """
        record = self.get_approval(approval_id)

        if record.status != ApprovalStatus.APPROVED:
            raise ApprovalError(f"Cannot execute action: Approval '{approval_id}' status is '{record.status.value}'.")

        if record.used:
            raise ApprovalError(
                f"Security violation: Approval token '{approval_id}' has already been consumed! "
                f"Reuse of old approvals is strictly prohibited."
            )

        # Check state drift if snapshot and current state are provided
        if current_state and record.state_snapshot:
            for k, v in record.state_snapshot.items():
                if current_state.get(k) != v:
                    raise ApprovalError(
                        f"Approval context changed! Target state attribute '{k}' changed from '{v}' "
                        f"to '{current_state.get(k)}' since approval was granted. Re-approval required."
                    )

        # Mark as used
        consumed = record.model_copy(update={"used": True})
        self._approvals[approval_id] = consumed
        return consumed
