"""Unit tests for CCK Control Plane (Layer 3).

Verifies:
1. Policy management and version registration.
2. RBAC/ABAC attribute and trust tier least privilege checks.
3. Human approval workflow: request, sign-off by privileged role, state diff verification, and reuse prevention.
4. Resource reservations: TTL lease acquisition, renewal, release, and concurrency conflict detection.
"""

import pytest

from cck.contracts.action import AgentAction, AgentIdentity
from cck.control.approvals import ApprovalWorkflowManager
from cck.control.policy_manager import PolicyManager, RBACABACEngine
from cck.control.reservations import ReservationManager
from cck.core.exceptions import ApprovalError, ReservationConflictError
from cck.core.types import ActionSeverity, ApprovalStatus, ReservationStatus


@pytest.fixture
def sample_action() -> AgentAction:
    return AgentAction(
        action_id="act-test-ctrl-1",
        agent=AgentIdentity(agent_id="agt-1", name="Bot", trust_tier="standard"),
        session_id="sess-ctrl-1",
        capability="database.update",
        target="users_table",
        parameters={"role": "admin"},
        severity=ActionSeverity.MUTATION,
    )


def test_policy_manager_versioning() -> None:
    """PolicyManager registers and tracks active policy versions."""
    mgr = PolicyManager()
    assert mgr.get_active_version() == "1.0.0"

    mgr.register_version(policy_version="1.1.0", rules=[], description="Updated rules")
    mgr.set_active_version("1.1.0")
    assert mgr.get_active_version() == "1.1.0"

    rec = mgr.get_version_record("1.1.0")
    assert rec.description == "Updated rules"


def test_rbac_abac_least_privilege() -> None:
    """RBAC/ABAC engine correctly enforces capability permissions by trust tier."""
    # Standard agent allowed database.update
    allowed, _ = RBACABACEngine.check_permissions("standard", "database.update", "table")
    assert allowed is True

    # Sandboxed agent denied database.update
    allowed, _ = RBACABACEngine.check_permissions("sandboxed", "database.update", "table")
    assert allowed is False

    # Admin tier has wildcard
    allowed, _ = RBACABACEngine.check_permissions("admin", "any.capability", "target")
    assert allowed is True


def test_approval_workflow_lifecycle_and_reuse_prevention(sample_action: AgentAction) -> None:
    """Approval workflow requires privileged approver, checks state diff, and prevents reuse."""
    approvals = ApprovalWorkflowManager()

    record = approvals.request_approval(
        action=sample_action,
        reason="Privileged grant",
        policy_version="1.0.0",
        state_snapshot={"status": "pending"},
    )
    assert record.status == ApprovalStatus.PENDING

    # Unauthorized approver role (e.g. 'sandboxed_user') is rejected
    with pytest.raises(ApprovalError) as exc_info:
        approvals.resolve_approval(
            approval_id=record.approval_id,
            approved=True,
            approver_id="user-evil",
            approver_role="sandboxed_user",
        )
    assert "unauthorized to sign off" in str(exc_info.value)

    # Authorized operator sign-off
    resolved = approvals.resolve_approval(
        approval_id=record.approval_id,
        approved=True,
        approver_id="admin-supervisor",
        approver_role="admin",
    )
    assert resolved.status == ApprovalStatus.APPROVED

    # Consuming approval with matching state succeeds
    consumed = approvals.consume_approval(record.approval_id, current_state={"status": "pending"})
    assert consumed.used is True

    # Reusing the same approval token must be strictly prohibited!
    with pytest.raises(ApprovalError) as exc_info:
        approvals.consume_approval(record.approval_id, current_state={"status": "pending"})
    assert "already been consumed" in str(exc_info.value)


def test_approval_state_drift_rejection(sample_action: AgentAction) -> None:
    """Consuming approval detects state drift between request and execution."""
    approvals = ApprovalWorkflowManager()
    record = approvals.request_approval(
        action=sample_action,
        reason="Approval test",
        policy_version="1.0.0",
        state_snapshot={"status": "pending"},
    )
    approvals.resolve_approval(record.approval_id, True, "admin-user", "admin")

    # State drifted from 'pending' to 'cancelled'
    with pytest.raises(ApprovalError) as exc_info:
        approvals.consume_approval(record.approval_id, current_state={"status": "cancelled"})
    assert "Approval context changed!" in str(exc_info.value)


def test_reservation_manager_concurrency_and_ttl() -> None:
    """ReservationManager handles TTL leases, renewal, release, and conflict detection."""
    rm = ReservationManager()

    # 1. Acquire reservation
    res1 = rm.acquire_reservation("resource:alpha", holder_id="agent-A", ttl_seconds=30.0)
    assert res1.status == ReservationStatus.ACTIVE

    # 2. Conflicting acquisition by another agent raises ReservationConflictError
    with pytest.raises(ReservationConflictError) as exc_info:
        rm.acquire_reservation("resource:alpha", holder_id="agent-B", ttl_seconds=30.0)
    assert "already actively reserved" in str(exc_info.value)

    # 3. Same agent can renew
    renewed = rm.renew_reservation("resource:alpha", holder_id="agent-A", extension_seconds=60.0)
    assert renewed.expires_at > res1.expires_at

    # 4. Release reservation
    released = rm.release_reservation("resource:alpha", holder_id="agent-A")
    assert released.status == ReservationStatus.RELEASED

    # 5. Now another agent can acquire it
    res2 = rm.acquire_reservation("resource:alpha", holder_id="agent-B", ttl_seconds=30.0)
    assert res2.holder_id == "agent-B"
    assert res2.status == ReservationStatus.ACTIVE
