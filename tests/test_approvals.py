"""Approval enforcement + binding."""
import pytest

from eve.domain.enums import OperationState
from eve.errors import ApprovalError


def test_operation_waits_for_approval(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full",
                              targets=["lab-web-01"], require_approval=True)
    assert snap.state == OperationState.AWAITING_APPROVAL
    # running without approval does nothing
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.AWAITING_APPROVAL


def test_approval_unblocks_and_completes(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full",
                              targets=["lab-web-01"], require_approval=True)
    snap = c.approve(snap.id, approver="approver")
    assert snap.state == OperationState.QUEUED and snap.approval_ok
    snap = c.run_to_completion(snap.id)
    assert snap.state == OperationState.SUCCEEDED


def test_double_approval_rejected(authorized_engine):
    c = authorized_engine.controller
    snap = c.create_operation(actor="operator", goal="full",
                              targets=["lab-web-01"], require_approval=True)
    c.approve(snap.id, approver="approver")
    with pytest.raises(ApprovalError):
        c.approve(snap.id, approver="approver")


def test_approval_bound_to_operation(authorized_engine):
    """An approval for op A cannot satisfy op B (different request id)."""
    c = authorized_engine.controller
    a = c.create_operation(actor="operator", goal="full",
                           targets=["lab-web-01"], require_approval=True)
    c.approve(a.id, approver="approver")
    # a second operation gets its own request id and remains blocked
    b = c.create_operation(actor="operator", goal="full",
                           targets=["lab-web-01"], require_approval=True)
    assert b.request_id != a.request_id
    b = c.run_to_completion(b.id)
    assert b.state == OperationState.AWAITING_APPROVAL
