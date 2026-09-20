"""Approval management. Approvals are single-use and tightly bound."""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import List

from ..clock import Clock, SystemClock
from ..errors import ApprovalError
from ..ids import approval_id
from ..persistence.repository import Repository
from ..persistence.tables import ApprovalRow


@dataclass(frozen=True)
class ApprovalGrant:
    id: str
    request_id: str
    operation_id: str
    actor: str
    approver: str
    target: str
    allowed_actions: List[str]


class ApprovalManager:
    def __init__(self, repo: Repository, clock: Clock | None = None) -> None:
        self.repo = repo
        self.clock = clock or SystemClock()

    def grant(self, *, request_id: str, operation_id: str, actor: str,
              approver: str, target: str, allowed_actions: List[str],
              ttl_seconds: int = 3600) -> ApprovalGrant:
        if self.repo.get_approval_by_request(request_id) is not None:
            raise ApprovalError(f"approval already exists for request '{request_id}'")
        row = ApprovalRow(
            id=approval_id(), request_id=request_id, operation_id=operation_id,
            actor=actor, approver=approver, target=target,
            allowed_actions=list(allowed_actions),
            expires_at=self.clock.now() + _dt.timedelta(seconds=ttl_seconds),
            consumed=False)
        self.repo.add_approval(row)
        return ApprovalGrant(row.id, request_id, operation_id, actor, approver,
                             target, list(allowed_actions))

    def verify(self, *, request_id: str, operation_id: str, actor: str,
               target: str, action: str, consume: bool = False) -> ApprovalGrant:
        row = self.repo.get_approval_by_request(request_id)
        if row is None:
            raise ApprovalError(f"no approval for request '{request_id}'")
        if row.operation_id != operation_id:
            raise ApprovalError("approval bound to a different operation")
        if row.actor != actor:
            raise ApprovalError("approval bound to a different actor")
        if row.target != target:
            raise ApprovalError("approval bound to a different target")
        if row.consumed:
            raise ApprovalError("approval already consumed")
        if _aware(row.expires_at) <= self.clock.now():
            raise ApprovalError("approval expired")
        if row.allowed_actions and action not in row.allowed_actions:
            raise ApprovalError(f"action '{action}' not covered by approval")
        if consume:
            self.repo.consume_approval(row.id)
        return ApprovalGrant(row.id, row.request_id, row.operation_id, row.actor,
                             row.approver, row.target, list(row.allowed_actions))


def _aware(dt: _dt.datetime) -> _dt.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_dt.timezone.utc)
    return dt
