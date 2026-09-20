"""Data-access layer. All engine persistence flows through Repository."""
from __future__ import annotations

import datetime as _dt
from typing import List, Optional

from sqlalchemy import select

from ..domain.models import OperationSnapshot
from .db import Database
from .tables import (ApprovalRow, EvidenceRow, ExecutionResultRow,
                     OperationEventRow, OperationRow, OperationStepRow,
                     TargetAuthorizationRow, ToolRegistrationRow)


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def save_operation(self, snap: OperationSnapshot) -> None:
        payload = snap.model_dump(mode="json")
        with self.db.session() as s:
            row = s.get(OperationRow, snap.id)
            if row is None:
                row = OperationRow(id=snap.id, request_id=snap.request_id,
                                   goal=snap.goal, actor=snap.actor,
                                   state=snap.state.value, snapshot=payload,
                                   created_at=snap.created_at,
                                   updated_at=snap.updated_at)
                s.add(row)
            else:
                row.state = snap.state.value
                row.snapshot = payload
                row.updated_at = snap.updated_at
            for st in snap.plan.steps:
                srow = s.get(OperationStepRow, st.id)
                if srow is None:
                    s.add(OperationStepRow(
                        id=st.id, operation_id=snap.id, phase=st.phase.value,
                        tool_id=st.tool_id, action=st.action, target=st.target,
                        state=st.state.value, attempts=st.attempts,
                        depends_on=list(st.depends_on)))
                else:
                    srow.state = st.state.value
                    srow.attempts = st.attempts
                    srow.updated_at = _dt.datetime.now(_dt.timezone.utc)

    def load_operation(self, operation_id: str) -> Optional[OperationSnapshot]:
        with self.db.session() as s:
            row = s.get(OperationRow, operation_id)
            if row is None:
                return None
            return OperationSnapshot.model_validate(row.snapshot)

    def list_operations(self, limit: int = 100) -> List[OperationSnapshot]:
        with self.db.session() as s:
            rows = s.execute(
                select(OperationRow).order_by(OperationRow.created_at.desc()).limit(limit)
            ).scalars().all()
            return [OperationSnapshot.model_validate(r.snapshot) for r in rows]

    def last_event_hash(self, operation_id: str) -> str:
        with self.db.session() as s:
            row = s.execute(
                select(OperationEventRow)
                .where(OperationEventRow.operation_id == operation_id)
                .order_by(OperationEventRow.seq.desc()).limit(1)
            ).scalar_one_or_none()
            return row.hash if row else ""

    def next_event_seq(self, operation_id: str) -> int:
        with self.db.session() as s:
            row = s.execute(
                select(OperationEventRow)
                .where(OperationEventRow.operation_id == operation_id)
                .order_by(OperationEventRow.seq.desc()).limit(1)
            ).scalar_one_or_none()
            return (row.seq + 1) if row else 0

    def append_event(self, **kw) -> None:
        with self.db.session() as s:
            s.add(OperationEventRow(**kw))

    def list_events(self, operation_id: str) -> List[OperationEventRow]:
        with self.db.session() as s:
            rows = s.execute(
                select(OperationEventRow)
                .where(OperationEventRow.operation_id == operation_id)
                .order_by(OperationEventRow.seq.asc())
            ).scalars().all()
            s.expunge_all()
            return rows

    def save_result(self, operation_id: str, result) -> None:
        with self.db.session() as s:
            s.add(ExecutionResultRow(
                id=result.id, operation_id=operation_id, step_id=result.step_id,
                tool_id=result.tool_id, action=result.action, ok=result.ok,
                unexpected=result.unexpected, output=result.output,
                error=result.error or "", duration_ms=result.duration_ms))

    def save_evidence(self, operation_id: str, ev) -> None:
        with self.db.session() as s:
            if s.get(EvidenceRow, ev.id) is not None:
                return  # deduped evidence already persisted
            s.add(EvidenceRow(
                id=ev.id, operation_id=operation_id, step_id=ev.step_id,
                target=ev.target, kind=ev.kind, summary=ev.summary,
                data=ev.data, sha256=ev.sha256))

    def list_evidence(self, operation_id: str) -> List[EvidenceRow]:
        with self.db.session() as s:
            rows = s.execute(
                select(EvidenceRow).where(EvidenceRow.operation_id == operation_id)
            ).scalars().all()
            s.expunge_all()
            return rows

    def upsert_tool(self, tool_id: str, version: str, name: str, spec: dict,
                    available: bool = True) -> None:
        with self.db.session() as s:
            row = s.get(ToolRegistrationRow, (tool_id, version))
            if row is None:
                s.add(ToolRegistrationRow(tool_id=tool_id, version=version,
                                          name=name, spec=spec, available=available))
            else:
                row.spec = spec
                row.available = available

    def add_authorization(self, row: TargetAuthorizationRow) -> None:
        with self.db.session() as s:
            s.add(row)

    def list_authorizations(self, actor: str) -> List[TargetAuthorizationRow]:
        with self.db.session() as s:
            rows = s.execute(
                select(TargetAuthorizationRow)
                .where(TargetAuthorizationRow.actor == actor)
            ).scalars().all()
            s.expunge_all()
            return rows

    def add_approval(self, row: ApprovalRow) -> None:
        with self.db.session() as s:
            s.add(row)

    def get_approval_by_request(self, request_id: str) -> Optional[ApprovalRow]:
        with self.db.session() as s:
            row = s.execute(
                select(ApprovalRow).where(ApprovalRow.request_id == request_id)
            ).scalar_one_or_none()
            if row is not None:
                s.expunge(row)
            return row

    def consume_approval(self, approval_id: str) -> None:
        with self.db.session() as s:
            row = s.get(ApprovalRow, approval_id)
            if row is not None:
                row.consumed = True
