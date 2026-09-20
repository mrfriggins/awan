"""SQLAlchemy ORM tables — the authoritative persistence schema."""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import (Boolean, DateTime, Integer, String, Text, JSON,
                        UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class OperationRow(Base):
    __tablename__ = "operations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    goal: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class OperationStepRow(Base):
    __tablename__ = "operation_steps"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(64), index=True)
    phase: Mapped[str] = mapped_column(String(32))
    tool_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(32))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class ToolRegistrationRow(Base):
    __tablename__ = "tool_registrations"
    tool_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    spec: Mapped[dict] = mapped_column(JSON)
    available: Mapped[bool] = mapped_column(Boolean, default=True)
    registered_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class TargetAuthorizationRow(Base):
    __tablename__ = "target_authorizations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    allowed_actions: Mapped[list] = mapped_column(JSON, default=list)
    allowed_phases: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class ApprovalRow(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    operation_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    approver: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(128))
    allowed_actions: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)
    __table_args__ = (UniqueConstraint("request_id", name="uq_approval_request"),)


class OperationEventRow(Base):
    __tablename__ = "operation_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(64), index=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    type: Mapped[str] = mapped_column(String(48))
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class ExecutionResultRow(Base):
    __tablename__ = "execution_results"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(64), index=True)
    step_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    ok: Mapped[bool] = mapped_column(Boolean)
    unexpected: Mapped[bool] = mapped_column(Boolean, default=False)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(64), index=True)
    step_id: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(48))
    summary: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_now)


ALL_TABLES = Base.metadata
