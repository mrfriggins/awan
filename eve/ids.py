"""Prefixed, sortable identifiers."""
from __future__ import annotations

import uuid


def _new(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


def operation_id() -> str:
    return _new("op")


def step_id() -> str:
    return _new("step")


def event_id() -> str:
    return _new("evt")


def approval_id() -> str:
    return _new("apr")


def authorization_id() -> str:
    return _new("authz")


def evidence_id() -> str:
    return _new("ev")


def result_id() -> str:
    return _new("res")


def request_id() -> str:
    return _new("req")
