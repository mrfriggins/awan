"""Operation & step state machines with explicit, validated transitions."""
from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class OperationState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETING = "COMPLETING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    STOPPED = "STOPPED"


TERMINAL_STATES: Set[OperationState] = {
    OperationState.SUCCEEDED,
    OperationState.FAILED,
    OperationState.CANCELLED,
    OperationState.STOPPED,
}

_ALLOWED: Dict[OperationState, Set[OperationState]] = {
    OperationState.CREATED: {OperationState.VALIDATING, OperationState.CANCELLED,
                             OperationState.STOPPED, OperationState.FAILED},
    OperationState.VALIDATING: {OperationState.AWAITING_APPROVAL, OperationState.QUEUED,
                                OperationState.FAILED, OperationState.CANCELLED,
                                OperationState.STOPPED},
    OperationState.AWAITING_APPROVAL: {OperationState.QUEUED, OperationState.CANCELLED,
                                       OperationState.STOPPED, OperationState.FAILED},
    OperationState.QUEUED: {OperationState.RUNNING, OperationState.CANCELLED,
                            OperationState.STOPPED, OperationState.FAILED},
    OperationState.RUNNING: {OperationState.PAUSED, OperationState.COMPLETING,
                             OperationState.AWAITING_APPROVAL, OperationState.FAILED,
                             OperationState.CANCELLED, OperationState.STOPPED},
    OperationState.PAUSED: {OperationState.RUNNING, OperationState.CANCELLED,
                            OperationState.STOPPED, OperationState.FAILED},
    OperationState.COMPLETING: {OperationState.SUCCEEDED, OperationState.FAILED,
                                OperationState.STOPPED},
}


def can_transition(src: OperationState, dst: OperationState) -> bool:
    if src in TERMINAL_STATES:
        return False
    return dst in _ALLOWED.get(src, set())


def allowed_targets(src: OperationState) -> Set[OperationState]:
    return set(_ALLOWED.get(src, set()))


class StepState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    RETRYING = "RETRYING"


class Confidence(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Phase(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    ENUMERATION = "ENUMERATION"
    VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS"
    VALIDATION = "VALIDATION"
    POST_ASSESSMENT = "POST_ASSESSMENT"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    OPERATION_CREATED = "OPERATION_CREATED"
    STATE_CHANGED = "STATE_CHANGED"
    AUTHORIZATION_DECISION = "AUTHORIZATION_DECISION"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    SENTINEL_DECISION = "SENTINEL_DECISION"
    PLAN_GENERATED = "PLAN_GENERATED"
    TOOL_SELECTED = "TOOL_SELECTED"
    STEP_STARTED = "STEP_STARTED"
    STEP_COMPLETED = "STEP_COMPLETED"
    STEP_FAILED = "STEP_FAILED"
    STEP_RETRY = "STEP_RETRY"
    RESULT_VALIDATED = "RESULT_VALIDATED"
    FINDING_RECORDED = "FINDING_RECORDED"
    EVIDENCE_STORED = "EVIDENCE_STORED"
    ADAPTATION = "ADAPTATION"
    PAUSED = "PAUSED"
    RESUMED = "RESUMED"
    CANCELLED = "CANCELLED"
    EMERGENCY_STOP = "EMERGENCY_STOP"
    REPORT_GENERATED = "REPORT_GENERATED"
    OPERATION_FINISHED = "OPERATION_FINISHED"
    ERROR = "ERROR"
