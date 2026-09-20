"""Domain value objects (Pydantic v2)."""
from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .enums import Confidence, OperationState, Phase, Severity, StepState


class Target(BaseModel):
    identifier: str
    kind: str = "host"
    labels: Dict[str, str] = Field(default_factory=dict)


class PlannedStep(BaseModel):
    id: str
    phase: Phase
    tool_id: str
    action: str
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    state: StepState = StepState.PENDING
    attempts: int = 0
    max_retries: int = 2
    rationale: str = ""
    result_id: Optional[str] = None
    error: Optional[str] = None


class Plan(BaseModel):
    steps: List[PlannedStep] = Field(default_factory=list)
    revision: int = 0

    def by_id(self, step_id: str) -> Optional[PlannedStep]:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None


class Evidence(BaseModel):
    id: str
    step_id: str
    target: str
    kind: str
    summary: str
    data: Dict[str, Any] = Field(default_factory=dict)
    sha256: str = ""
    created_at: _dt.datetime


class Finding(BaseModel):
    id: str
    title: str
    target: str
    phase: Phase
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.UNVERIFIED
    description: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    remediation: str = ""
    affected_components: List[str] = Field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    cvss: float = 0.0
    references: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    meta: Dict[str, Any] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    id: str
    step_id: str
    tool_id: str
    action: str
    ok: bool
    unexpected: bool = False
    output: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0


class Report(BaseModel):
    operation_id: str
    goal: str
    generated_at: _dt.datetime
    summary: str
    targets: List[str]
    findings: List[Finding]
    steps_total: int
    steps_succeeded: int
    steps_failed: int
    adaptations: int
    outcome: str
    executive_summary: str = ""
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0
    owasp_coverage: List[str] = Field(default_factory=list)
    methodology: List[str] = Field(default_factory=list)


class OperationSnapshot(BaseModel):
    id: str
    request_id: str
    goal: str
    actor: str
    state: OperationState
    targets: List[str]
    current_step: Optional[str]
    plan: Plan
    findings: List[Finding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    adaptations: int = 0
    authorization_ok: bool = False
    approval_ok: bool = False
    sentinel_ok: bool = False
    created_at: _dt.datetime
    updated_at: _dt.datetime
    started_at: Optional[_dt.datetime] = None
    finished_at: Optional[_dt.datetime] = None
    report: Optional[Report] = None
