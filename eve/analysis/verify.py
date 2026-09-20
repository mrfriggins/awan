"""Verification Engine — goal-satisfaction + validation reconciliation."""
from __future__ import annotations

from typing import Dict, List

from ..domain.enums import Confidence, StepState
from ..domain.models import Finding, Plan


class VerificationEngine:
    def goal_satisfied(self, plan: Plan) -> bool:
        if not plan.steps:
            return False
        for s in plan.steps:
            if s.state in (StepState.PENDING, StepState.READY,
                           StepState.RUNNING, StepState.RETRYING):
                return False
        return True

    def apply_validation(self, findings: List[Finding],
                         verdicts: Dict[str, str]) -> None:
        for f in findings:
            verdict = verdicts.get(f.id)
            if verdict == "CONFIRMED":
                f.confidence = Confidence.CONFIRMED
            elif verdict == "FALSE_POSITIVE":
                f.confidence = Confidence.FALSE_POSITIVE

    def confirmed(self, findings: List[Finding]) -> List[Finding]:
        return [f for f in findings if f.confidence == Confidence.CONFIRMED]
