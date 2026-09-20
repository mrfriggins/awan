"""Reporting Engine — structured technical report generation."""
from __future__ import annotations

from typing import List

from ..clock import Clock, SystemClock
from ..domain.enums import Confidence, StepState
from ..domain.models import Finding, Plan, Report


class ReportingEngine:
    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()

    def build(self, *, operation_id: str, goal: str, targets: List[str],
              plan: Plan, findings: List[Finding], adaptations: int,
              outcome: str) -> Report:
        succeeded = sum(1 for s in plan.steps if s.state == StepState.SUCCEEDED)
        failed = sum(1 for s in plan.steps if s.state == StepState.FAILED)
        confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
        fps = [f for f in findings if f.confidence == Confidence.FALSE_POSITIVE]
        summary = (
            f"Assessed {len(targets)} target(s) across {len(plan.steps)} steps. "
            f"{len(confirmed)} confirmed finding(s), "
            f"{len(findings) - len(confirmed) - len(fps)} unconfirmed, "
            f"{len(fps)} false positive(s). Outcome: {outcome}.")
        reportable = sorted(
            [f for f in findings if f.confidence != Confidence.FALSE_POSITIVE],
            key=lambda f: (f.confidence != Confidence.CONFIRMED, f.severity.value))
        return Report(
            operation_id=operation_id, goal=goal,
            generated_at=self.clock.now(), summary=summary, targets=targets,
            findings=reportable, steps_total=len(plan.steps),
            steps_succeeded=succeeded, steps_failed=failed,
            adaptations=adaptations, outcome=outcome)
