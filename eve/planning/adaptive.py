"""Adaptive Planner — bounded, scope-preserving replanning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..domain.enums import Phase
from ..domain.models import ExecutionResult, Plan, PlannedStep
from ..ids import step_id
from .interpreter import OperationIntent


@dataclass
class Adaptation:
    new_steps: List[PlannedStep]
    rationale: str


class AdaptivePlanner:
    def revise(self, plan: Plan, step: PlannedStep, result: ExecutionResult,
               intent: OperationIntent) -> Adaptation:
        if not result.unexpected:
            return Adaptation([], "no adaptation required")
        if step.target not in intent.targets:
            return Adaptation([], "unexpected result outside authorized targets; ignored")

        new_services = []
        for svc in result.output.get("services", []):
            if svc.get("note") or svc.get("name", "").endswith("-admin"):
                new_services.append(svc)
        if not new_services:
            return Adaptation([], "unexpected result had no actionable new services")

        injected: List[PlannedStep] = []
        enum_id = step_id()
        injected.append(PlannedStep(
            id=enum_id, phase=Phase.ENUMERATION, tool_id="sim.enum",
            action="service_enum", target=step.target,
            params={"service": new_services[0]["name"]},
            depends_on=[step.id], max_retries=step.max_retries,
            rationale=f"adaptive: enumerate unexpected service "
                      f"{new_services[0]['name']} on {step.target}"))
        vuln_id = step_id()
        injected.append(PlannedStep(
            id=vuln_id, phase=Phase.VULNERABILITY_ANALYSIS, tool_id="sim.vuln",
            action="vuln_analysis", target=step.target, depends_on=[enum_id],
            max_retries=step.max_retries,
            rationale=f"adaptive: analyze unexpected service on {step.target}"))
        return Adaptation(
            injected,
            f"discovered {len(new_services)} unexpected service(s) on "
            f"{step.target}; injected in-scope enumeration + analysis")
