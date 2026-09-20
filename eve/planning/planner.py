"""Operation Planner + plan validation (dependency graph, cycles, dupes)."""
from __future__ import annotations

from typing import Dict, List

from ..domain.enums import Phase, StepState
from ..domain.models import Plan, PlannedStep
from ..errors import ValidationError
from ..ids import step_id
from ..tools.registry import ToolRegistry
from .interpreter import OperationIntent

_PHASE_PLAN = {
    Phase.RECONNAISSANCE: [("sim.recon", "asset_inventory"),
                           ("sim.recon", "service_discovery"),
                           ("sim.recon", "tech_identification")],
    Phase.ENUMERATION: [("sim.enum", "service_enum"),
                        ("sim.enum", "config_analysis")],
    Phase.VULNERABILITY_ANALYSIS: [("sim.vuln", "vuln_analysis")],
    Phase.VALIDATION: [("sim.validate", "validate_finding")],
    Phase.POST_ASSESSMENT: [],
}

_LIVE_PHASE_PLAN = {
    Phase.RECONNAISSANCE: [("net.recon", "asset_inventory"),
                           ("net.recon", "service_discovery"),
                           ("net.recon", "tech_identification")],
    Phase.ENUMERATION: [("net.enum", "service_enum"),
                        ("net.enum", "config_analysis"),
                        ("net.enum", "http_methods"),
                        ("net.enum", "content_probe")],
    Phase.VULNERABILITY_ANALYSIS: [("net.vuln", "vuln_analysis")],
    Phase.VALIDATION: [("net.validate", "validate_finding")],
    Phase.POST_ASSESSMENT: [],
}

_TOOLSETS = {"sim": _PHASE_PLAN, "live": _LIVE_PHASE_PLAN}


class OperationPlanner:
    def __init__(self, registry: ToolRegistry, max_retries: int = 2) -> None:
        self.registry = registry
        self.max_retries = max_retries

    def build(self, intent: OperationIntent) -> Plan:
        steps: List[PlannedStep] = []
        toolset = _TOOLSETS.get(getattr(intent, "mode", "sim"), _PHASE_PLAN)
        for target in intent.targets:
            prev_phase_last: List[str] = []
            for phase in intent.phases:
                specs = toolset.get(phase, [])
                phase_ids: List[str] = []
                for tool_id, action in specs:
                    sid = step_id()
                    params: Dict[str, object] = {}
                    if action == "config_analysis":
                        params = {"service": "http"}
                    step = PlannedStep(
                        id=sid, phase=phase, tool_id=tool_id, action=action,
                        target=target, params=params,
                        depends_on=list(prev_phase_last),
                        max_retries=self.max_retries,
                        rationale=f"{phase.value.lower()} via {tool_id}.{action}")
                    steps.append(step)
                    phase_ids.append(sid)
                if phase_ids:
                    prev_phase_last = phase_ids
        return Plan(steps=steps, revision=0)

    def validate(self, plan: Plan) -> None:
        validate_plan(plan, self.registry)


def validate_plan(plan: Plan, registry: ToolRegistry) -> None:
    ids = [s.id for s in plan.steps]
    seen = set()
    for sid in ids:
        if sid in seen:
            raise ValidationError(f"duplicate step id '{sid}'")
        seen.add(sid)
    idset = set(ids)
    for s in plan.steps:
        registry.validate_action(s.tool_id, s.action)
        if not registry.is_available(s.tool_id):
            raise ValidationError(f"tool '{s.tool_id}' is unavailable")
        for dep in s.depends_on:
            if dep not in idset:
                raise ValidationError(
                    f"step '{s.id}' depends on missing step '{dep}'")
            if dep == s.id:
                raise ValidationError(f"step '{s.id}' depends on itself")
    _detect_cycle(plan)


def _detect_cycle(plan: Plan) -> None:
    graph: Dict[str, List[str]] = {s.id: list(s.depends_on) for s in plan.steps}
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {sid: WHITE for sid in graph}

    def visit(node: str, stack: List[str]) -> None:
        color[node] = GRAY
        for dep in graph.get(node, []):
            if color[dep] == GRAY:
                cyc = " -> ".join(stack + [node, dep])
                raise ValidationError(f"dependency cycle detected: {cyc}")
            if color[dep] == WHITE:
                visit(dep, stack + [node])
        color[node] = BLACK

    for sid in graph:
        if color[sid] == WHITE:
            visit(sid, [])


def ready_steps(plan: Plan) -> List[PlannedStep]:
    done = {s.id for s in plan.steps if s.state == StepState.SUCCEEDED}
    out = []
    for s in plan.steps:
        if s.state != StepState.PENDING:
            continue
        if all(dep in done for dep in s.depends_on):
            out.append(s)
    return out
