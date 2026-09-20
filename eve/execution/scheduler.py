"""Execution Scheduler — selects the next valid step to run."""
from __future__ import annotations

from typing import Optional

from ..domain.enums import Phase
from ..domain.models import Plan, PlannedStep
from ..planning.planner import ready_steps

_PHASE_ORDER = {p: i for i, p in enumerate(Phase)}


class ExecutionScheduler:
    def next_step(self, plan: Plan) -> Optional[PlannedStep]:
        ready = ready_steps(plan)
        if not ready:
            return None
        ready.sort(key=lambda s: (_PHASE_ORDER.get(s.phase, 99),
                                  plan.steps.index(s)))
        return ready[0]
