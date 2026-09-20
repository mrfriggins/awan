"""Goal Interpreter — deterministic goal -> structured intent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..domain.enums import Phase

_KEYWORD_PHASES = {
    "recon": Phase.RECONNAISSANCE,
    "reconnaissance": Phase.RECONNAISSANCE,
    "inventory": Phase.RECONNAISSANCE,
    "enumerate": Phase.ENUMERATION,
    "enumeration": Phase.ENUMERATION,
    "vulnerab": Phase.VULNERABILITY_ANALYSIS,
    "weakness": Phase.VULNERABILITY_ANALYSIS,
    "validate": Phase.VALIDATION,
    "confirm": Phase.VALIDATION,
    "report": Phase.POST_ASSESSMENT,
}

_FULL_KEYWORDS = ("full", "assess", "assessment", "audit", "pentest",
                  "penetration", "complete", "end-to-end", "security review")

DEFAULT_PHASES = [Phase.RECONNAISSANCE, Phase.ENUMERATION,
                  Phase.VULNERABILITY_ANALYSIS, Phase.VALIDATION,
                  Phase.POST_ASSESSMENT]


@dataclass
class OperationIntent:
    goal: str
    targets: List[str]
    phases: List[Phase] = field(default_factory=list)
    mode: str = "sim"  # "sim" (offline fixtures) or "live" (authorized online recon)


class GoalInterpreter:
    def interpret(self, goal: str, targets: List[str],
                  phases: List[str] | None = None,
                  mode: str = "sim") -> OperationIntent:
        if not targets:
            raise ValueError("at least one authorized target is required")
        if phases:
            resolved = [Phase(p) for p in phases]
        else:
            resolved = self._infer_phases(goal)
        if Phase.POST_ASSESSMENT not in resolved:
            resolved.append(Phase.POST_ASSESSMENT)
        ordered = [p for p in DEFAULT_PHASES if p in resolved]
        return OperationIntent(goal=goal, targets=list(targets), phases=ordered,
                               mode=mode if mode in ("sim", "live") else "sim")

    def _infer_phases(self, goal: str) -> List[Phase]:
        g = goal.lower()
        if any(kw in g for kw in _FULL_KEYWORDS):
            return list(DEFAULT_PHASES)
        found = {phase for kw, phase in _KEYWORD_PHASES.items() if kw in g}
        if not found:
            return list(DEFAULT_PHASES)
        if Phase.VULNERABILITY_ANALYSIS in found or Phase.VALIDATION in found:
            found.update({Phase.RECONNAISSANCE, Phase.ENUMERATION})
        if Phase.ENUMERATION in found:
            found.add(Phase.RECONNAISSANCE)
        return [p for p in DEFAULT_PHASES if p in found]
