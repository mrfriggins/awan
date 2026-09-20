"""Tool adapter interface. Every executable capability is a registered adapter."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AdapterResult:
    ok: bool
    output: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    unexpected: bool = False
    error: str | None = None


class ToolAdapter(abc.ABC):
    tool_id: str = ""
    supported_actions: List[str] = []

    @abc.abstractmethod
    def execute(self, action: str, target: str,
                params: Dict[str, Any]) -> AdapterResult:
        ...

    def supports(self, action: str) -> bool:
        return action in self.supported_actions
