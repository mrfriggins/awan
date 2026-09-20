"""Tool Registry. The planner may select ONLY registered tools/actions."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from ..errors import UnknownToolError
from .adapter import ToolAdapter


@dataclass
class ToolSpec:
    tool_id: str
    name: str
    version: str
    description: str
    capabilities: List[str] = field(default_factory=list)
    supported_actions: List[str] = field(default_factory=list)
    required_permissions: List[str] = field(default_factory=list)
    target_requirements: List[str] = field(default_factory=list)
    resource_limits: Dict[str, int] = field(default_factory=dict)
    timeout_seconds: int = 30
    input_schema: Dict[str, object] = field(default_factory=dict)
    output_schema: Dict[str, object] = field(default_factory=dict)
    available: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: Dict[str, ToolSpec] = {}
        self._adapters: Dict[str, ToolAdapter] = {}

    def register(self, spec: ToolSpec, adapter: ToolAdapter) -> None:
        for action in spec.supported_actions:
            if not adapter.supports(action):
                raise UnknownToolError(
                    f"adapter for '{spec.tool_id}' does not implement '{action}'")
        self._specs[spec.tool_id] = spec
        self._adapters[spec.tool_id] = adapter

    def is_registered(self, tool_id: str) -> bool:
        return tool_id in self._specs

    def has_action(self, tool_id: str, action: str) -> bool:
        spec = self._specs.get(tool_id)
        return bool(spec and action in spec.supported_actions)

    def get_spec(self, tool_id: str) -> ToolSpec:
        if tool_id not in self._specs:
            raise UnknownToolError(f"unknown tool '{tool_id}'")
        return self._specs[tool_id]

    def get_adapter(self, tool_id: str) -> ToolAdapter:
        if tool_id not in self._adapters:
            raise UnknownToolError(f"unknown tool '{tool_id}'")
        return self._adapters[tool_id]

    def is_available(self, tool_id: str) -> bool:
        spec = self._specs.get(tool_id)
        return bool(spec and spec.available)

    def set_available(self, tool_id: str, available: bool) -> None:
        if tool_id in self._specs:
            self._specs[tool_id].available = available

    def validate_action(self, tool_id: str, action: str) -> None:
        if tool_id not in self._specs:
            raise UnknownToolError(f"unknown tool '{tool_id}'")
        if action not in self._specs[tool_id].supported_actions:
            raise UnknownToolError(
                f"unknown action '{action}' for tool '{tool_id}'")

    def list_specs(self) -> List[ToolSpec]:
        return list(self._specs.values())

    def capabilities_for(self, tool_id: str) -> set:
        spec = self._specs.get(tool_id)
        return set(spec.capabilities) if spec else set()

    def find_by_action(self, action: str) -> Optional[str]:
        for tid, spec in self._specs.items():
            if action in spec.supported_actions and spec.available:
                return tid
        return None
