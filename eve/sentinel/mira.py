"""MIRA Sentinel and the global Emergency Stop.

Both are deterministic backend authorities that sit OUTSIDE the model's control.
There is deliberately no tool, action, or API surface that lets a planned step,
adapter, or the LLM disable the sentinel or clear the emergency stop. The
controller consults the sentinel before every step; if the sentinel is
unavailable it FAILS CLOSED (denies).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional, Set

from ..clock import Clock, SystemClock

FORBIDDEN_CAPABILITIES: Set[str] = {
    "destructive", "persistence", "lateral_movement", "exfiltration",
    "credential_theft", "malware", "command_and_control", "evasion", "dos",
}


@dataclass
class EmergencyStop:
    _engaged: bool = False
    _reason: str = ""
    _by: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def engage(self, reason: str, by: str = "operator") -> None:
        with self._lock:
            self._engaged = True
            self._reason = reason
            self._by = by

    def reset(self, by: str = "operator") -> None:
        with self._lock:
            self._engaged = False
            self._reason = ""
            self._by = by

    def is_engaged(self) -> bool:
        with self._lock:
            return self._engaged

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason


@dataclass(frozen=True)
class SentinelContext:
    operation_id: str
    actor: str
    target: str
    action: str
    phase: str
    capabilities: Set[str] = field(default_factory=set)
    destructive: bool = False


@dataclass(frozen=True)
class SentinelVerdict:
    allowed: bool
    reason: str
    available: bool = True


class MiraSentinel:
    def __init__(self, emergency_stop: EmergencyStop, *,
                 fail_closed: bool = True, clock: Clock | None = None) -> None:
        self.emergency_stop = emergency_stop
        self.fail_closed = fail_closed
        self.clock = clock or SystemClock()
        self._available = True
        self._denied_targets: Set[str] = set()

    def set_available(self, available: bool) -> None:
        self._available = available

    def deny_target(self, target: str) -> None:
        self._denied_targets.add(target)

    @property
    def available(self) -> bool:
        return self._available

    def evaluate(self, ctx: SentinelContext) -> SentinelVerdict:
        if not self._available:
            return SentinelVerdict(
                allowed=not self.fail_closed,
                reason="sentinel unavailable — failing closed"
                if self.fail_closed else "sentinel unavailable — fail-open configured",
                available=False)
        if self.emergency_stop.is_engaged():
            return SentinelVerdict(False,
                                   f"emergency stop engaged: {self.emergency_stop.reason}")
        if ctx.destructive:
            return SentinelVerdict(False, "destructive action denied by sentinel policy")
        forbidden = ctx.capabilities & FORBIDDEN_CAPABILITIES
        if forbidden:
            return SentinelVerdict(
                False, f"forbidden capability requested: {sorted(forbidden)}")
        if ctx.target in self._denied_targets:
            return SentinelVerdict(False, f"target '{ctx.target}' denied by sentinel")
        return SentinelVerdict(True, "sentinel approved")
