"""Injectable clock so time-based logic (expiry, budgets) is testable."""
from __future__ import annotations

import datetime as _dt
from typing import Protocol


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class Clock(Protocol):
    def now(self) -> _dt.datetime: ...


class SystemClock:
    def now(self) -> _dt.datetime:
        return utcnow()


class FrozenClock:
    """Manually advanced clock for deterministic tests."""

    def __init__(self, start: _dt.datetime | None = None) -> None:
        self._now = start or utcnow()

    def now(self) -> _dt.datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now = self._now + _dt.timedelta(seconds=seconds)
