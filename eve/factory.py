"""Assembly: wire the whole engine together from Settings."""
from __future__ import annotations

import datetime as _dt
from typing import List, Optional

from .clock import Clock
from .config import Settings
from .controller import EveExecutionController
from .authz.actors import ActorStore
from .events.bus import build_event_bus
from .ids import authorization_id
from .logging_ import configure
from .persistence.db import Database
from .persistence.migrations import apply as apply_migrations
from .persistence.repository import Repository
from .persistence.tables import TargetAuthorizationRow
from .sentinel.mira import EmergencyStop, MiraSentinel
from .tools.registry import ToolRegistry
from .tools.simulator.adapters import register_simulator


class Engine:
    """Holds all singletons for one process/test."""

    def __init__(self, settings: Settings, clock: Optional[Clock] = None) -> None:
        configure(settings.log_level)
        self.settings = settings
        self.clock = clock
        self.db = Database.from_settings(settings)
        apply_migrations(self.db)
        self.repo = Repository(self.db)
        self.registry = ToolRegistry()
        register_simulator(self.registry)
        for spec in self.registry.list_specs():
            self.repo.upsert_tool(spec.tool_id, spec.version, spec.name,
                                  spec.to_dict(), spec.available)
        self.bus = build_event_bus(settings.redis_url)
        self.emergency_stop = EmergencyStop()
        self.sentinel = MiraSentinel(self.emergency_stop,
                                     fail_closed=settings.sentinel_fail_closed,
                                     clock=clock)
        self.actors = ActorStore.from_env()
        self.controller = EveExecutionController(
            settings=settings, repo=self.repo, registry=self.registry,
            bus=self.bus, sentinel=self.sentinel,
            emergency_stop=self.emergency_stop, actors=self.actors, clock=clock)

    def _now(self) -> _dt.datetime:
        if self.clock is not None:
            return self.clock.now()
        return _dt.datetime.now(_dt.timezone.utc)

    def authorize_target(self, *, actor: str, target: str,
                         allowed_actions: Optional[List[str]] = None,
                         allowed_phases: Optional[List[str]] = None,
                         ttl_seconds: int = 3600) -> str:
        row = TargetAuthorizationRow(
            id=authorization_id(), actor=actor, target=target,
            allowed_actions=allowed_actions or [],
            allowed_phases=allowed_phases or [],
            expires_at=self._now() + _dt.timedelta(seconds=ttl_seconds),
            revoked=False)
        self.repo.add_authorization(row)
        return row.id


def build_engine(settings: Optional[Settings] = None,
                 clock: Optional[Clock] = None) -> Engine:
    return Engine(settings or Settings.load(), clock=clock)
