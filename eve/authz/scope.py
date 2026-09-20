"""Deterministic scope validation."""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import List

from ..clock import Clock, SystemClock
from ..persistence.repository import Repository


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeValidator:
    def __init__(self, repo: Repository, clock: Clock | None = None) -> None:
        self.repo = repo
        self.clock = clock or SystemClock()

    def authorized_targets(self, actor: str) -> List[str]:
        now = self.clock.now()
        out = []
        for a in self.repo.list_authorizations(actor):
            if a.revoked:
                continue
            if _as_aware(a.expires_at) <= now:
                continue
            out.append(a.target)
        return sorted(set(out))

    def check(self, actor: str, target: str, action: str, phase: str) -> ScopeDecision:
        now = self.clock.now()
        grants = self.repo.list_authorizations(actor)
        if not grants:
            return ScopeDecision(False, f"no authorization grants for actor '{actor}'")
        target_seen = False
        for g in grants:
            if g.target != target:
                continue
            target_seen = True
            if g.revoked:
                return ScopeDecision(False, f"authorization for target '{target}' revoked")
            if _as_aware(g.expires_at) <= now:
                return ScopeDecision(False, f"authorization for target '{target}' expired")
            if g.allowed_actions and action not in g.allowed_actions:
                return ScopeDecision(
                    False, f"action '{action}' not permitted on target '{target}'")
            if g.allowed_phases and phase not in g.allowed_phases:
                return ScopeDecision(
                    False, f"phase '{phase}' not permitted on target '{target}'")
            return ScopeDecision(True, "within authorized scope")
        if not target_seen:
            return ScopeDecision(False, f"target '{target}' is outside authorized scope")
        return ScopeDecision(False, "no matching authorization")


def _as_aware(dt: _dt.datetime) -> _dt.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_dt.timezone.utc)
    return dt
