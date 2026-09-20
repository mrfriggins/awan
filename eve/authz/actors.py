"""Actor identity resolved from bearer tokens. Deterministic, config-driven."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Actor:
    id: str
    roles: List[str] = field(default_factory=list)

    def has_role(self, role: str) -> bool:
        return role in self.roles


class ActorStore:
    def __init__(self, mapping: Optional[Dict[str, Actor]] = None) -> None:
        self._by_token: Dict[str, Actor] = mapping or {}

    @classmethod
    def from_env(cls) -> "ActorStore":
        raw = os.environ.get("EVE_ACTORS")
        mapping: Dict[str, Actor] = {}
        if raw:
            for entry in raw.split(","):
                parts = entry.strip().split(":")
                if len(parts) >= 2:
                    token, actor_id = parts[0], parts[1]
                    roles = parts[2].split("|") if len(parts) > 2 and parts[2] else []
                    mapping[token] = Actor(id=actor_id, roles=roles)
        if not mapping:
            mapping = {
                "operator-token": Actor("operator", ["operator"]),
                "approver-token": Actor("approver", ["operator", "approver"]),
                "viewer-token": Actor("viewer", ["viewer"]),
            }
        return cls(mapping)

    def resolve(self, token: Optional[str]) -> Optional[Actor]:
        if not token:
            return None
        return self._by_token.get(token)
