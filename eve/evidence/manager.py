"""Evidence Manager — content-addressed, deduplicated evidence storage."""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from ..clock import Clock, SystemClock
from ..domain.models import Evidence
from ..ids import evidence_id


class EvidenceManager:
    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()
        self._store: Dict[str, Evidence] = {}
        self._by_hash: Dict[str, str] = {}

    @staticmethod
    def _hash(target: str, kind: str, data: dict) -> str:
        blob = json.dumps({"t": target, "k": kind, "d": data}, sort_keys=True,
                          default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def record(self, *, step_id: str, target: str, kind: str, summary: str,
               data: dict) -> Evidence:
        digest = self._hash(target, kind, data)
        if digest in self._by_hash:
            return self._store[self._by_hash[digest]]
        ev = Evidence(id=evidence_id(), step_id=step_id, target=target, kind=kind,
                      summary=summary, data=data, sha256=digest,
                      created_at=self.clock.now())
        self._store[ev.id] = ev
        self._by_hash[digest] = ev.id
        return ev

    def all(self) -> List[Evidence]:
        return list(self._store.values())

    def for_target(self, target: str) -> List[Evidence]:
        return [e for e in self._store.values() if e.target == target]
