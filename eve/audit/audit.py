"""Audit System — append-only, hash-chained operation event log."""
from __future__ import annotations

import hashlib
import json
from typing import Tuple

from ..domain.enums import EventType
from ..events.bus import EventBus
from ..ids import event_id
from ..logging_ import get_logger, redact
from ..persistence.repository import Repository

_log = get_logger("audit")


def _hash_event(seq: int, type_: str, message: str, data: dict, prev_hash: str) -> str:
    blob = json.dumps(
        {"seq": seq, "type": type_, "message": message, "data": data,
         "prev": prev_hash}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class AuditSystem:
    def __init__(self, repo: Repository, bus: EventBus) -> None:
        self.repo = repo
        self.bus = bus

    def record(self, operation_id: str, type_: EventType, message: str,
               data: dict | None = None) -> dict:
        safe = redact(data or {})
        seq = self.repo.next_event_seq(operation_id)
        prev = self.repo.last_event_hash(operation_id)
        tval = type_.value if isinstance(type_, EventType) else str(type_)
        h = _hash_event(seq, tval, message, safe, prev)
        eid = event_id()
        self.repo.append_event(id=eid, operation_id=operation_id, seq=seq,
                               type=tval, message=message, data=safe,
                               prev_hash=prev, hash=h)
        event = {"id": eid, "operation_id": operation_id, "seq": seq,
                 "type": tval, "message": message, "data": safe}
        self.bus.publish(operation_id, event)
        _log.info("op=%s seq=%s %s: %s", operation_id, seq, tval, message)
        return event

    def verify_chain(self, operation_id: str) -> Tuple[bool, str]:
        prev = ""
        for row in self.repo.list_events(operation_id):
            expect = _hash_event(row.seq, row.type, row.message, row.data, prev)
            if expect != row.hash:
                return False, f"hash mismatch at seq {row.seq}"
            if row.prev_hash != prev:
                return False, f"broken link at seq {row.seq}"
            prev = row.hash
        return True, "audit chain intact"
