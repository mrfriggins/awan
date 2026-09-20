"""Event distribution for live streaming (SSE/WebSocket)."""
from __future__ import annotations

import json
import queue
import threading
from typing import Dict, Iterator, List, Optional, Protocol


class EventBus(Protocol):
    def publish(self, operation_id: str, event: dict) -> None: ...
    def subscribe(self, operation_id: str) -> "Subscription": ...


class Subscription:
    def __init__(self, on_close) -> None:
        self._q: "queue.Queue[Optional[dict]]" = queue.Queue()
        self._on_close = on_close
        self._closed = False

    def put(self, event: Optional[dict]) -> None:
        self._q.put(event)

    def stream(self, timeout: float = 15.0) -> Iterator[dict]:
        while not self._closed:
            try:
                item = self._q.get(timeout=timeout)
            except queue.Empty:
                yield {"type": "HEARTBEAT"}
                continue
            if item is None:
                break
            yield item

    def close(self) -> None:
        self._closed = True
        self._q.put(None)
        self._on_close(self)


class InMemoryEventBus:
    def __init__(self) -> None:
        self._subs: Dict[str, List[Subscription]] = {}
        self._lock = threading.Lock()

    def publish(self, operation_id: str, event: dict) -> None:
        with self._lock:
            for sub in list(self._subs.get(operation_id, [])):
                sub.put(event)

    def subscribe(self, operation_id: str) -> Subscription:
        def _on_close(sub: Subscription) -> None:
            with self._lock:
                if operation_id in self._subs and sub in self._subs[operation_id]:
                    self._subs[operation_id].remove(sub)

        sub = Subscription(_on_close)
        with self._lock:
            self._subs.setdefault(operation_id, []).append(sub)
        return sub


class RedisEventBus:
    """Optional Redis-backed fan-out. Falls back cleanly if redis is missing."""

    def __init__(self, url: str) -> None:
        import redis  # type: ignore

        self._redis = redis.Redis.from_url(url)
        self._local = InMemoryEventBus()

    def _channel(self, operation_id: str) -> str:
        return f"eve:op:{operation_id}"

    def publish(self, operation_id: str, event: dict) -> None:
        self._redis.publish(self._channel(operation_id), json.dumps(event))
        self._local.publish(operation_id, event)

    def subscribe(self, operation_id: str) -> Subscription:
        sub = self._local.subscribe(operation_id)
        pubsub = self._redis.pubsub()
        pubsub.subscribe(self._channel(operation_id))

        def _pump() -> None:
            for msg in pubsub.listen():
                if msg.get("type") == "message":
                    try:
                        sub.put(json.loads(msg["data"]))
                    except Exception:
                        pass

        threading.Thread(target=_pump, daemon=True).start()
        return sub


def build_event_bus(redis_url: Optional[str]) -> EventBus:
    if redis_url:
        try:
            return RedisEventBus(redis_url)
        except Exception:
            pass
    return InMemoryEventBus()
