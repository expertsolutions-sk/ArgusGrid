"""In-process fan-out of live telemetry to WebSocket clients. Thread-safe publish from request threads."""
from __future__ import annotations

import asyncio
from typing import Any


class StreamHub:
    MAX_QUEUE = 500

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self.MAX_QUEUE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, message: dict[str, Any]) -> None:
        """Safe from any thread. A slow client loses messages instead of blocking ingestion."""
        loop = self._loop
        if loop is None or not self._subscribers or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._fanout, message)

    def _fanout(self, message: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass
