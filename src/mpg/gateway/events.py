"""탐지 이벤트를 요청 경로에서 떼어내 Redis Streams로 비동기 기록한다.

요청 처리 코드는 deque에 넣기만 하고(O(1), await 없음), 백그라운드 태스크가 묶어서 XADD 한다.
Redis가 죽으면 최대 10,000건까지 메모리에 쌓고, 넘치면 가장 오래된 것부터 버리고 개수를 센다.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque

from . import metrics

log = logging.getLogger("mpg.gateway.events")
STREAM = "gateway.events"
STREAM_MAXLEN = 100_000


class EventSink:
    def __init__(self, redis, capacity: int = 10_000, batch: int = 200) -> None:
        self.redis = redis
        self.buffer: deque[dict] = deque()
        self.capacity = capacity
        self.batch = batch
        self.dropped = 0
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None

    def emit(self, event: dict) -> None:
        if len(self.buffer) >= self.capacity:
            self.buffer.popleft()
            self.dropped += 1
            metrics.EVENTS_DROPPED.inc()
        self.buffer.append(event)
        metrics.EVENT_BUFFER.set(len(self.buffer))
        self._wake.set()

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self, flush_timeout: float = 3.0) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        try:
            await asyncio.wait_for(self._flush_all(), flush_timeout)
        except Exception:
            if self.buffer:
                log.warning("events lost at shutdown", extra={"count": len(self.buffer)})

    async def _flush_all(self) -> None:
        while self.buffer:
            await self._send_batch()

    async def _send_batch(self) -> None:
        items = [self.buffer[i] for i in range(min(self.batch, len(self.buffer)))]
        pipe = self.redis.pipeline(transaction=False)
        for ev in items:
            pipe.xadd(STREAM, {"data": json.dumps(ev, ensure_ascii=False)},
                      maxlen=STREAM_MAXLEN, approximate=True)
        await pipe.execute()
        for _ in items:
            if self.buffer:
                self.buffer.popleft()
        metrics.EVENTS_SENT.inc(len(items))
        metrics.EVENT_BUFFER.set(len(self.buffer))

    async def _run(self) -> None:
        backoff = 0.5
        while True:
            if not self.buffer:
                self._wake.clear()
                await self._wake.wait()
            try:
                await self._send_batch()
                backoff = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("event write failed; buffering", extra={
                    "error": repr(e), "buffered": len(self.buffer)})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10)
