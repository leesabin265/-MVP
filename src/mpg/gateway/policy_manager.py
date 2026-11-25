"""활성 정책을 메모리에 들고 있고, policy.updated 알림이나 주기 점검 때 DB에서 다시 읽어 파이프라인을 교체한다.

교체는 self.pipeline 참조 하나를 바꾸는 것뿐이라, 검사 중인 요청은 시작할 때 잡은 파이프라인으로 끝까지 간다.
DB·Redis가 죽어도 마지막으로 컴파일한 파이프라인으로 계속 검사한다.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from mpg.common.policy_io import policy_from_snapshot, read_cache, write_cache
from mpg.detection import DetectionPipeline, load_policy

from . import metrics

log = logging.getLogger("mpg.gateway.policy")
CHANNEL = "policy.updated"


class PolicyManager:
    def __init__(self, db_url: str | None, redis, cache_path: Path, bootstrap_rules: Path,
                 poll_interval: float = 30.0) -> None:
        self.db_url = db_url
        self.redis = redis
        self.cache_path = cache_path
        self.bootstrap_rules = bootstrap_rules
        self.poll_interval = poll_interval
        self.pipeline: DetectionPipeline | None = None
        self.source = "none"
        self.last_reload_ok: float | None = None
        self.last_reload_error: str | None = None
        self._lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []

    @property
    def version(self) -> int:
        return self.pipeline.policy.version if self.pipeline else 0

    async def _fetch_active(self) -> tuple[int, dict] | None:
        if not self.db_url:
            return None
        import asyncpg

        conn = await asyncpg.connect(self.db_url, timeout=3)
        try:
            row = await conn.fetchrow(
                "SELECT version, snapshot FROM policy_versions WHERE active ORDER BY version DESC LIMIT 1"
            )
        finally:
            await conn.close()
        if row is None:
            return None
        snap = row["snapshot"]
        return row["version"], json.loads(snap) if isinstance(snap, str) else snap

    async def start(self) -> None:
        try:
            await self.reload(reason="startup")
        except Exception as e:
            log.warning("startup load from DB failed, falling back", extra={"error": repr(e)})
        if self.pipeline is None:
            cached = read_cache(self.cache_path)
            if cached:
                self._install(DetectionPipeline(cached), "cache")
            else:
                self._install(DetectionPipeline(load_policy(self.bootstrap_rules, version=0)), "bootstrap")
        self._tasks = [asyncio.create_task(self._subscribe()), asyncio.create_task(self._poll())]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def _install(self, pipe: DetectionPipeline, source: str) -> None:
        self.pipeline = pipe
        self.source = source
        metrics.POLICY_VERSION.set(pipe.policy.version)
        log.info("policy installed", extra={"version": pipe.policy.version, "source": source,
                                            "rules": len(pipe.policy.rules)})

    async def reload(self, reason: str, wanted: int | None = None) -> bool:
        async with self._lock:
            t0 = time.perf_counter()
            try:
                active = await self._fetch_active()
                self.last_reload_error = None
                if active is None:
                    return False
                version, snap = active
                if self.pipeline and version == self.version:
                    self.source = "db"
                    return False
                policy = policy_from_snapshot(snap, version=version)
                pipe = await asyncio.to_thread(DetectionPipeline, policy)
            except Exception as e:
                self.last_reload_error = repr(e)
                metrics.POLICY_RELOADS.labels("failure").inc()
                log.error("policy reload failed; keeping previous version",
                          extra={"reason": reason, "kept_version": self.version, "error": repr(e)})
                raise
            self._install(pipe, "db")
            self.last_reload_ok = time.time()
            self.last_reload_error = None
            metrics.POLICY_RELOADS.labels("success").inc()
            log.info("policy reloaded", extra={
                "reason": reason, "version": version, "wanted": wanted,
                "compile_ms": round((time.perf_counter() - t0) * 1000, 1)})
            try:
                await asyncio.to_thread(write_cache, self.cache_path, policy)
            except OSError as e:
                log.warning("policy cache write failed", extra={"error": repr(e)})
            return True

    async def _subscribe(self) -> None:
        backoff = 1.0
        while True:
            try:
                pubsub = self.redis.pubsub()
                await pubsub.subscribe(CHANNEL)
                backoff = 1.0
                async for msg in pubsub.listen():
                    if msg.get("type") != "message":
                        continue
                    try:
                        wanted = int(json.loads(msg["data"])["version"])
                    except (ValueError, KeyError, TypeError):
                        log.warning("ignored malformed policy notification")
                        continue
                    if wanted > self.version:
                        try:
                            await self.reload("notify", wanted)
                        except Exception:
                            pass
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("policy subscription lost", extra={"error": repr(e)})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _poll(self) -> None:
        while True:
            await asyncio.sleep(self.poll_interval)
            try:
                await self.reload("poll")
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
