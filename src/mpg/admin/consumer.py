"""gateway.events 스트림을 소비 그룹으로 읽어 PostgreSQL에 적재한다.

DB 커밋이 끝난 뒤에만 XACK 하므로, 적재 도중 죽으면 메시지는 PEL(pending)에 남아 재시작 때 다시 처리된다.
INSERT ... ON CONFLICT DO NOTHING 이라 같은 메시지를 두 번 처리해도 한 건만 남는다(at-least-once + 멱등).
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
from datetime import datetime

from redis.exceptions import ResponseError

log = logging.getLogger("mpg.admin.consumer")
STREAM = "gateway.events"
GROUP = "admin-api"
RETENTION_DAYS = 30


class EventConsumer:
    def __init__(self, pool, redis, name: str | None = None, batch: int = 200) -> None:
        self.pool = pool
        self.redis = redis
        self.name = name or socket.gethostname()
        self.batch = batch
        self.processed = 0
        self.failed = 0

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def run(self) -> None:
        backoff = 1.0
        pending_first = True
        while True:
            try:
                await self.ensure_group()
                if pending_first:
                    await self._drain("0")
                    await self._claim_stale()
                    pending_first = False
                resp = await self.redis.xreadgroup(GROUP, self.name, {STREAM: ">"},
                                                   count=self.batch, block=5000)
                for _, msgs in resp or []:
                    await self._handle(msgs)
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("consumer error", extra={"error": repr(e)})
                pending_first = True
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _drain(self, start: str) -> None:
        while True:
            resp = await self.redis.xreadgroup(GROUP, self.name, {STREAM: start}, count=self.batch)
            msgs = resp[0][1] if resp else []
            if not msgs:
                return
            await self._handle(msgs)

    async def _claim_stale(self) -> None:
        cursor = "0-0"
        while True:
            cursor, msgs, *_ = await self.redis.xautoclaim(STREAM, GROUP, self.name, 60_000,
                                                          start_id=cursor, count=self.batch)
            if msgs:
                await self._handle([m for m in msgs if m])
            if cursor in ("0-0", b"0-0"):
                return

    async def _handle(self, msgs) -> None:
        rows, ids = [], []
        for mid, fields in msgs:
            ids.append(mid)
            try:
                data = fields.get(b"data") or fields.get("data")
                rows.append(json.loads(data))
            except Exception:
                self.failed += 1
                log.error("malformed event dropped", extra={"id": str(mid)})
        if rows:
            await store_events(self.pool, rows)
        if ids:
            await self.redis.xack(STREAM, GROUP, *ids)
        self.processed += len(rows)

    async def lag(self) -> int | None:
        try:
            for g in await self.redis.xinfo_groups(STREAM):
                name = g.get("name")
                if name in (GROUP, GROUP.encode()):
                    lag = g.get("lag")
                    pending = g.get("pending", 0)
                    return int(lag or 0) + int(pending or 0)
        except Exception:
            return None
        return 0


async def store_events(pool, rows: list[dict]) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            for ev in rows:
                inserted = await conn.fetchval(
                    """INSERT INTO security_events(request_id, ts, client_ip, method, path, risk_score,
                           action, policy_version, field_ref, masked_sample, inspect_ms)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                       ON CONFLICT (request_id) DO NOTHING RETURNING 1""",
                    ev["request_id"], datetime.fromisoformat(ev["ts"]), ev.get("client_ip") or None,
                    ev["method"][:16], ev["path"][:2048], int(ev["risk_score"]), ev["action"],
                    int(ev["policy_version"]), ev.get("field_ref", "")[:256],
                    ev.get("masked_sample", "")[:256], ev.get("inspect_ms"))
                if inserted:
                    await conn.executemany(
                        "INSERT INTO event_matches(request_id, rule_id, field_ref, score, mode, excepted)"
                        " VALUES ($1,$2,$3,$4,$5,$6)",
                        [(ev["request_id"], m["rule_id"], m["field_ref"][:256], int(m["score"]),
                          m.get("mode", "BLOCK"), bool(m.get("excepted"))) for m in ev.get("matches", [])])


async def retention_loop(pool, interval: float = 3600) -> None:
    while True:
        try:
            async with pool.acquire() as conn:
                n = await conn.execute(
                    f"DELETE FROM security_events WHERE ts < now() - interval '{RETENTION_DAYS} days'")
            log.info("retention run", extra={"result": n})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("retention failed", extra={"error": repr(e)})
        await asyncio.sleep(interval)
