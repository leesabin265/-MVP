"""기획서 6-1 알림 기준. 대시보드 배너로 보여주고, Critical은 웹훅으로도 보낸다."""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

log = logging.getLogger("mpg.admin.alerts")


def _a(level: str, key: str, message: str, value=None) -> dict:
    return {"level": level, "key": key, "message": message, "value": value}


async def gateway_stats(redis) -> list[dict]:
    out = []
    async for k in redis.scan_iter("gateway:stats:*", count=100):
        raw = await redis.get(k)
        if raw:
            out.append(json.loads(raw))
    return sorted(out, key=lambda s: s.get("instance", ""))


async def compute(conn, redis, consumer_lag: int | None, active_version: int | None,
                  published_at: float | None) -> list[dict]:
    alerts: list[dict] = []
    stats = await gateway_stats(redis)
    if not stats:
        alerts.append(_a("critical", "gateway_down", "게이트웨이 상태 보고가 60초 넘게 없습니다"))
    now = time.time()
    for s in stats:
        inst = s.get("instance", "?")
        p95 = s.get("p95_ms")
        if p95 is not None and s.get("count", 0) >= 50:
            if p95 > 20:
                alerts.append(_a("critical", "latency", f"{inst} 추가 지연 p95 {p95}ms > 20ms", p95))
            elif p95 > 5:
                alerts.append(_a("warning", "latency", f"{inst} 추가 지연 p95 {p95}ms > 5ms", p95))
        ratio = s.get("error_5xx_ratio", 0)
        if s.get("count", 0) >= 50:
            if ratio > 0.05:
                alerts.append(_a("critical", "5xx", f"{inst} 5xx 비율 {ratio:.1%}", ratio))
            elif ratio > 0.01:
                alerts.append(_a("warning", "5xx", f"{inst} 5xx 비율 {ratio:.1%}", ratio))
        if s.get("last_reload_error"):
            alerts.append(_a("critical", "reload_failed",
                             f"{inst} 정책 리로드 실패, v{s.get('policy_version')} 유지 중"))
        if active_version and s.get("policy_version") != active_version and published_at:
            age = now - published_at
            if age > 60:
                alerts.append(_a("critical", "version_mismatch",
                                 f"{inst} 정책 v{s.get('policy_version')} ≠ 발행 v{active_version}", age))
            elif age > 10:
                alerts.append(_a("warning", "version_mismatch",
                                 f"{inst} 정책 v{s.get('policy_version')} ≠ 발행 v{active_version}", age))
        if s.get("events_dropped"):
            alerts.append(_a("warning", "events_dropped",
                             f"{inst} 이벤트 {s['events_dropped']}건 유실(버퍼 초과)", s["events_dropped"]))

    if consumer_lag is not None:
        if consumer_lag > 50_000:
            alerts.append(_a("critical", "stream_lag", f"이벤트 미처리 {consumer_lag}건 (유실 위험)", consumer_lag))
        elif consumer_lag > 10_000:
            alerts.append(_a("warning", "stream_lag", f"이벤트 미처리 {consumer_lag}건", consumer_lag))

    row = await conn.fetchrow(
        """SELECT count(*) FILTER (WHERE ts > now() - interval '1 hour') AS last_hour,
                  count(*) FILTER (WHERE ts > now() - interval '25 hours'
                                     AND ts <= now() - interval '1 hour') / 24.0 AS avg_hour
           FROM security_events WHERE action='BLOCK' AND ts > now() - interval '25 hours'""")
    if row["avg_hour"] and row["last_hour"] > 3 * float(row["avg_hour"]) and row["last_hour"] >= 30:
        alerts.append(_a("warning", "block_spike",
                         f"최근 1시간 차단 {row['last_hour']}건 (평균의 3배 이상)", row["last_hour"]))
    top = await conn.fetchrow(
        """SELECT m.rule_id, count(DISTINCT e.request_id) AS n,
                  (SELECT count(*) FROM security_events WHERE action='BLOCK' AND ts > now() - interval '1 hour') AS total
           FROM security_events e JOIN event_matches m USING (request_id)
           WHERE e.action='BLOCK' AND e.ts > now() - interval '1 hour' AND NOT m.excepted
           GROUP BY m.rule_id ORDER BY n DESC LIMIT 1""")
    if top and top["total"] >= 20 and top["n"] / top["total"] >= 0.5 and not top["rule_id"].startswith("ENC"):
        alerts.append(_a("warning", "single_rule",
                         f"{top['rule_id']}가 최근 1시간 차단의 {top['n'] / top['total']:.0%} (오탐 의심)", top["rule_id"]))
    fails = await conn.fetchval(
        "SELECT count(*) FROM audit_log WHERE action='auth.login_failed' AND ts > now() - interval '10 minutes'")
    if fails >= 10:
        alerts.append(_a("warning", "login_failures", f"최근 10분 로그인 실패 {fails}회", fails))
    locked = await conn.fetchval(
        "SELECT count(*) FROM audit_log WHERE action='auth.account_locked' AND ts > now() - interval '1 hour'")
    if locked:
        alerts.append(_a("critical", "account_locked", f"최근 1시간 계정 잠금 {locked}건", locked))
    expiring = await conn.fetchval(
        "SELECT count(*) FROM rule_exceptions WHERE active AND expires_at > now()"
        " AND expires_at < now() + interval '7 days'")
    if expiring:
        alerts.append(_a("warning", "exception_expiring", f"7일 안에 만료되는 예외 {expiring}건", expiring))
    return alerts


async def webhook_loop(get_alerts, url: str | None, interval: float = 60) -> None:
    if not url:
        return
    sent: dict[str, float] = {}
    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            await asyncio.sleep(interval)
            try:
                for a in await get_alerts():
                    if a["level"] != "critical":
                        continue
                    k = f"{a['key']}:{a['message']}"
                    if time.time() - sent.get(k, 0) < 3600:
                        continue
                    await client.post(url, json={"content": f"[MPG CRITICAL] {a['message']}",
                                                 "text": f"[MPG CRITICAL] {a['message']}"})
                    sent[k] = time.time()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("webhook failed", extra={"error": repr(e)})
