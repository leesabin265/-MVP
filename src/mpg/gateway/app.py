from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import socket
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from mpg.common.config import (
    PRIVATE_DEFAULT,
    database_url,
    env,
    env_float,
    env_int,
    ip_in,
    parse_networks,
    project_root,
    redis_url,
)
from mpg.common.logging import setup_logging
from mpg.common.masking import make_sample
from mpg.detection.models import Action

from . import metrics
from .events import EventSink
from .extract import MAX_PCT_ESCAPES, BadRequest, RawRequest, build_inspection
from .policy_manager import PolicyManager
from .response_body import inspectable, read_prefix, replay, to_text

log = logging.getLogger("mpg.gateway")
access = logging.getLogger("mpg.gateway.access")

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


class Settings:
    def __init__(self) -> None:
        self.backend_url = env("MPG_BACKEND_URL", "http://localhost:9000").rstrip("/")
        self.max_body = env_int("MPG_MAX_BODY_BYTES", 1 << 20)
        self.max_pct_escapes = env_int("MPG_MAX_PCT_ESCAPES", MAX_PCT_ESCAPES)
        self.resp_inspect_bytes = env_int("MPG_RESPONSE_INSPECT_BYTES", 256 * 1024)  # 0이면 응답 검사 끔
        self.backend_timeout = env_float("MPG_BACKEND_TIMEOUT", 5.0)
        self.internal_nets = parse_networks(env("MPG_INTERNAL_CIDRS", PRIVATE_DEFAULT))
        self.trusted_proxies = parse_networks(env("MPG_TRUSTED_PROXIES", ""))
        self.access_sample = env_float("MPG_ACCESS_LOG_SAMPLE", 0.1)
        self.db_url = database_url("MPG_GATEWAY_DB_USER", "MPG_GATEWAY_DB_PASSWORD") if env("MPG_DB_HOST") else None
        self.redis_url = redis_url("MPG_GATEWAY_REDIS_USER", "MPG_GATEWAY_REDIS_PASSWORD")
        self.cache_path = Path(env("MPG_POLICY_CACHE", "/tmp/mpg-policy-cache.json"))
        self.bootstrap_rules = Path(env("MPG_BOOTSTRAP_RULES", str(project_root() / "rules" / "rules.yaml")))
        self.poll_interval = env_float("MPG_POLICY_POLL_SECONDS", 30.0)
        self.backend_ca = env("MPG_BACKEND_CA")  # 백엔드가 HTTPS(내부 CA)일 때 CA 경로
        self.instance = env("MPG_INSTANCE", f"{socket.gethostname()}:{os.getpid()}")


def _backend_tls(ca: str | None):
    if not ca:
        return True
    import ssl
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _error(status: int, code: str, rid: str) -> JSONResponse:
    metrics.RESPONSES.labels(str(status)).inc()
    return JSONResponse({"error": code, "request_id": rid}, status_code=status,
                        headers={"X-Request-ID": rid, "Cache-Control": "no-store"})


def create_app(settings: Settings | None = None, redis_client=None) -> FastAPI:
    s = settings or Settings()
    state: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        setup_logging(env("MPG_LOG_LEVEL", "INFO"))
        import redis.asyncio as aioredis

        r = redis_client or aioredis.from_url(s.redis_url, socket_timeout=3, socket_connect_timeout=3,
                                             health_check_interval=15)
        pm = PolicyManager(s.db_url, r, s.cache_path, s.bootstrap_rules, s.poll_interval)
        await pm.start()
        sink = EventSink(r)
        sink.start()
        client = httpx.AsyncClient(
            base_url=s.backend_url,
            timeout=httpx.Timeout(s.backend_timeout, connect=2.0),
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=100),
            follow_redirects=False,
            verify=_backend_tls(s.backend_ca),
        )
        window = metrics.Window()
        state.update(redis=r, pm=pm, sink=sink, client=client, window=window)
        stats_task = asyncio.create_task(_publish_stats(r, s, pm, sink, window))
        log.info("gateway started", extra={"backend": s.backend_url, "policy_version": pm.version,
                                           "policy_source": pm.source, "instance": s.instance})
        try:
            yield
        finally:
            stats_task.cancel()
            await pm.stop()
            await sink.stop()
            await client.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.mpg = state

    def client_ip(request: Request) -> str:
        peer = request.client.host if request.client else ""
        if s.trusted_proxies and ip_in(peer, s.trusted_proxies):
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                return xff.split(",")[-1].strip()
        return peer

    @app.get("/__mpg/health")
    async def health(request: Request):
        # 로드밸런서 뒤에서는 접속 주소가 LB라서, 신뢰하는 프록시가 넘긴 실제 클라이언트 주소로 판단한다.
        if not ip_in(client_ip(request), s.internal_nets):
            return Response(status_code=404)
        pm: PolicyManager = state["pm"]
        return {"status": "ok", "policy_version": pm.version, "policy_source": pm.source,
                "last_reload_error": pm.last_reload_error, "event_buffer": len(state["sink"].buffer),
                "events_dropped": state["sink"].dropped}

    @app.get("/__mpg/metrics")
    async def prom(request: Request):
        # 로드밸런서 뒤에서는 접속 주소가 LB라서, 신뢰하는 프록시가 넘긴 실제 클라이언트 주소로 판단한다.
        if not ip_in(client_ip(request), s.internal_nets):
            return Response(status_code=404)
        body, ctype = metrics.render()
        return Response(body, media_type=ctype)

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def proxy(request: Request, full_path: str):
        t0 = time.perf_counter()
        rid = str(uuid.uuid4())
        scope = request.scope
        raw_path = scope.get("raw_path", b"").decode("latin-1") or scope["path"]
        qs = scope.get("query_string", b"").decode("latin-1")
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
        lower = [k.lower() for k, _ in headers]
        ip = client_ip(request)

        if "transfer-encoding" in lower and "content-length" in lower or lower.count("content-length") > 1:
            return _finish(_error(400, "bad_request", rid), t0, 0.0, None, request, ip, rid)

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > s.max_body:
            return _finish(_error(413, "payload_too_large", rid), t0, 0.0, None, request, ip, rid)
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > s.max_body:
                return _finish(_error(413, "payload_too_large", rid), t0, 0.0, None, request, ip, rid)
        body = bytes(body)

        pm: PolicyManager = state["pm"]
        pipe = pm.pipeline
        ti = time.perf_counter()
        try:
            insp = build_inspection(RawRequest(request.method, raw_path, qs, headers, body), s.max_pct_escapes)
            verdict = pipe.inspect(insp)
        except BadRequest as e:
            metrics.INSPECTION.observe(time.perf_counter() - ti)
            log.info("request rejected by parser", extra={"request_id": rid, "reason": str(e)})
            return _finish(_error(400, "bad_request", rid), t0, 0.0, None, request, ip, rid)
        except Exception:
            metrics.INTERNAL_ERRORS.inc()
            log.exception("inspection failed; fail-closed", extra={"request_id": rid})
            return _finish(_error(403, "blocked", rid), t0, 0.0, "BLOCK", request, ip, rid)
        metrics.INSPECTION.observe(time.perf_counter() - ti)
        metrics.REQUESTS.labels(verdict.action.value).inc()
        _count_matches(verdict)

        # 요청 판정 이벤트는 응답 검사 결과와 합쳐 한 건으로 남긴다(security_events는 요청 ID당 한 건).
        def emit(rv=None):
            _emit(state["sink"], verdict, rv, insp, request, ip, rid)

        if verdict.action is Action.BLOCK:
            emit()
            return _finish(_error(403, "blocked", rid), t0, 0.0, "BLOCK", request, ip, rid)

        fwd_headers = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP
                       and not k.lower().startswith("x-forwarded-") and k.lower() != "x-request-id"]
        host = request.headers.get("host", "")
        peer = request.client.host if request.client else ""
        prior = request.headers.get("x-forwarded-for") if ip_in(peer, s.trusted_proxies) else None
        fwd_headers += [
            ("X-Request-ID", rid),
            # 각 프록시는 자기가 받은 상대 주소를 뒤에 붙인다(LB 뒤면 '클라이언트, LB').
            ("X-Forwarded-For", f"{prior}, {peer}" if prior else ip),
            ("X-Forwarded-Proto", scope.get("scheme", "http")),
            ("X-Forwarded-Host", host),
        ]
        target = raw_path + (f"?{qs}" if qs else "")
        client: httpx.AsyncClient = state["client"]
        tu = time.perf_counter()
        try:
            upstream_req = client.build_request(request.method, target, headers=fwd_headers, content=body)
            upstream = await client.send(upstream_req, stream=True)
        except httpx.TimeoutException:
            emit()
            return _finish(_error(504, "gateway_timeout", rid), t0, time.perf_counter() - tu,
                           verdict.action.value, request, ip, rid)
        except httpx.HTTPError:
            emit()
            return _finish(_error(502, "bad_gateway", rid), t0, time.perf_counter() - tu,
                           verdict.action.value, request, ip, rid)

        # 응답 검사: 텍스트 응답의 앞부분만 담아 검사하고 나머지는 그대로 흘려보낸다.
        body_iter = upstream.aiter_raw()
        rv = None
        if inspectable(request.method, upstream.status_code, upstream.headers, s.resp_inspect_bytes):
            try:
                prefix, complete = await read_prefix(body_iter, s.resp_inspect_bytes)
            except httpx.HTTPError:
                await upstream.aclose()
                emit()
                return _finish(_error(502, "bad_gateway", rid), t0, time.perf_counter() - tu,
                               verdict.action.value, request, ip, rid)
            tr = time.perf_counter()
            try:
                rv = pipe.inspect_response(insp.path, upstream.status_code,
                                           to_text(prefix, upstream.headers, s.resp_inspect_bytes))
            except Exception:
                # 응답 검사 오류는 응답을 막지 않는다(요청 검사와 달리 Fail-Open). 오류 수는 지표로 센다.
                metrics.INTERNAL_ERRORS.inc()
                log.exception("response inspection failed; passing response", extra={"request_id": rid})
            metrics.RESPONSE_INSPECTION.observe(time.perf_counter() - tr)
            if rv is not None:
                metrics.RESPONSE_VERDICTS.labels(rv.action.value).inc()
                _count_matches(rv)
            body_iter = replay(prefix, None if complete else body_iter)
        upstream_s = time.perf_counter() - tu
        metrics.UPSTREAM.observe(upstream_s)
        emit(rv)
        if rv is not None and rv.action is Action.BLOCK:
            await upstream.aclose()
            log.warning("response blocked", extra={"request_id": rid, "path": insp.path,
                                                   "rules": [m.rule_id for m in rv.matches if not m.excepted]})
            return _finish(_error(502, "response_blocked", rid), t0, upstream_s, "BLOCK", request, ip, rid)

        out_headers = [(k, v) for k, v in upstream.headers.multi_items()
                       if k.lower() not in HOP_BY_HOP or k.lower() == "content-length"]
        out_headers.append(("X-Request-ID", rid))
        resp = StreamingResponse(body_iter, status_code=upstream.status_code,
                                 background=BackgroundTask(upstream.aclose))
        resp.raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in out_headers]
        metrics.RESPONSES.labels(str(upstream.status_code)).inc()
        return _finish(resp, t0, upstream_s, verdict.action.value, request, ip, rid, counted=True)

    def _finish(resp, t0, upstream_s, action, request, ip, rid, counted=False):
        total = time.perf_counter() - t0
        overhead = max(0.0, total - upstream_s)
        metrics.OVERHEAD.observe(overhead)
        state["window"].add(overhead * 1000, resp.status_code)
        if action == "BLOCK" or resp.status_code >= 400 or random.random() < s.access_sample:
            access.info("request", extra={
                "request_id": rid, "method": request.method, "path": request.url.path,
                "status": resp.status_code, "action": action or "-", "client_ip": ip,
                "gateway_ms": round(overhead * 1000, 3), "backend_ms": round(upstream_s * 1000, 3)})
        return resp

    return app


_RANK = {Action.ALLOW: 0, Action.DETECT_ONLY: 1, Action.BLOCK: 2}


def _count_matches(verdict) -> None:
    for m in verdict.matches:
        if not m.excepted:
            metrics.RULE_MATCHES.labels(m.rule_id).inc()


def _emit(sink: EventSink, verdict, rv, insp, request: Request, ip: str, rid: str) -> None:
    """요청 판정과 (있으면) 응답 판정을 합쳐 이벤트 한 건으로 보낸다. 둘 다 ALLOW면 보내지 않는다."""
    resp_flagged = rv is not None and rv.action is not Action.ALLOW
    if verdict.action is Action.ALLOW and not resp_flagged:
        return
    action = max(verdict.action, rv.action if resp_flagged else Action.ALLOW, key=_RANK.get)
    if verdict.action is not Action.ALLOW:
        top = max(verdict.fields, key=lambda f: (f.block_score, f.score))
        ev_match = next((m for m in top.matches if not m.excepted), None)
        sample = make_sample(top.field.location.value, top.field.name, top.field.value,
                             ev_match.evidence if ev_match else "")
        field_ref = top.field.ref
    else:
        # 응답에서 찾은 것은 유출된 데이터 자체라 원문을 저장하지 않는다.
        sample = "[response redacted]"
        field_ref = rv.matches[0].field_ref
    matches = list(verdict.matches) + (list(rv.matches) if resp_flagged else [])
    sink.emit({
        "request_id": rid,
        "ts": datetime.now(timezone.utc).isoformat(),
        "client_ip": ip,
        "method": request.method,
        "path": insp.path,
        "risk_score": max(verdict.risk_score, rv.risk_score if resp_flagged else 0),
        "action": action.value,
        "policy_version": verdict.policy_version,
        "field_ref": field_ref,
        "masked_sample": sample,
        "matches": [{"rule_id": m.rule_id, "field_ref": m.field_ref, "score": m.score,
                     "mode": m.mode.value, "excepted": m.excepted} for m in matches],
        "inspect_ms": round(verdict.elapsed_ms + (rv.elapsed_ms if rv is not None else 0), 3),
    })


async def _publish_stats(r, s: Settings, pm: PolicyManager, sink: EventSink, window) -> None:
    key = f"gateway:stats:{s.instance}"
    while True:
        try:
            snap = window.snapshot()
            snap.update(instance=s.instance, policy_version=pm.version, policy_source=pm.source,
                        last_reload_error=pm.last_reload_error, event_buffer=len(sink.buffer),
                        events_dropped=sink.dropped, ts=time.time())
            await r.set(key, json.dumps(snap), ex=60)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        await asyncio.sleep(10)


def get_app() -> FastAPI:
    return create_app()
