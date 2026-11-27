from __future__ import annotations

import asyncio
import base64
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field as PField

from mpg.common.config import (
    PRIVATE_DEFAULT,
    database_url,
    env,
    env_bool,
    ip_in,
    parse_networks,
    project_root,
    redis_url,
)
from mpg.common.logging import setup_logging
from mpg.detection.rules import (
    RuleError,
    exception_from_dict,
    load_rules,
    path_threshold_from_dict,
    rule_from_dict,
    rule_override_from_dict,
)

from . import alerts as alerts_mod
from . import auth
from . import policy_service as ps
from .consumer import EventConsumer, retention_loop
from .db import audit, create_pool, migrate

log = logging.getLogger("mpg.admin")
MAX_EXCEPTION_DAYS = 180


class Settings:
    def __init__(self) -> None:
        self.db_url = database_url("MPG_ADMIN_DB_USER", "MPG_ADMIN_DB_PASSWORD")
        self.redis_url = redis_url("MPG_ADMIN_REDIS_USER", "MPG_ADMIN_REDIS_PASSWORD")
        self.allow_nets = parse_networks(env("MPG_ADMIN_ALLOW_CIDRS", PRIVATE_DEFAULT))
        self.trusted_proxies = parse_networks(env("MPG_TRUSTED_PROXIES", ""))
        self.cookie_secure = env_bool("MPG_COOKIE_SECURE", True)
        self.datasets_dir = Path(env("MPG_DATASETS_DIR", str(project_root() / "datasets")))
        self.webhook = env("MPG_ALERT_WEBHOOK")
        self.run_consumer = env_bool("MPG_RUN_CONSUMER", True)
        self.auto_migrate = env_bool("MPG_AUTO_MIGRATE", True)
        # 수업 참여 서비스(선택). 콘솔의 '수업 참여' 탭이 admin-api를 거쳐 발표자 기능을 쓴다(키는 브라우저에 가지 않는다).
        self.classroom_url = (env("MPG_CLASSROOM_URL", "http://classroom:8080") or "").rstrip("/")
        self.classroom_key = env("MPG_CLASS_PRESENTER_KEY", "") or ""


# ───────────── 요청 모델 ─────────────
class LoginIn(BaseModel):
    login_id: str = PField(min_length=1, max_length=64)
    password: str = PField(min_length=1, max_length=256)


class RuleIn(BaseModel):
    id: str
    category: Literal["SQLI", "XSS", "SCR", "CMD", "PATH", "FILE", "RESP", "ENC"]
    kind: Literal["regex", "signal", "analyzer"] = "regex"
    pattern: str | None = PField(default=None, max_length=2000)
    keywords: list[str] = PField(default_factory=list, max_length=50)
    signal: str | None = None
    analyzer: str | None = None
    weight: int = PField(ge=1, le=10)
    mode: Literal["BLOCK", "DETECT"] = "DETECT"
    description: str = PField(default="", max_length=500)
    enabled: bool = True


class RulePatch(BaseModel):
    pattern: str | None = PField(default=None, max_length=2000)
    keywords: list[str] | None = PField(default=None, max_length=50)
    weight: int | None = PField(default=None, ge=1, le=10)
    description: str | None = PField(default=None, max_length=500)
    enabled: bool | None = None
    category: Literal["SQLI", "XSS", "SCR", "CMD", "PATH", "FILE", "RESP", "ENC"] | None = None


class ModeIn(BaseModel):
    mode: Literal["BLOCK", "DETECT"]


class ExceptionIn(BaseModel):
    rule_id: str
    path: str = PField(min_length=1, max_length=512)
    param: str = PField(min_length=1, max_length=256)
    expires_at: datetime | None = None
    expires_in_days: int | None = PField(default=None, ge=1, le=MAX_EXCEPTION_DAYS)
    reason: str = PField(default="", max_length=500)
    source_request_id: UUID | None = None


class PathThresholdIn(BaseModel):
    path: str = PField(min_length=1, max_length=512)
    param: str | None = PField(default=None, max_length=256)
    prefix: bool = False
    threshold: int = PField(ge=1, le=20)
    reason: str = PField(min_length=5, max_length=500)


class RuleOverrideIn(BaseModel):
    path: str = PField(min_length=1, max_length=512)
    param: str | None = PField(default=None, max_length=256)
    prefix: bool = False
    rule_id: str = PField(min_length=1, max_length=16)
    mode: Literal["BLOCK", "DETECT"]
    reason: str = PField(min_length=5, max_length=500)


class ClassPhaseIn(BaseModel):
    phase: Literal["lobby", "vote", "reveal", "challenge", "end"]
    q: int | None = PField(default=None, ge=0, le=20)


class PublishIn(BaseModel):
    comment: str = PField(default="", max_length=500)


class TestIn(BaseModel):
    value: str | None = PField(default=None, max_length=1 << 20)
    location: str = "query"
    path: str = "/"
    param: str = "q"
    use: Literal["draft", "active"] = "draft"


class RollbackIn(BaseModel):
    reason: str = PField(default="", max_length=500)


# ───────────── 앱 ─────────────
def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or Settings()
    st: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        setup_logging(env("MPG_LOG_LEVEL", "INFO"))
        import redis.asyncio as aioredis

        pool = await create_pool(s.db_url)
        if s.auto_migrate:
            async with pool.acquire() as conn:
                await migrate(conn)
        r = aioredis.from_url(s.redis_url, socket_timeout=6, socket_connect_timeout=3,
                              health_check_interval=15)
        datasets = ps.Datasets.load(s.datasets_dir)
        consumer = EventConsumer(pool, r)
        st.update(pool=pool, redis=r, datasets=datasets, consumer=consumer)
        tasks = [asyncio.create_task(retention_loop(pool))]
        if s.run_consumer:
            tasks.append(asyncio.create_task(consumer.run()))
        tasks.append(asyncio.create_task(alerts_mod.webhook_loop(_current_alerts, s.webhook)))
        log.info("admin-api started", extra={"attacks": len(datasets.attacks),
                                             "normals": len(datasets.normals)})
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await r.aclose()
            await pool.close()

    async def _current_alerts():
        async with st["pool"].acquire() as conn:
            active = await ps.active_version(conn)
            return await alerts_mod.compute(
                conn, st["redis"], await st["consumer"].lag(),
                active["version"] if active else None,
                active["published_at"].timestamp() if active else None)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    api = APIRouter(prefix="/admin/api")

    @app.exception_handler(ps.PolicyError)
    async def _policy_error(_, e: ps.PolicyError):
        return JSONResponse({"error": e.code, "detail": e.detail}, status_code=e.status)

    @app.exception_handler(RuleError)
    async def _rule_error(_, e: RuleError):
        return JSONResponse({"error": "invalid_rule", "detail": str(e)}, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def _validation(_, e: RequestValidationError):
        errs = [{"loc": list(x.get("loc", [])), "msg": x.get("msg")} for x in e.errors()]
        return JSONResponse({"error": "validation_failed", "detail": errs}, status_code=422)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def client_ip(request: Request) -> str:
        peer = request.client.host if request.client else ""
        if s.trusted_proxies and ip_in(peer, s.trusted_proxies):
            real = request.headers.get("x-real-ip")
            if real:
                return real.strip()
        return peer

    def check_ip(request: Request) -> str:
        ip = client_ip(request)
        if not ip_in(ip, s.allow_nets):
            raise HTTPException(403, {"error": "ip_not_allowed"})
        return ip

    def require(role: str):
        async def dep(request: Request) -> auth.Session:
            check_ip(request)
            sess = await auth.load_session(st["redis"], request.cookies.get(auth.COOKIE))
            if not sess:
                raise HTTPException(401, {"error": "unauthenticated"})
            async with st["pool"].acquire() as conn:
                u = await conn.fetchrow("SELECT role, disabled FROM admin_users WHERE id=$1", sess.user_id)
            if not u or u["disabled"]:
                await auth.drop_session(st["redis"], sess.sid)
                raise HTTPException(401, {"error": "unauthenticated"})
            sess.role = u["role"]
            auth.check_csrf(request, sess)
            if not sess.at_least(role):
                raise HTTPException(403, {"error": "forbidden", "required": role})
            request.state.ip = client_ip(request)
            return sess
        return dep

    viewer, operator, admin = require("VIEWER"), require("OPERATOR"), require("ADMIN")

    # ── 인증 ──
    @api.post("/auth/login")
    async def login(body: LoginIn, request: Request, response: Response):
        ip = check_ip(request)
        r = st["redis"]
        if await auth.ip_failures(r, ip) >= auth.IP_FAIL_LIMIT:
            raise HTTPException(429, {"error": "too_many_attempts"})
        now = datetime.now(timezone.utc)
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                u = await conn.fetchrow("SELECT * FROM admin_users WHERE login_id=$1 FOR UPDATE",
                                        body.login_id)
                if u and u["locked_until"] and u["locked_until"] > now:
                    await audit(conn, body.login_id, "auth.login_failed", body.login_id,
                                reason="locked", client_ip=ip)
                    raise HTTPException(423, {"error": "account_locked",
                                              "locked_until": u["locked_until"].isoformat()})
                ok = auth.verify_password(u["password_hash"] if u else None, body.password)
                if not ok or u["disabled"]:
                    await auth.note_ip_failure(r, ip)
                    if u:
                        n = u["failed_count"] + 1
                        if n >= auth.LOCK_AFTER:
                            await conn.execute("UPDATE admin_users SET failed_count=0, locked_until=$2"
                                               " WHERE id=$1", u["id"], auth.lock_deadline(now))
                            await audit(conn, body.login_id, "auth.account_locked", body.login_id,
                                        client_ip=ip)
                        else:
                            await conn.execute("UPDATE admin_users SET failed_count=$2 WHERE id=$1",
                                               u["id"], n)
                    await audit(conn, body.login_id[:64], "auth.login_failed", body.login_id[:64],
                                client_ip=ip)
                    raise HTTPException(401, {"error": "invalid_credentials"})
                await conn.execute("UPDATE admin_users SET failed_count=0, locked_until=NULL,"
                                   " last_login_at=now() WHERE id=$1", u["id"])
                await audit(conn, u["login_id"], "auth.login", u["login_id"], client_ip=ip)
        sess = await auth.create_session(r, u["id"], u["login_id"], u["role"])
        response.set_cookie(auth.COOKIE, sess.sid, max_age=auth.SESSION_TTL, httponly=True,
                            secure=s.cookie_secure, samesite="strict", path="/admin/api")
        return {"login_id": sess.login_id, "role": sess.role, "csrf_token": sess.csrf}

    @api.post("/auth/logout")
    async def logout(response: Response, sess: auth.Session = Depends(viewer), request: Request = None):
        await auth.drop_session(st["redis"], sess.sid)
        async with st["pool"].acquire() as conn:
            await audit(conn, sess.login_id, "auth.logout", sess.login_id, client_ip=request.state.ip)
        response.delete_cookie(auth.COOKIE, path="/admin/api")
        return {"ok": True}

    @api.get("/auth/me")
    async def me(sess: auth.Session = Depends(viewer)):
        return {"login_id": sess.login_id, "role": sess.role, "csrf_token": sess.csrf}

    # ── 탐지 로그 ──
    def _enc_cursor(ts: datetime, rid) -> str:
        return base64.urlsafe_b64encode(f"{ts.isoformat()}|{rid}".encode()).decode()

    def _dec_cursor(c: str):
        try:
            ts, rid = base64.urlsafe_b64decode(c.encode()).decode().split("|")
            return datetime.fromisoformat(ts), UUID(rid)
        except Exception:
            raise HTTPException(400, {"error": "bad_cursor"}) from None

    @api.get("/events")
    async def events(
        sess: auth.Session = Depends(viewer),
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        rule: str | None = Query(None, max_length=16),
        action: Literal["BLOCK", "DETECT_ONLY"] | None = None,
        q: str | None = Query(None, max_length=200),
        fp: bool | None = None,
        cursor: str | None = None,
        limit: int = Query(50, ge=1, le=200),
    ):
        where, args = [], []

        def add(cond: str, val):
            args.append(val)
            where.append(cond.replace("?", f"${len(args)}"))

        if from_:
            add("e.ts >= ?", from_)
        if to:
            add("e.ts < ?", to)
        if action:
            add("e.action = ?", action)
        if fp is not None:
            add("e.false_positive = ?", fp)
        if rule:
            add("EXISTS (SELECT 1 FROM event_matches m WHERE m.request_id=e.request_id AND m.rule_id = ?)", rule)
        if q:
            try:
                add("e.request_id = ?", UUID(q.strip()))
            except ValueError:
                pat = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                args.append(pat)
                i = len(args)
                args.append(q.strip())
                where.append(f"(e.path ILIKE ${i} OR e.masked_sample ILIKE ${i} OR host(e.client_ip) = ${i + 1})")
        if cursor:
            ts, rid = _dec_cursor(cursor)
            args += [ts, rid]
            where.append(f"(e.ts, e.request_id) < (${len(args) - 1}, ${len(args)})")
        sql = ("SELECT e.*, (SELECT array_agg(DISTINCT m.rule_id ORDER BY m.rule_id) FROM event_matches m"
               " WHERE m.request_id=e.request_id AND NOT m.excepted) AS rules FROM security_events e")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY e.ts DESC, e.request_id DESC LIMIT {limit + 1}"
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch(sql, *args)
        more = len(rows) > limit
        rows = rows[:limit]
        return {
            "items": [_event_out(r) for r in rows],
            "next_cursor": _enc_cursor(rows[-1]["ts"], rows[-1]["request_id"]) if more else None,
        }

    def _event_out(r) -> dict:
        return {
            "request_id": str(r["request_id"]), "ts": r["ts"].isoformat(),
            "client_ip": str(r["client_ip"]) if r["client_ip"] else None, "method": r["method"],
            "path": r["path"], "risk_score": r["risk_score"], "action": r["action"],
            "policy_version": r["policy_version"], "field_ref": r["field_ref"],
            "masked_sample": r["masked_sample"], "false_positive": r["false_positive"],
            "rules": list(r["rules"] or []) if "rules" in r.keys() else None,
        }

    async def _event_policy(conn, version: int):
        row = await conn.fetchrow("SELECT snapshot FROM policy_versions WHERE version=$1", version)
        if row:
            return ps.compile_snapshot(row["snapshot"], version)
        active = await ps.active_version(conn)
        return ps.compile_snapshot(active["snapshot"], active["version"]) if active else None

    @api.get("/events/{request_id}")
    async def event_detail(request_id: UUID, request: Request, sess: auth.Session = Depends(viewer)):
        async with st["pool"].acquire() as conn:
            e = await conn.fetchrow("SELECT * FROM security_events WHERE request_id=$1", request_id)
            if not e:
                raise HTTPException(404, {"error": "not_found"})
            matches = await conn.fetch("SELECT rule_id, field_ref, score, mode, excepted FROM event_matches"
                                       " WHERE request_id=$1 ORDER BY score DESC, rule_id", request_id)
            policy = await _event_policy(conn, e["policy_version"])
            await audit(conn, sess.login_id, "event.view", str(request_id), client_ip=request.state.ip)
        loc, _, name = e["field_ref"].partition(".")
        recomputed = None
        # 응답에서 찾은 유출은 원문을 저장하지 않아 재계산할 수 없다.
        if policy and e["masked_sample"] not in ("[redacted]", "[response redacted]") and loc != "response":
            try:
                recomputed = ps.sandbox(policy, e["masked_sample"], loc, e["path"], name)
            except ps.PolicyError:
                recomputed = ps.sandbox(policy, e["masked_sample"], "body", e["path"], name)
        out = _event_out(e)
        out.update(matches=[dict(m) for m in matches], recomputed=recomputed,
                   fp_marked_by=e["fp_marked_by"],
                   fp_marked_at=e["fp_marked_at"].isoformat() if e["fp_marked_at"] else None,
                   note="재계산은 마스킹된 샘플(최대 256자)로 수행하므로 원래 판정과 다를 수 있습니다.")
        return out

    @api.post("/events/{request_id}/false-positive")
    async def mark_fp(request_id: UUID, request: Request, sess: auth.Session = Depends(operator)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                e = await conn.fetchrow("SELECT * FROM security_events WHERE request_id=$1 FOR UPDATE",
                                        request_id)
                if not e:
                    raise HTTPException(404, {"error": "not_found"})
                matches = await conn.fetch(
                    "SELECT rule_id, field_ref, score, mode FROM event_matches WHERE request_id=$1"
                    " AND NOT excepted ORDER BY score DESC, rule_id", request_id)
                await conn.execute("UPDATE security_events SET false_positive=true, fp_marked_by=$2,"
                                   " fp_marked_at=now() WHERE request_id=$1", request_id, sess.login_id)
                await audit(conn, sess.login_id, "event.false_positive", str(request_id),
                            {"false_positive": e["false_positive"]}, {"false_positive": True},
                            client_ip=request.state.ip)
        field = e["field_ref"]
        same = [m for m in matches if m["field_ref"] == field] or list(matches)
        candidates = [m for m in same if m["mode"] == "BLOCK" and not m["rule_id"].startswith("ENC")] or same
        if not candidates:
            return {"marked": True, "draft": None}
        top = candidates[0]
        param = top["field_ref"].partition(".")[2]
        total_after = sum(m["score"] for m in same) - top["score"]
        return {
            "marked": True,
            "draft": {
                "rule_id": top["rule_id"], "path": e["path"], "param": param,
                "expires_in_days": 30, "source_request_id": str(request_id),
                "reason": f"오탐 처리 (요청 {request_id})",
            },
            "score_before": e["risk_score"], "score_after_estimate": total_after,
            "alternatives": [{"rule_id": m["rule_id"], "score": m["score"]} for m in candidates[1:]],
        }

    # ── 룰 ──
    @api.get("/rules")
    async def rules_list(sess: auth.Session = Depends(viewer)):
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch("SELECT * FROM rules ORDER BY id")
            active = await ps.active_version(conn)
        pub = {r["id"]: r for r in (active["snapshot"]["rules"] if active else [])}
        out = []
        for r in rows:
            d = ps._rule_row_to_dict(r)
            d["updated_at"] = r["updated_at"].isoformat()
            d["updated_by"] = r["updated_by"]
            d["published"] = r["id"] in pub
            d["dirty"] = pub.get(r["id"]) != ps._rule_row_to_dict(r)
            out.append(d)
        return out

    @api.post("/rules", status_code=201)
    async def rules_create(body: RuleIn, request: Request, sess: auth.Session = Depends(operator)):
        d = body.model_dump(exclude_none=True)
        rule_from_dict(d)
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                if await conn.fetchval("SELECT 1 FROM rules WHERE id=$1", body.id):
                    raise HTTPException(409, {"error": "rule_exists"})
                await ps.upsert_rule(conn, d, sess.login_id)
                await audit(conn, sess.login_id, "rule.create", body.id, None, d, client_ip=request.state.ip)
            return {"rule": d, "unpublished_changes": await _changes_count(conn)}

    async def _get_rule(conn, rid: str) -> dict:
        r = await conn.fetchrow("SELECT * FROM rules WHERE id=$1 FOR UPDATE", rid)
        if not r:
            raise HTTPException(404, {"error": "rule_not_found"})
        return ps._rule_row_to_dict(r)

    @api.patch("/rules/{rid}")
    async def rules_patch(rid: str, body: RulePatch, request: Request, sess: auth.Session = Depends(operator)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                before = await _get_rule(conn, rid)
                after = {**before, **body.model_dump(exclude_none=True)}
                rule_from_dict(after)
                await ps.upsert_rule(conn, after, sess.login_id)
                await audit(conn, sess.login_id, "rule.update", rid, before, after, client_ip=request.state.ip)
            return {"rule": after, "unpublished_changes": await _changes_count(conn)}

    @api.patch("/rules/{rid}/mode")
    async def rules_mode(rid: str, body: ModeIn, request: Request, sess: auth.Session = Depends(operator)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                before = await _get_rule(conn, rid)
                after = {**before, "mode": body.mode}
                await ps.upsert_rule(conn, after, sess.login_id)
                await audit(conn, sess.login_id, "rule.mode", rid, {"mode": before["mode"]},
                            {"mode": body.mode}, client_ip=request.state.ip)
            return {"rule": after, "unpublished_changes": await _changes_count(conn)}

    # ── 예외 ──
    @api.get("/exceptions")
    async def exc_list(sess: auth.Session = Depends(viewer), include_inactive: bool = False):
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM rule_exceptions" + ("" if include_inactive else " WHERE active")
                + " ORDER BY id DESC")
            active = await ps.active_version(conn)
        published = {str(e["id"]) for e in (active["snapshot"].get("exceptions", []) if active else [])}
        now = datetime.now(timezone.utc)
        return [{
            "id": r["id"], "rule_id": r["rule_id"], "path": r["path"], "param": r["param"],
            "expires_at": r["expires_at"].isoformat(), "expired": r["expires_at"] <= now,
            "reason": r["reason"], "active": r["active"], "created_by": r["created_by"],
            "created_at": r["created_at"].isoformat(),
            "source_request_id": str(r["source_request_id"]) if r["source_request_id"] else None,
            "published": str(r["id"]) in published,
        } for r in rows]

    async def _insert_exception(conn, body: ExceptionIn, sess: auth.Session, ip: str) -> int:
        now = datetime.now(timezone.utc)
        expires = body.expires_at or (now + timedelta(days=body.expires_in_days or 30))
        if expires.tzinfo is None:
            raise HTTPException(422, {"error": "expires_at_needs_timezone"})
        if expires <= now or expires > now + timedelta(days=MAX_EXCEPTION_DAYS):
            raise HTTPException(422, {"error": "expires_at_out_of_range", "max_days": MAX_EXCEPTION_DAYS})
        exception_from_dict({"rule_id": body.rule_id, "path": body.path, "param": body.param,
                             "expires_at": expires})
        if not body.path.startswith("/"):
            raise HTTPException(422, {"error": "path_must_start_with_slash"})
        if not await conn.fetchval("SELECT 1 FROM rules WHERE id=$1", body.rule_id):
            raise HTTPException(422, {"error": "rule_not_found"})
        dup = await conn.fetchval(
            "SELECT id FROM rule_exceptions WHERE active AND expires_at > now() AND rule_id=$1"
            " AND path=$2 AND param=$3", body.rule_id, body.path, body.param)
        if dup:
            raise HTTPException(409, {"error": "exception_exists", "id": dup})
        eid = await conn.fetchval(
            "INSERT INTO rule_exceptions(rule_id, path, param, expires_at, reason, source_request_id,"
            " created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
            body.rule_id, body.path, body.param, expires, body.reason, body.source_request_id, sess.login_id)
        await audit(conn, sess.login_id, "exception.create", str(eid), None,
                    {"rule_id": body.rule_id, "path": body.path, "param": body.param,
                     "expires_at": expires.isoformat(),
                     "source_request_id": str(body.source_request_id) if body.source_request_id else None},
                    body.reason, ip)
        return eid

    @api.post("/exceptions", status_code=201)
    async def exc_create(body: ExceptionIn, request: Request, publish: bool = False,
                         sess: auth.Session = Depends(operator)):
        if not publish:
            async with st["pool"].acquire() as conn:
                async with conn.transaction():
                    eid = await _insert_exception(conn, body, sess, request.state.ip)
                return {"id": eid, "unpublished_changes": await _changes_count(conn)}
        # 3-3 시퀀스: 예외 등록과 발행을 한 번에. 회귀 실패면 예외도 남기지 않는다.
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                eid = await _insert_exception(conn, body, sess, request.state.ip)
        try:
            result = await ps.publish(st["pool"], st["redis"], st["datasets"], sess.login_id,
                                      body.reason or f"exception {eid}", request.state.ip)
        except ps.PolicyError:
            async with st["pool"].acquire() as conn:
                await conn.execute("UPDATE rule_exceptions SET active=false WHERE id=$1", eid)
                await audit(conn, sess.login_id, "exception.discard", str(eid),
                            reason="publish rejected", client_ip=request.state.ip)
            raise
        return {"id": eid, **result}

    @api.delete("/exceptions/{eid}")
    async def exc_delete(eid: int, request: Request, sess: auth.Session = Depends(operator)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                r = await conn.fetchrow("UPDATE rule_exceptions SET active=false WHERE id=$1 AND active"
                                        " RETURNING rule_id, path, param", eid)
                if not r:
                    raise HTTPException(404, {"error": "not_found"})
                await audit(conn, sess.login_id, "exception.deactivate", str(eid), dict(r), None,
                            client_ip=request.state.ip)
            return {"ok": True, "unpublished_changes": await _changes_count(conn)}

    # ── 경로별 차단 임계값 ──
    @api.get("/thresholds")
    async def thresholds_list(sess: auth.Session = Depends(viewer), include_inactive: bool = False):
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch("SELECT * FROM path_thresholds"
                                    + ("" if include_inactive else " WHERE active") + " ORDER BY id DESC")
            active = await ps.active_version(conn)
        snap = active["snapshot"] if active else {}
        published = {str(t["id"]) for t in snap.get("path_thresholds", [])}
        return {
            "global_threshold": snap.get("threshold", 6),
            "items": [{
                "id": r["id"], "path": r["path"], "param": r["param"], "prefix": r["prefix"],
                "threshold": r["threshold"], "reason": r["reason"], "active": r["active"],
                "created_by": r["created_by"], "created_at": r["created_at"].isoformat(),
                "published": str(r["id"]) in published,
            } for r in rows],
        }

    @api.post("/thresholds", status_code=201)
    async def thresholds_create(body: PathThresholdIn, request: Request, sess: auth.Session = Depends(admin)):
        param = body.param.strip() if body.param and body.param.strip() else None
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                active = await ps.active_version(conn)
                global_t = active["snapshot"].get("threshold", 6) if active else 6
                path_threshold_from_dict({"path": body.path, "param": param, "prefix": body.prefix,
                                          "threshold": body.threshold}, global_t)
                dup = await conn.fetchval(
                    "SELECT id FROM path_thresholds WHERE active AND path=$1 AND coalesce(param,'')=$2 AND prefix=$3",
                    body.path, param or "", body.prefix)
                if dup:
                    raise HTTPException(409, {"error": "threshold_exists", "id": dup})
                tid = await conn.fetchval(
                    "INSERT INTO path_thresholds(path, param, prefix, threshold, reason, created_by)"
                    " VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
                    body.path, param, body.prefix, body.threshold, body.reason, sess.login_id)
                await audit(conn, sess.login_id, "threshold.create", str(tid), None,
                            {"path": body.path, "param": param, "prefix": body.prefix,
                             "threshold": body.threshold, "global": global_t}, body.reason, request.state.ip)
            return {"id": tid, "unpublished_changes": await _changes_count(conn)}

    @api.delete("/thresholds/{tid}")
    async def thresholds_delete(tid: int, request: Request, sess: auth.Session = Depends(admin)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                r = await conn.fetchrow("UPDATE path_thresholds SET active=false WHERE id=$1 AND active"
                                        " RETURNING path, param, prefix, threshold", tid)
                if not r:
                    raise HTTPException(404, {"error": "not_found"})
                await audit(conn, sess.login_id, "threshold.deactivate", str(tid), dict(r), None,
                            client_ip=request.state.ip)
            return {"ok": True, "unpublished_changes": await _changes_count(conn)}

    # ── 경로별 룰 모드 ──
    @api.get("/rule-overrides")
    async def overrides_list(sess: auth.Session = Depends(viewer), include_inactive: bool = False):
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch(
                "SELECT o.*, r.mode AS global_mode, r.weight, r.description FROM path_rule_overrides o"
                " JOIN rules r ON r.id = o.rule_id"
                + ("" if include_inactive else " WHERE o.active") + " ORDER BY o.id DESC")
            active = await ps.active_version(conn)
        published = {str(o["id"]) for o in (active["snapshot"] if active else {}).get("rule_overrides", [])}
        return [{
            "id": r["id"], "path": r["path"], "param": r["param"], "prefix": r["prefix"],
            "rule_id": r["rule_id"], "mode": r["mode"], "global_mode": r["global_mode"], "weight": r["weight"],
            "description": r["description"], "reason": r["reason"], "active": r["active"],
            "created_by": r["created_by"], "created_at": r["created_at"].isoformat(),
            "published": str(r["id"]) in published,
        } for r in rows]

    @api.post("/rule-overrides", status_code=201)
    async def overrides_create(body: RuleOverrideIn, request: Request, sess: auth.Session = Depends(admin)):
        param = body.param.strip() if body.param and body.param.strip() else None
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                rule_rows = await conn.fetch("SELECT * FROM rules")
                rules = load_rules(ps._rule_row_to_dict(r) for r in rule_rows)
                rule_override_from_dict({"path": body.path, "param": param, "prefix": body.prefix,
                                         "rule_id": body.rule_id, "mode": body.mode}, rules, strict=True)
                dup = await conn.fetchval(
                    "SELECT id FROM path_rule_overrides WHERE active AND path=$1 AND coalesce(param,'')=$2"
                    " AND prefix=$3 AND rule_id=$4", body.path, param or "", body.prefix, body.rule_id)
                if dup:
                    raise HTTPException(409, {"error": "override_exists", "id": dup})
                oid = await conn.fetchval(
                    "INSERT INTO path_rule_overrides(path, param, prefix, rule_id, mode, reason, created_by)"
                    " VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
                    body.path, param, body.prefix, body.rule_id, body.mode, body.reason, sess.login_id)
                await audit(conn, sess.login_id, "rule_override.create", str(oid), None,
                            {"path": body.path, "param": param, "prefix": body.prefix,
                             "rule_id": body.rule_id, "mode": body.mode}, body.reason, request.state.ip)
            return {"id": oid, "unpublished_changes": await _changes_count(conn)}

    @api.delete("/rule-overrides/{oid}")
    async def overrides_delete(oid: int, request: Request, sess: auth.Session = Depends(admin)):
        async with st["pool"].acquire() as conn:
            async with conn.transaction():
                r = await conn.fetchrow("UPDATE path_rule_overrides SET active=false WHERE id=$1 AND active"
                                        " RETURNING path, param, prefix, rule_id, mode", oid)
                if not r:
                    raise HTTPException(404, {"error": "not_found"})
                await audit(conn, sess.login_id, "rule_override.deactivate", str(oid), dict(r), None,
                            client_ip=request.state.ip)
            return {"ok": True, "unpublished_changes": await _changes_count(conn)}

    # ── 정책 ──
    async def _changes(conn) -> list[dict]:
        snap = await ps.draft_snapshot(conn)
        active = await ps.active_version(conn)
        return ps.diff_snapshots(snap, active["snapshot"] if active else None)

    async def _changes_count(conn) -> int:
        return len(await _changes(conn))

    @api.get("/policy/changes")
    async def policy_changes(sess: auth.Session = Depends(viewer)):
        async with st["pool"].acquire() as conn:
            changes = await _changes(conn)
            active = await ps.active_version(conn)
        return {"active_version": active["version"] if active else None, "changes": changes}

    @api.post("/policy/test")
    async def policy_test(body: TestIn, request: Request, sess: auth.Session = Depends(operator)):
        async with st["pool"].acquire() as conn:
            if body.value is not None:
                if body.use == "active":
                    a = await ps.active_version(conn)
                    if not a:
                        raise HTTPException(409, {"error": "no_active_policy"})
                    policy = ps.compile_snapshot(a["snapshot"], a["version"])
                else:
                    policy = ps.compile_snapshot(await ps.draft_snapshot(conn), 0)
                return ps.sandbox(policy, body.value, body.location, body.path, body.param)
            result = await ps.test_draft(conn, st["datasets"])
            await ps._record_run(conn, sess.login_id, "test", None, result["report"])
        result.pop("report")
        return result

    @api.post("/policy/publish", status_code=201)
    async def policy_publish(body: PublishIn, request: Request, sess: auth.Session = Depends(operator)):
        return await ps.publish(st["pool"], st["redis"], st["datasets"], sess.login_id, body.comment,
                                request.state.ip)

    @api.get("/policy/versions")
    async def versions(sess: auth.Session = Depends(admin)):
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch(
                """SELECT v.version, v.active, v.published_at, v.published_by, v.comment, v.rolled_back_from,
                          jsonb_array_length(v.snapshot->'rules') AS rules,
                          jsonb_array_length(v.snapshot->'exceptions') AS exceptions,
                          r.detection_rate, r.fp_rate
                   FROM policy_versions v
                   LEFT JOIN LATERAL (SELECT detection_rate, fp_rate FROM regression_runs
                                      WHERE policy_version=v.version ORDER BY id DESC LIMIT 1) r ON true
                   ORDER BY v.version DESC LIMIT 100""")
        return [{**dict(r), "published_at": r["published_at"].isoformat()} for r in rows]

    @api.post("/policy/rollback/{version}")
    async def policy_rollback(version: int, request: Request, body: RollbackIn | None = None,
                              sess: auth.Session = Depends(admin)):
        return await ps.rollback(st["pool"], st["redis"], st["datasets"], version, sess.login_id,
                                 body.reason if body else "", request.state.ip)

    # ── 대시보드 ──
    @api.get("/metrics/summary")
    async def summary(period: Literal["1h", "24h", "7d", "30d"] = "24h", sess: auth.Session = Depends(viewer)):
        interval = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}[period]
        bucket = "hour" if period in ("1h", "24h") else "day"
        async with st["pool"].acquire() as conn:
            counts = await conn.fetchrow(
                f"""SELECT count(*) FILTER (WHERE action='BLOCK') AS blocked,
                           count(*) FILTER (WHERE action='DETECT_ONLY') AS detected,
                           count(*) FILTER (WHERE false_positive) AS false_positives
                    FROM security_events WHERE ts > now() - interval '{interval}'""")
            series = await conn.fetch(
                f"""SELECT date_trunc('{bucket}', ts) AS t,
                           count(*) FILTER (WHERE action='BLOCK') AS blocked,
                           count(*) FILTER (WHERE action='DETECT_ONLY') AS detected
                    FROM security_events WHERE ts > now() - interval '{interval}' GROUP BY 1 ORDER BY 1""")
            top = await conn.fetch(
                f"""SELECT m.rule_id, count(*) AS n FROM event_matches m JOIN security_events e USING (request_id)
                    WHERE e.ts > now() - interval '{interval}' AND NOT m.excepted
                    GROUP BY 1 ORDER BY 2 DESC LIMIT 10""")
            active = await ps.active_version(conn)
            last_run = await conn.fetchrow(
                "SELECT ts, kind, policy_version, detection_rate, fp_rate, attack_total, normal_total"
                " FROM regression_runs WHERE kind IN ('publish','cli') ORDER BY id DESC LIMIT 1")
            changes = await _changes_count(conn)
            lag = await st["consumer"].lag()
            alert_list = await alerts_mod.compute(
                conn, st["redis"], lag, active["version"] if active else None,
                active["published_at"].timestamp() if active else None)
        gws = await alerts_mod.gateway_stats(st["redis"])
        return {
            "period": period,
            "counts": dict(counts),
            "series": [{"t": r["t"].isoformat(), "blocked": r["blocked"], "detected": r["detected"]} for r in series],
            "top_rules": [dict(r) for r in top],
            "gateways": gws,
            "active_policy": {"version": active["version"], "published_at": active["published_at"].isoformat(),
                              "published_by": active["published_by"]} if active else None,
            "regression": {**dict(last_run), "ts": last_run["ts"].isoformat()} if last_run else None,
            "unpublished_changes": changes,
            "consumer": {"lag": lag, "processed": st["consumer"].processed},
            "alerts": alert_list,
        }

    @api.get("/audit")
    async def audit_list(sess: auth.Session = Depends(admin), action: str | None = Query(None, max_length=64),
                         actor: str | None = Query(None, max_length=64), before_id: int | None = None,
                         limit: int = Query(100, ge=1, le=500)):
        where, args = [], []
        for col, val in (("action", action), ("actor", actor)):
            if val:
                args.append(val)
                where.append(f"{col} = ${len(args)}")
        if before_id:
            args.append(before_id)
            where.append(f"id < ${len(args)}")
        sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "")
        sql += f" ORDER BY id DESC LIMIT {limit}"
        async with st["pool"].acquire() as conn:
            rows = await conn.fetch(sql, *args)
        return [{**dict(r), "ts": r["ts"].isoformat(), "client_ip": str(r["client_ip"]) if r["client_ip"] else None}
                for r in rows]

    # ── 수업 참여(발표자) — 콘솔 로그인(OPERATOR 이상)으로 쓴다 ──
    async def _classroom(method: str, path: str, body: dict | None = None) -> Response:
        if not s.classroom_key:
            raise HTTPException(503, {"error": "classroom_not_configured"})
        try:
            async with httpx.AsyncClient(base_url=s.classroom_url, timeout=10) as c:
                r = await c.request(method, f"/api/presenter/{path}", json=body,
                                    headers={"X-Presenter-Key": s.classroom_key})
        except httpx.HTTPError:
            raise HTTPException(503, {"error": "classroom_down"}) from None
        if r.status_code >= 400:
            raise HTTPException(r.status_code, {"error": "classroom_error", "detail": r.text[:200]})
        return Response(r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type", "application/json"))

    @api.get("/class/state")
    async def class_state(sess: auth.Session = Depends(operator)):
        return await _classroom("GET", "state")

    @api.get("/class/qr.svg")
    async def class_qr(sess: auth.Session = Depends(operator)):
        return await _classroom("GET", "qr.svg")

    @api.post("/class/phase")
    async def class_phase(body: ClassPhaseIn, sess: auth.Session = Depends(operator)):
        return await _classroom("POST", "phase", body.model_dump(exclude_none=True))

    @api.post("/class/reset")
    async def class_reset(request: Request, sess: auth.Session = Depends(operator)):
        res = await _classroom("POST", "reset")
        async with st["pool"].acquire() as conn:
            await audit(conn, sess.login_id, "classroom.reset", "", client_ip=request.state.ip)
        return res

    @app.get("/health")
    async def health():
        try:
            async with st["pool"].acquire() as conn:
                await conn.fetchval("SELECT 1")
            await st["redis"].ping()
        except Exception as e:
            return JSONResponse({"status": "degraded", "error": type(e).__name__}, status_code=503)
        return {"status": "ok"}

    app.include_router(api)
    app.state.mpg = st
    return app


def get_app() -> FastAPI:
    return create_app()
