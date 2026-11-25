"""관리자 인증: Argon2id 해시, Redis 세션(유휴 30분), CSRF 토큰, 역할 기반 접근 제어, 로그인 잠금."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request

ROLES = {"VIEWER": 1, "OPERATOR": 2, "ADMIN": 3}
SESSION_TTL = 30 * 60
COOKIE = "mpg_sid"
LOCK_AFTER = 5
LOCK_FOR = timedelta(minutes=15)
IP_FAIL_LIMIT = 20
IP_FAIL_WINDOW = 600
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

hasher = PasswordHasher()
_DUMMY = hasher.hash(secrets.token_hex(16))


def hash_password(pw: str) -> str:
    if len(pw) < 10:
        raise ValueError("password must be at least 10 characters")
    return hasher.hash(pw)


def verify_password(stored: str | None, pw: str) -> bool:
    try:
        return hasher.verify(stored or _DUMMY, pw) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _key(sid: str) -> str:
    return "sess:" + hashlib.sha256(sid.encode()).hexdigest()


@dataclass
class Session:
    sid: str
    user_id: int
    login_id: str
    role: str
    csrf: str

    def at_least(self, role: str) -> bool:
        return ROLES[self.role] >= ROLES[role]


async def create_session(redis, user_id: int, login_id: str, role: str) -> Session:
    sid = secrets.token_urlsafe(32)
    s = Session(sid, user_id, login_id, role, secrets.token_urlsafe(32))
    await redis.set(_key(sid), json.dumps({"user_id": user_id, "login_id": login_id,
                                           "role": role, "csrf": s.csrf}), ex=SESSION_TTL)
    return s


async def load_session(redis, sid: str | None) -> Session | None:
    if not sid or len(sid) > 128:
        return None
    raw = await redis.get(_key(sid))
    if not raw:
        return None
    await redis.expire(_key(sid), SESSION_TTL)
    d = json.loads(raw)
    return Session(sid, d["user_id"], d["login_id"], d["role"], d["csrf"])


async def drop_session(redis, sid: str) -> None:
    await redis.delete(_key(sid))


async def drop_user_sessions(redis, login_id: str) -> int:
    n = 0
    async for k in redis.scan_iter("sess:*", count=500):
        raw = await redis.get(k)
        if raw and json.loads(raw).get("login_id") == login_id:
            n += await redis.delete(k)
    return n


async def ip_failures(redis, ip: str) -> int:
    v = await redis.get(f"loginfail:{ip}")
    return int(v or 0)


async def note_ip_failure(redis, ip: str) -> None:
    k = f"loginfail:{ip}"
    n = await redis.incr(k)
    if n == 1:
        await redis.expire(k, IP_FAIL_WINDOW)


def check_csrf(request: Request, session: Session) -> None:
    if request.method in UNSAFE:
        token = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(token.encode(), session.csrf.encode()):
            raise HTTPException(403, {"error": "csrf_failed"})


def lock_deadline(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) + LOCK_FOR
