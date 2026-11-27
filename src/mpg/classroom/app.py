"""수업 발표용 실시간 참여 서비스.

학생은 휴대폰으로 접속해(QR) 닉네임을 정하고, 발표자가 넘기는 단계에 따라
  1) 예측 투표: 문자열이 게이트웨이에서 '막힌다/통과한다' 를 고른다 → 발표자가 공개하면 실제 요청을 보내 판정을 보여 준다.
  2) 우회 챌린지: 직접 입력한 문자열을 실제 게이트웨이로 보내 차단/통과를 본다.
     통과한 입력은 발표자 화면에 뜨고, 발표자가 '공격으로 인정' 한 것만 순위에 오른다(평범한 글로 점수를 얻지 못하게).
상태는 메모리에만 둔다(워커 1개, 20~40명 규모). 서버를 내리면 사라진다.

보안: 학생 입력은 공격 문자열이므로 화면에는 textContent로만 넣고(정적 JS, CSP script-src 'self'),
요청은 게이트웨이(LB)로만 보낸다. 발표자 기능은 시작할 때 만든 키가 있어야 쓴다.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field as PField

STATIC = Path(__file__).parent / "static"
GATEWAY = os.environ.get("MPG_CLASS_GATEWAY", "https://edge-lb:8443").rstrip("/")
PUBLIC_URL = os.environ.get("MPG_CLASS_URL", "http://localhost:8080/")
MAX_PAYLOAD = 500
SUBMIT_INTERVAL = 1.5  # 학생 1명당 제출 간격(초)
MAX_SUBMISSIONS = 3000


def _presenter_key() -> str:
    path = os.environ.get("MPG_CLASS_PRESENTER_KEY_FILE")
    if path and Path(path).exists():
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get("MPG_CLASS_PRESENTER_KEY") or secrets.token_urlsafe(16)


PRESENTER_KEY = _presenter_key()

TARGETS = {
    "login": {"label": "로그인 아이디", "method": "GET", "path": "/api/login", "param": "username"},
    "search": {"label": "상품 검색", "method": "GET", "path": "/api/search", "param": "q"},
    "board": {"label": "게시판 글", "method": "POST", "path": "/api/qna/posts", "param": "content"},
    "ping": {"label": "핑 도구 호스트", "method": "GET", "path": "/api/tools/ping", "param": "host"},
}

# ── 변장 챌린지 ──
# 학생은 공격 카드 하나 + 변장 카드 여러 개를 골라 '보내기'만 누른다. 서버가 문자열을 만들어 실제 게이트웨이로 보낸다.
# 공격 원본은 항상 진짜 공격이라, '통과 = 진짜로 뚫은 것' 이다(발표자 심사가 필요 없다).
ATTACKS = {
    "login": {"label": "🔑 로그인 뚫기", "base": "' OR 1=1--", "target": "login",
              "desc": "아이디 칸에 넣어 비밀번호 없이 로그인"},
    "script": {"label": "💉 스크립트 심기", "base": "<script>alert(1)</script>", "target": "search",
               "desc": "검색어에 넣어 남의 화면에서 코드 실행"},
    "command": {"label": "💻 서버 명령 실행", "base": "; cat /etc/passwd", "target": "ping",
                "desc": "핑 도구에 넣어 서버 비밀 파일 읽기"},
}

# 변장은 고정 순서로 적용한다. case/encode/comment 는 정규화가 되돌려 막히고, look/glob 은 실제 빈틈을 노린다.
_LOOKALIKE = {"'": "’", '"': "”", "<": "‹", ">": "›"}


def _d_case(s: str) -> str:
    import random
    r = random.Random(s)
    return "".join(c.upper() if c.isalpha() and r.random() < 0.5 else c for c in s)


def _d_encode(s: str) -> str:
    return quote(s, safe="")


def _d_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def _d_look(s: str) -> str:
    return "".join(_LOOKALIKE.get(c, c) for c in s)


def _d_glob(s: str) -> str:
    import re as _re
    return _re.sub(r"[a-z]", lambda m: f"[{m.group(0)}]", s, count=1)


DISGUISES = {
    "case": {"label": "🔤 대소문자 섞기", "fn": _d_case, "blurb": "SeLeCt 처럼 대소문자를 뒤섞는다"},
    "encode": {"label": "🔒 URL 인코딩", "fn": _d_encode, "blurb": "%27 처럼 한 겹 더 인코딩한다"},
    "comment": {"label": "💬 주석 끼우기", "fn": _d_comment, "blurb": "빈칸을 /**/ 주석으로 바꾼다"},
    "look": {"label": "🎭 닮은 문자로", "fn": _d_look, "blurb": "' < > 를 비슷하게 생긴 유니코드로 바꾼다"},
    "glob": {"label": "✨ 셸 글롭", "fn": _d_glob, "blurb": "글자 하나를 [x] 로 — 셸은 같게 읽는다"},
}
DISGUISE_ORDER = ["look", "glob", "comment", "case", "encode"]  # encode 는 마지막(가장 바깥 겹)


def build_payload(attack: str, disguises: list[str]) -> tuple[str, bool]:
    """(보낼 문자열, raw여부). raw=True 면 이미 %인코딩이 들어 있어 전송용 재인코딩을 하지 않는다."""
    s = ATTACKS[attack]["base"]
    chosen = [d for d in DISGUISE_ORDER if d in disguises]
    for d in chosen:
        s = DISGUISES[d]["fn"](s)
    return s, "encode" in chosen


@dataclass
class Student:
    sid: str
    nick: str
    joined: float
    last_submit: float = 0.0
    cracked: dict[str, float] = field(default_factory=dict)  # attack -> 처음 뚫은 시각


@dataclass
class Submission:
    id: int
    sid: str
    nick: str
    attack: str
    disguises: list[str]
    payload: str
    status: int
    blocked: bool
    request_id: str
    ts: float


@dataclass
class State:
    phase: str = "lobby"  # lobby | challenge | end
    students: dict[str, Student] = field(default_factory=dict)
    submissions: list[Submission] = field(default_factory=list)
    version: int = 0


st = State()
lock = asyncio.Lock()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
client: httpx.AsyncClient | None = None


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.on_event("startup")
async def _startup() -> None:
    global client
    # 같은 PC 안의 LB로 보내는 내부 홉. LB 인증서는 발표용 자체 서명(SAN=localhost)이라 검증하지 않는다.
    client = httpx.AsyncClient(base_url=GATEWAY, verify=False, timeout=8,
                               limits=httpx.Limits(max_connections=50))


@app.on_event("shutdown")
async def _shutdown() -> None:
    if client:
        await client.aclose()


# ───────────── 게이트웨이로 보내기 ─────────────
async def send_to_gateway(target: str, payload: str, raw: bool) -> tuple[int, str]:
    t = TARGETS[target]
    headers = {"User-Agent": "MPG-Classroom/1.0"}
    try:
        if t["method"] == "GET":
            value = payload if raw else quote(payload, safe="")
            r = await client.get(f"{t['path']}?{t['param']}={value}", headers=headers)
        else:
            r = await client.post(t["path"], json={"title": "수업 챌린지", t["param"]: payload}, headers=headers)
    except httpx.HTTPError:
        return 599, ""
    return r.status_code, r.headers.get("x-request-id", "")


def is_blocked(status: int) -> bool:
    # 403 = 요청 차단, 400 = 파서 거부(검사 전 차단), 502 = 응답 검사 차단
    return status in (400, 403, 502)


# ───────────── 학생 ─────────────
class JoinIn(BaseModel):
    nick: str = PField(min_length=1, max_length=12)


class SubmitIn(BaseModel):
    attack: str = PField(pattern="^(login|script|command)$")
    disguises: list[str] = PField(default_factory=list, max_length=5)


def student_of(request: Request) -> Student:
    sid = request.cookies.get("mpg_class")
    s = st.students.get(sid or "")
    if not s:
        raise HTTPException(401, "join first")
    return s


@app.get("/")
async def student_page():
    return FileResponse(STATIC / "student.html")


@app.get("/static/{name}")
async def static(name: str):
    if name not in {"student.js", "presenter.js", "app.css"}:
        raise HTTPException(404)
    return FileResponse(STATIC / name)


@app.post("/api/join")
async def join(body: JoinIn, request: Request, response: Response):
    nick = " ".join(body.nick.split())[:12]
    if not nick:
        raise HTTPException(400, "닉네임을 입력하세요")
    async with lock:
        sid = request.cookies.get("mpg_class")
        if sid in st.students:
            st.students[sid].nick = nick
        else:
            sid = secrets.token_urlsafe(16)
            st.students[sid] = Student(sid, nick, time.time())
        st.version += 1
    response.set_cookie("mpg_class", sid, httponly=True, samesite="strict", max_age=6 * 3600)
    return {"nick": nick}


CARDS = {
    "attacks": [{"id": k, "label": v["label"], "desc": v["desc"]} for k, v in ATTACKS.items()],
    "disguises": [{"id": k, "label": v["label"], "blurb": v["blurb"]} for k, v in DISGUISES.items()],
}


def public_state(s: Student | None) -> dict:
    out = {"phase": st.phase, "version": st.version, "joined": s is not None,
           "nick": s.nick if s else None}
    if st.phase == "challenge" and s:
        out["cards"] = CARDS
        out["cracked"] = sorted(s.cracked)
        mine = [x for x in st.submissions if x.sid == s.sid][-8:]
        out["mine"] = [{"attack": ATTACKS[x.attack]["label"], "payload": x.payload, "blocked": x.blocked,
                        "disguises": [DISGUISES[d]["label"] for d in x.disguises]} for x in reversed(mine)]
    return out


@app.get("/api/state")
async def state(request: Request):
    s = st.students.get(request.cookies.get("mpg_class") or "")
    return public_state(s)


@app.post("/api/submit")
async def submit(body: SubmitIn, request: Request):
    s = student_of(request)
    if st.phase != "challenge":
        raise HTTPException(409, "지금은 챌린지 시간이 아닙니다")
    disguises = [d for d in DISGUISE_ORDER if d in body.disguises]
    now = time.time()
    if now - s.last_submit < SUBMIT_INTERVAL:
        raise HTTPException(429, "잠깐만요, 1.5초에 한 번씩 보낼 수 있어요")
    if len(st.submissions) >= MAX_SUBMISSIONS:
        raise HTTPException(429, "제출 한도에 도달했습니다")
    s.last_submit = now
    payload, raw = build_payload(body.attack, disguises)
    target = ATTACKS[body.attack]["target"]
    status, rid = await send_to_gateway(target, payload, raw)
    blocked = is_blocked(status)
    first_crack = False
    async with lock:
        if not blocked and body.attack not in s.cracked:
            s.cracked[body.attack] = now
            first_crack = True
        sub = Submission(len(st.submissions) + 1, s.sid, s.nick, body.attack, disguises, payload,
                         status, blocked, rid, now)
        st.submissions.append(sub)
        st.version += 1
    return {"blocked": blocked, "status": status, "payload": payload, "first_crack": first_crack,
            "cracked": sorted(s.cracked)}


# ───────────── 발표자 ─────────────
def require_presenter(request: Request) -> None:
    key = request.headers.get("x-presenter-key") or request.query_params.get("key") or ""
    if not hmac.compare_digest(key.encode(), PRESENTER_KEY.encode()):
        raise HTTPException(403, "presenter key required")


@app.get("/presenter")
async def presenter_page(request: Request):
    require_presenter(request)
    return FileResponse(STATIC / "presenter.html")


@app.get("/api/presenter/qr.svg")
async def qr(request: Request):
    require_presenter(request)
    import io

    import segno
    buf = io.BytesIO()
    segno.make(PUBLIC_URL, error="m").save(buf, kind="svg", scale=8, border=2, dark="#111", light="#fff")
    return Response(buf.getvalue(), media_type="image/svg+xml")


def leaderboard() -> list[dict]:
    # 점수 = 서로 다른 공격을 뚫은 수(최대 3). 동점이면 먼저 다 뚫은 사람이 위로.
    rows = [{"nick": s.nick, "cracked": len(s.cracked), "attacks": sorted(s.cracked),
             "last": max(s.cracked.values()) if s.cracked else 0.0}
            for s in st.students.values() if s.cracked]
    return sorted(rows, key=lambda e: (-e["cracked"], e["last"]))[:10]


def disguise_wins() -> list[dict]:
    # 통과한 제출에서 '핵심 변장'(그 공격을 뚫은 변장)이 무엇이었는지 센다.
    wins: dict[str, int] = {}
    for x in st.submissions:
        if not x.blocked:
            for d in x.disguises:
                wins[d] = wins.get(d, 0) + 1
    return [{"label": DISGUISES[d]["label"], "n": n}
            for d, n in sorted(wins.items(), key=lambda kv: -kv[1]) if d in DISGUISES][:5]


@app.get("/api/presenter/state")
async def presenter_state(request: Request):
    require_presenter(request)
    out = {"phase": st.phase, "url": PUBLIC_URL,
           "students": len(st.students), "version": st.version}
    subs = st.submissions
    # 공격별로 몇 명이 뚫었는지(처음 뚫은 요청 ID도 — 발표자가 로그로 넘어갈 수 있게)
    cracks = {}
    for a in ATTACKS:
        crackers = sorted((s for s in st.students.values() if a in s.cracked), key=lambda s: s.cracked[a])
        rid = next((x.request_id for x in subs if x.attack == a and not x.blocked), "")
        cracks[a] = {"label": ATTACKS[a]["label"], "count": len(crackers), "request_id": rid}
    out["challenge"] = {
        "total": len(subs), "blocked": sum(x.blocked for x in subs), "passed": sum(not x.blocked for x in subs),
        "cracks": cracks,
        "disguise_wins": disguise_wins(),
        "recent": [{"nick": x.nick, "attack": ATTACKS[x.attack]["label"], "payload": x.payload,
                    "blocked": x.blocked, "disguises": [DISGUISES[d]["label"] for d in x.disguises]}
                   for x in subs[-14:]][::-1],
        "leaderboard": leaderboard(),
    }
    return out


class PhaseIn(BaseModel):
    phase: str = PField(pattern="^(lobby|challenge|end)$")


@app.post("/api/presenter/phase")
async def set_phase(body: PhaseIn, request: Request):
    require_presenter(request)
    async with lock:
        st.phase = body.phase
        st.version += 1
    return {"phase": st.phase}


@app.post("/api/presenter/reset")
async def reset(request: Request):
    require_presenter(request)
    global st
    async with lock:
        st = State()
    return {"ok": True}


@app.get("/healthz")
async def healthz():
    return JSONResponse({"ok": True})
