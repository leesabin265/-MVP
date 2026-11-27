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

# 예측 투표 문제. 정답은 미리 적지 않는다 — '공개' 를 누를 때 실제 게이트웨이에 보내 그 자리에서 판정한다.
QUIZ = [
    {"id": "q1", "title": "로그인 아이디 칸에 이걸 넣으면?",
     "shown": "admin%2527%20OR%201%3D1--",
     "hint": "%25는 '%'를 한 번 더 인코딩한 것 — 두 번 풀어야 정체가 보입니다",
     "method": "GET", "target": "login", "raw": True,
     "explain": "URL 디코딩을 두 번 하면 admin' OR 1=1-- (항상 참 조건). 정규화가 풀어서 잡습니다."},
    {"id": "q2", "title": "기술 Q&A 게시판에 이런 질문을 올리면?",
     "shown": "Union SELECT 공격이 뭔가요?",
     "hint": "공격 문법을 '설명' 하는 정상 질문입니다",
     "method": "POST", "target": "board", "raw": False,
     "explain": "게시판 본문은 차단 기준을 8로 올려 두어 정상 질문은 통과시키고 기록만 합니다(오탐 줄이기)."},
    {"id": "q3", "title": "핑 도구의 호스트 칸에 이걸 넣으면?",
     "shown": "cat /etc/pa[s]swd",
     "hint": "[s] 는 셸에서 's' 한 글자와 같습니다(글롭)",
     "method": "GET", "target": "ping", "raw": False,
     "explain": "현재 룰은 이 우회 기법을 모릅니다 — 직접 만든 데이터에 없던 기법이라 놓친 사례입니다."},
]

TARGETS = {
    "login": {"label": "로그인 아이디", "method": "GET", "path": "/api/login", "param": "username"},
    "search": {"label": "상품 검색", "method": "GET", "path": "/api/search", "param": "q"},
    "board": {"label": "게시판 글", "method": "POST", "path": "/api/qna/posts", "param": "content"},
    "ping": {"label": "핑 도구 호스트", "method": "GET", "path": "/api/tools/ping", "param": "host"},
}


@dataclass
class Student:
    sid: str
    nick: str
    joined: float
    last_submit: float = 0.0


@dataclass
class Submission:
    id: int
    sid: str
    nick: str
    target: str
    payload: str
    status: int
    blocked: bool
    request_id: str
    ts: float
    verdict: str | None = None  # accepted | rejected


@dataclass
class State:
    phase: str = "lobby"  # lobby | vote | reveal | challenge | end
    q: int = 0
    students: dict[str, Student] = field(default_factory=dict)
    votes: dict[str, dict[str, str]] = field(default_factory=lambda: {q["id"]: {} for q in QUIZ})
    results: dict[str, dict] = field(default_factory=dict)
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


class VoteIn(BaseModel):
    choice: str = PField(pattern="^(block|pass)$")


class SubmitIn(BaseModel):
    target: str = PField(pattern="^(login|search|board|ping)$")
    payload: str = PField(min_length=1, max_length=MAX_PAYLOAD)
    raw: bool = False


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


def public_state(s: Student | None) -> dict:
    out = {"phase": st.phase, "version": st.version, "joined": s is not None,
           "nick": s.nick if s else None, "targets": {k: v["label"] for k, v in TARGETS.items()}}
    if st.phase in ("vote", "reveal"):
        q = QUIZ[st.q]
        out["question"] = {k: q[k] for k in ("id", "title", "shown", "hint")}
        out["my_vote"] = st.votes[q["id"]].get(s.sid) if s else None
        if st.phase == "reveal" and q["id"] in st.results:
            out["result"] = {**st.results[q["id"]], "explain": q["explain"]}
    if st.phase == "challenge" and s:
        mine = [x for x in st.submissions if x.sid == s.sid][-8:]
        out["mine"] = [{"target": TARGETS[x.target]["label"], "payload": x.payload, "blocked": x.blocked,
                        "status": x.status, "verdict": x.verdict} for x in reversed(mine)]
    return out


@app.get("/api/state")
async def state(request: Request):
    s = st.students.get(request.cookies.get("mpg_class") or "")
    return public_state(s)


@app.post("/api/vote")
async def vote(body: VoteIn, request: Request):
    s = student_of(request)
    if st.phase != "vote":
        raise HTTPException(409, "지금은 투표 시간이 아닙니다")
    async with lock:
        st.votes[QUIZ[st.q]["id"]][s.sid] = body.choice
        st.version += 1
    return {"ok": True}


@app.post("/api/submit")
async def submit(body: SubmitIn, request: Request):
    s = student_of(request)
    if st.phase != "challenge":
        raise HTTPException(409, "지금은 챌린지 시간이 아닙니다")
    now = time.time()
    if now - s.last_submit < SUBMIT_INTERVAL:
        raise HTTPException(429, "잠깐만요, 1.5초에 한 번씩 보낼 수 있어요")
    if len(st.submissions) >= MAX_SUBMISSIONS:
        raise HTTPException(429, "제출 한도에 도달했습니다")
    s.last_submit = now
    status, rid = await send_to_gateway(body.target, body.payload, body.raw)
    async with lock:
        sub = Submission(len(st.submissions) + 1, s.sid, s.nick, body.target, body.payload, status,
                         is_blocked(status), rid, now)
        st.submissions.append(sub)
        st.version += 1
    return {"blocked": sub.blocked, "status": status}


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
    score: dict[str, dict] = {}
    for x in st.submissions:
        if x.verdict == "accepted":
            e = score.setdefault(x.sid, {"nick": x.nick, "accepted": 0, "first": x.ts})
            e["accepted"] += 1
            e["first"] = min(e["first"], x.ts)
    return sorted(score.values(), key=lambda e: (-e["accepted"], e["first"]))[:10]


@app.get("/api/presenter/state")
async def presenter_state(request: Request):
    require_presenter(request)
    out = {"phase": st.phase, "q": st.q, "quiz_len": len(QUIZ), "url": PUBLIC_URL,
           "students": len(st.students), "version": st.version}
    if st.phase in ("vote", "reveal"):
        q = QUIZ[st.q]
        votes = list(st.votes[q["id"]].values())
        out["question"] = {k: q[k] for k in ("id", "title", "shown", "hint", "explain")}
        out["votes"] = {"block": votes.count("block"), "pass": votes.count("pass")}
        out["result"] = st.results.get(q["id"])
    subs = st.submissions
    out["challenge"] = {
        "total": len(subs), "blocked": sum(x.blocked for x in subs), "passed": sum(not x.blocked for x in subs),
        "pending": [{"id": x.id, "nick": x.nick, "target": TARGETS[x.target]["label"], "payload": x.payload,
                     "status": x.status, "request_id": x.request_id}
                    for x in subs if not x.blocked and x.verdict is None][-30:],
        "recent": [{"nick": x.nick, "target": TARGETS[x.target]["label"], "payload": x.payload,
                    "blocked": x.blocked, "verdict": x.verdict} for x in subs[-12:]][::-1],
        "leaderboard": leaderboard(),
    }
    return out


class PhaseIn(BaseModel):
    phase: str = PField(pattern="^(lobby|vote|reveal|challenge|end)$")
    q: int | None = PField(default=None, ge=0)


@app.post("/api/presenter/phase")
async def set_phase(body: PhaseIn, request: Request):
    require_presenter(request)
    if body.q is not None and body.q >= len(QUIZ):
        raise HTTPException(400, "no such question")
    if body.phase == "reveal":
        q = QUIZ[st.q if body.q is None else body.q]
        status, rid = await send_to_gateway(q["target"], q["shown"], q["raw"])
        st.results[q["id"]] = {"status": status, "blocked": is_blocked(status), "request_id": rid}
    async with lock:
        st.phase = body.phase
        if body.q is not None:
            st.q = body.q
        st.version += 1
    return {"phase": st.phase, "q": st.q, "result": st.results.get(QUIZ[st.q]["id"])}


class VerdictIn(BaseModel):
    id: int
    verdict: str = PField(pattern="^(accepted|rejected)$")


@app.post("/api/presenter/verdict")
async def set_verdict(body: VerdictIn, request: Request):
    require_presenter(request)
    async with lock:
        for x in st.submissions:
            if x.id == body.id and not x.blocked:
                x.verdict = body.verdict
                st.version += 1
                return {"ok": True}
    raise HTTPException(404, "not found")


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
