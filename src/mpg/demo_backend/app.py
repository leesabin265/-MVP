"""데모용 백엔드. 게이트웨이 뒤에 있는 '기존 서비스' 역할.

자체 방어(Prepared Statement, 출력 시 이스케이프)도 갖춘다 — 게이트웨이는 대체가 아니라 앞단의 한 겹이다.
"""
from __future__ import annotations

import asyncio
import html
import sqlite3
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, name TEXT);
    INSERT INTO users(username, password, name) VALUES ('admin','admin-pass','관리자'),('kim','kim-pass','김민수');
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
    INSERT INTO products(name, price) VALUES ('노트북',1200000),('무선 이어폰',150000),('키보드',89000);
    CREATE TABLE posts(id INTEGER PRIMARY KEY, title TEXT, content TEXT, created REAL);
    """
)
lock = asyncio.Lock()


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/api/login")
async def login(request: Request):
    ctype = request.headers.get("content-type", "")
    if "json" in ctype:
        d = await request.json()
    else:
        d = dict(await request.form())
    row = db.execute("SELECT id, name FROM users WHERE username=? AND password=?",
                     (str(d.get("username", "")), str(d.get("password", "")))).fetchone()
    if not row:
        return JSONResponse({"ok": False}, status_code=401)
    return {"ok": True, "user": {"id": row[0], "name": row[1]}}


@app.get("/api/login")
async def login_get(username: str = "", password: str = ""):
    row = db.execute("SELECT id FROM users WHERE username=? AND password=?", (username, password)).fetchone()
    return {"ok": bool(row)}


@app.get("/api/products")
async def products(id: str | None = None):
    if id is None:
        rows = db.execute("SELECT id, name, price FROM products").fetchall()
    else:
        rows = db.execute("SELECT id, name, price FROM products WHERE id=?", (id,)).fetchall()
    return [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]


@app.get("/api/search")
async def search(q: str = ""):
    rows = db.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return {"q": q, "results": [{"id": r[0], "name": r[1]} for r in rows]}


@app.get("/api/qna/posts")
async def list_posts():
    rows = db.execute("SELECT id, title, content FROM posts ORDER BY id DESC LIMIT 20").fetchall()
    return [{"id": r[0], "title": r[1], "content": r[2]} for r in rows]


@app.post("/api/qna/posts")
async def create_post(request: Request):
    d = await request.json()
    async with lock:
        cur = db.execute("INSERT INTO posts(title, content, created) VALUES (?,?,?)",
                         (str(d.get("title", "")), str(d.get("content", "")), time.time()))
    return JSONResponse({"id": cur.lastrowid}, status_code=201)


@app.get("/board", response_class=HTMLResponse)
async def board():
    rows = db.execute("SELECT title, content FROM posts ORDER BY id DESC LIMIT 20").fetchall()
    items = "".join(f"<li><b>{html.escape(t)}</b> {html.escape(c)}</li>" for t, c in rows)
    return f"<!doctype html><meta charset=utf-8><title>board</title><ul>{items}</ul>"


@app.post("/api/profile")
async def profile(bio: str = Form(""), display_name: str = Form("")):
    return {"bio": bio, "display_name": display_name}


@app.post("/api/feedback")
async def feedback(request: Request):
    d = await request.json()
    return {"received": len(str(d.get("message", "")))}


@app.post("/api/upload")
async def upload(request: Request):
    form = await request.form()
    return {"fields": sorted(form.keys())}


@app.get("/api/slow")
async def slow(seconds: float = 6.0):
    await asyncio.sleep(min(seconds, 30))
    return {"slept": seconds}


@app.get("/api/demo/legacy-report")
async def legacy_report(name: str = ""):
    """일부러 넣은 '오래된 취약 화면' 흉내: 입력이 이상하면 DB 오류 원문을 500으로 내보낸다(응답 검사 시연용)."""
    if "'" in name or '"' in name:
        return HTMLResponse(
            "<h1>500</h1><pre>You have an error in your SQL syntax; check the manual that corresponds to your "
            "MySQL server version for the right syntax to use near '" + html.escape(name[:40]) + "' at line 1</pre>",
            status_code=500)
    return {"report": name, "rows": 0}


DEMO_LEAKS = {
    "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    "trace": 'Traceback (most recent call last):\n  File "/app/report.py", line 12, in render\nKeyError: \'x\'\n',
}


@app.get("/api/demo/file")
async def demo_file(kind: str = "readme"):
    """경로 조작이 '성공한' 백엔드 흉내: 민감 파일 내용이 응답으로 새는 상황(응답 검사 시연용, 가짜 데이터)."""
    if kind in DEMO_LEAKS:
        return HTMLResponse(f"<pre>{DEMO_LEAKS[kind]}</pre>", status_code=500 if kind == "trace" else 200)
    return HTMLResponse("<pre>README: 데모 파일입니다</pre>")


@app.api_route("/echo", methods=["GET", "POST"])
async def echo(request: Request):
    body = await request.body()
    return {"method": request.method, "query": str(request.url.query),
            "headers": {k: v for k, v in request.headers.items() if k.startswith("x-")},
            "body_len": len(body)}
