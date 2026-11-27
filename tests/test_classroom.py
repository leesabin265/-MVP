"""수업 참여 서비스: 단계 진행·투표·챌린지·심사·발표자 키(게이트웨이 호출은 가짜로 바꾼다)."""
from fastapi.testclient import TestClient

from mpg.classroom import app as classroom

KEY = {"X-Presenter-Key": classroom.PRESENTER_KEY}


async def fake_gateway(target, payload, raw):
    return (403 if "OR 1=1" in payload or "%2527" in payload else 200), "rid-1"


def test_full_flow(monkeypatch):
    monkeypatch.setattr(classroom, "send_to_gateway", fake_gateway)
    c = TestClient(classroom.app)
    assert c.post("/api/presenter/reset", headers=KEY).status_code == 200
    assert c.get("/api/presenter/state").status_code == 403  # 키 없으면 거부
    assert c.post("/api/vote", json={"choice": "block"}).status_code == 401  # 참여 전

    assert c.post("/api/join", json={"nick": "학생1"}).status_code == 200
    assert c.post("/api/vote", json={"choice": "block"}).status_code == 409  # 아직 대기 단계

    c.post("/api/presenter/phase", json={"phase": "vote", "q": 0}, headers=KEY)
    assert c.post("/api/vote", json={"choice": "block"}).status_code == 200
    r = c.post("/api/presenter/phase", json={"phase": "reveal", "q": 0}, headers=KEY).json()
    assert r["result"]["blocked"] is True
    s = c.get("/api/state").json()
    assert s["phase"] == "reveal" and s["my_vote"] == "block" and s["result"]["blocked"]

    c.post("/api/presenter/phase", json={"phase": "challenge"}, headers=KEY)
    assert c.post("/api/submit", json={"target": "login", "payload": "' OR 1=1--"}).json()["blocked"]
    classroom.st.students[next(iter(classroom.st.students))].last_submit = 0
    assert c.post("/api/submit", json={"target": "ping", "payload": "<b>x</b>"}).json()["blocked"] is False
    assert c.post("/api/submit", json={"target": "ping", "payload": "again"}).status_code == 429  # 연속 제출 제한
    assert c.post("/api/submit", json={"target": "nope", "payload": "x"}).status_code == 422

    ps = c.get("/api/presenter/state", headers=KEY).json()["challenge"]
    assert (ps["blocked"], ps["passed"]) == (1, 1)
    pid = ps["pending"][0]["id"]
    assert ps["pending"][0]["payload"] == "<b>x</b>"  # 원문 그대로(화면에선 textContent)
    assert c.post("/api/presenter/verdict", json={"id": pid, "verdict": "accepted"}, headers=KEY).status_code == 200
    lb = c.get("/api/presenter/state", headers=KEY).json()["challenge"]["leaderboard"]
    assert lb[0]["nick"] == "학생1" and lb[0]["accepted"] == 1
    assert "script-src 'self'" in c.get("/").headers["content-security-policy"]
