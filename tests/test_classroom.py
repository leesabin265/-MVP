"""수업 참여 서비스: 단계 진행·투표·변장 챌린지·발표자 키(게이트웨이 호출은 가짜로 바꾼다)."""
from fastapi.testclient import TestClient

from mpg.classroom import app as classroom

KEY = {"X-Presenter-Key": classroom.PRESENTER_KEY}


def fake_gateway_factory():
    async def fake(target, payload, raw):
        # 'look'(스마트 따옴표·유니코드 괄호)·'glob'([x])이 들어간 변장만 통과로 흉내 낸다.
        passed = "’" in payload or "‹" in payload or "[" in payload
        return (200 if passed else 403), "rid-1"
    return fake


def test_build_payload_keys():
    # 각 공격의 '열쇠' 변장만 원본을 바꿔 통과 모양이 된다
    build = classroom.build_payload
    assert "’" in build("login", ["look"])[0]
    assert "[" in build("command", ["glob"])[0]
    assert build("login", [])[0] == "' OR 1=1--"
    # 순서 고정: 알 수 없는 값은 무시
    assert build("script", ["nope", "look"])[0].startswith("‹")


def test_full_flow(monkeypatch):
    monkeypatch.setattr(classroom, "send_to_gateway", fake_gateway_factory())
    c = TestClient(classroom.app)
    assert c.post("/api/presenter/reset", headers=KEY).status_code == 200
    assert c.get("/api/presenter/state").status_code == 403  # 키 없으면 거부
    assert c.post("/api/submit", json={"attack": "login"}).status_code == 401  # 참여 전

    assert c.post("/api/join", json={"nick": "학생1"}).status_code == 200
    assert c.post("/api/submit", json={"attack": "login"}).status_code == 409  # 아직 대기 단계
    assert c.post("/api/presenter/phase", json={"phase": "vote"}, headers=KEY).status_code == 422  # 투표 단계 없음

    # 변장 챌린지
    c.post("/api/presenter/phase", json={"phase": "challenge"}, headers=KEY)
    st = c.get("/api/state").json()
    assert len(st["cards"]["attacks"]) == 3 and len(st["cards"]["disguises"]) == 5
    # 변장 없이 보내면 막힌다
    blocked = c.post("/api/submit", json={"attack": "login", "disguises": []}).json()
    assert blocked["blocked"] is True and blocked["first_crack"] is False
    classroom.st.students[next(iter(classroom.st.students))].last_submit = 0
    # 'look' 변장으로 뚫는다
    win = c.post("/api/submit", json={"attack": "login", "disguises": ["look"]}).json()
    assert win["blocked"] is False and win["first_crack"] is True and win["cracked"] == ["login"]
    assert c.post("/api/submit", json={"attack": "login"}).status_code == 429  # 연속 제출 제한
    assert c.post("/api/submit", json={"attack": "nope"}).status_code == 422

    ch = c.get("/api/presenter/state", headers=KEY).json()["challenge"]
    assert ch["passed"] == 1 and ch["cracks"]["login"]["count"] == 1 and ch["cracks"]["script"]["count"] == 0
    assert ch["disguise_wins"][0]["n"] == 1
    lb = ch["leaderboard"]
    assert lb[0]["nick"] == "학생1" and lb[0]["cracked"] == 1
    assert "script-src 'self'" in c.get("/").headers["content-security-policy"]
