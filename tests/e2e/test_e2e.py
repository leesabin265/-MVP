"""실제로 떠 있는 gateway·admin-api·PostgreSQL·Redis를 대상으로 한 종단 간 테스트.

MPG_E2E_GATEWAY / MPG_E2E_ADMIN 이 설정되어 있을 때만 실행한다(로컬 개발 서버 또는 docker compose).
"""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest

GW = os.environ.get("MPG_E2E_GATEWAY")
ADMIN = os.environ.get("MPG_E2E_ADMIN")
ADMIN_PW = os.environ.get("MPG_E2E_ADMIN_PASSWORD", "admin-password-123")
OP_PW = os.environ.get("MPG_E2E_OPERATOR_PASSWORD", "operator-pass-123")
VIEWER_PW = os.environ.get("MPG_E2E_VIEWER_PASSWORD", "viewer-pass-1234")
VERIFY = os.environ.get("MPG_E2E_VERIFY", "1") != "0"

pytestmark = pytest.mark.skipif(not (GW and ADMIN), reason="e2e 대상 서버가 설정되지 않음")

QNA = "UNION SELECT 문법이 헷갈려요. SELECT name FROM users UNION SELECT email FROM admins 이렇게 쓰면 되나요?"


class Admin:
    def __init__(self, login_id: str, password: str) -> None:
        self.c = httpx.Client(base_url=ADMIN, verify=VERIFY, timeout=30)
        r = self.c.post("/admin/api/auth/login", json={"login_id": login_id, "password": password})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        self.role = r.json()["role"]

    def get(self, path, **kw):
        return self.c.get("/admin/api" + path, **kw)

    def send(self, method, path, csrf=True, **kw):
        headers = kw.pop("headers", {})
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.c.request(method, "/admin/api" + path, headers=headers, **kw)


@pytest.fixture(scope="module")
def gw():
    return httpx.Client(base_url=GW, verify=VERIFY, timeout=15)


@pytest.fixture(scope="module")
def admin():
    return Admin("lee", ADMIN_PW)


@pytest.fixture(scope="module")
def op():
    return Admin("op1", OP_PW)


def wait_event(a: Admin, rid: str, timeout: float = 10.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r = a.get(f"/events/{rid}")
        if r.status_code == 200:
            return r.json()
        time.sleep(0.2)
    raise AssertionError(f"event {rid} not stored")


GATEWAYS = int(os.environ.get("MPG_E2E_GATEWAYS", "2"))


def wait_gateway_version(gw: httpx.Client, version: int, timeout: float = 10.0) -> float:
    """LB 뒤 게이트웨이 여러 대가 모두 새 버전이 될 때까지. 라운드로빈이라 연속 (대수×2)번 맞으면 전부 본 것이다."""
    t0, streak = time.time(), 0
    while time.time() - t0 < timeout:
        h = httpx.Client(base_url=GW, verify=VERIFY, timeout=5)  # 새 연결이어야 LB가 다른 복제본으로 보낸다
        ok = h.get("/__mpg/health").json().get("policy_version") == version
        h.close()
        streak = streak + 1 if ok else 0
        if streak >= GATEWAYS * 2:
            return time.time() - t0
        time.sleep(0.02)
    raise AssertionError(f"gateways did not all reach v{version}")


def active_version(a: Admin) -> int:
    return a.get("/policy/changes").json()["active_version"]


def test_scenario_a_blocked_and_logged(gw, admin):
    r = gw.get("/api/login?username=admin%2527%20OR%201%3D1--")
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "blocked" and "rule" not in r.text.lower()
    assert r.headers["x-request-id"] == body["request_id"]
    ev = wait_event(admin, body["request_id"])
    assert ev["risk_score"] == 10
    assert sorted(m["rule_id"] for m in ev["matches"]) == ["ENC-002", "SQLI-001", "SQLI-003"]
    assert ev["recomputed"]["steps"][1]["value"] == "admin' OR 1=1--"


def test_normal_request_passes_with_request_id(gw):
    r = gw.get("/api/products?id=1")
    assert r.status_code == 200
    assert uuid.UUID(r.headers["x-request-id"])


def test_scenario_b_false_positive_flow(gw, op):
    post = lambda: gw.post("/api/qna/posts", json={"title": "질문", "content": QNA})
    r = post()
    assert r.status_code == 403
    rid = r.json()["request_id"]
    ev = wait_event(op, rid)
    assert {m["rule_id"] for m in ev["matches"]} == {"SQLI-002", "SQLI-007"}

    fp = op.send("POST", f"/events/{rid}/false-positive")
    assert fp.status_code == 200, fp.text
    draft = fp.json()["draft"]
    assert (draft["rule_id"], draft["path"], draft["param"]) == ("SQLI-002", "/api/qna/posts", "content")

    t = op.send("POST", "/policy/test", json={})
    assert t.status_code == 200

    before = active_version(op)
    r = op.send("POST", "/exceptions?publish=true", json=draft)
    assert r.status_code == 201, r.text
    new_v = r.json()["version"]
    assert new_v == before + 1
    reload_s = wait_gateway_version(gw, new_v)
    assert reload_s < 3.0
    assert post().status_code == 201
    other = gw.post("/api/qna/posts", json={"title": QNA, "content": "x"})
    assert other.status_code == 403, "예외는 content 파라미터에만 적용되어야 한다"


def test_scenario_c_new_rule_detect_then_block(gw, op):
    rid = f"XSS-{900 + int(time.time()) % 99:03d}"
    r = op.send("POST", "/rules", json={
        "id": rid, "category": "XSS", "weight": 6, "keywords": ["mpgtest"],
        "pattern": r"<mpgtest\b", "description": "e2e 테스트 룰"})
    assert r.status_code == 201, r.text
    assert r.json()["rule"]["mode"] == "DETECT"
    v = op.send("POST", "/policy/publish", json={"comment": "add " + rid}).json()["version"]
    wait_gateway_version(gw, v)
    resp = gw.post("/api/feedback", json={"message": "<mpgtest>"})
    assert resp.status_code == 200
    ev = wait_event(op, resp.headers["x-request-id"])
    assert ev["action"] == "DETECT_ONLY"

    assert op.send("PATCH", f"/rules/{rid}/mode", json={"mode": "BLOCK"}).status_code == 200
    v = op.send("POST", "/policy/publish", json={"comment": "block " + rid}).json()["version"]
    wait_gateway_version(gw, v)
    assert gw.post("/api/feedback", json={"message": "<mpgtest>"}).status_code == 403
    op.send("PATCH", f"/rules/{rid}", json={"enabled": False})
    v = op.send("POST", "/policy/publish", json={"comment": "cleanup"}).json()["version"]
    wait_gateway_version(gw, v)


def test_regression_gate_rejects_weakening(op):
    before = active_version(op)
    assert op.send("PATCH", "/rules/XSS-001", json={"enabled": False}).status_code == 200
    r = op.send("POST", "/policy/publish", json={"comment": "should fail"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "detection_rate_dropped" in detail["reasons"]
    assert detail["new_misses"]
    assert active_version(op) == before
    assert op.send("PATCH", "/rules/XSS-001", json={"enabled": True}).status_code == 200
    assert op.get("/policy/changes").json()["changes"] == []


def test_invalid_regex_rejected(op):
    r = op.send("POST", "/rules", json={"id": "XSS-899", "category": "XSS", "weight": 3,
                                        "pattern": r"(a+)\1"})
    assert r.status_code == 400
    assert "RE2" in r.json()["detail"]


def test_wildcard_exception_rejected(op):
    r = op.send("POST", "/exceptions", json={"rule_id": "SQLI-002", "path": "/api/*", "param": "content"})
    assert r.status_code == 400
    r = op.send("POST", "/exceptions", json={"rule_id": "SQLI-002", "path": "/x", "param": "c",
                                             "expires_in_days": 365})
    assert r.status_code == 422


def test_rbac_and_csrf(op):
    viewer = Admin("viewer1", VIEWER_PW)
    assert viewer.get("/events").status_code == 200
    assert viewer.send("POST", "/policy/publish", json={}).status_code == 403
    assert op.get("/audit").status_code == 403
    assert op.get("/policy/versions").status_code == 403
    assert op.send("POST", "/policy/test", csrf=False, json={"value": "x"}).status_code == 403
    anon = httpx.Client(base_url=ADMIN, verify=VERIFY)
    assert anon.get("/admin/api/events").status_code == 401


def test_session_cookie_flags():
    c = httpx.Client(base_url=ADMIN, verify=VERIFY)
    r = c.post("/admin/api/auth/login", json={"login_id": "viewer1", "password": VIEWER_PW})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/admin/api" in cookie


def test_path_threshold_flow(gw, admin, op):
    body = {"path": "/api/feedback", "param": "message", "threshold": 8, "reason": "피드백 본문 오탐 완화(e2e)"}
    assert op.send("POST", "/thresholds", json=body).status_code == 403, "OPERATOR는 임계값을 바꿀 수 없다"
    r = admin.send("POST", "/thresholds", json=body)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    assert admin.send("POST", "/thresholds", json=body).status_code == 409
    assert admin.send("POST", "/thresholds", json={**body, "threshold": 11}).status_code == 400

    t = admin.send("POST", "/policy/test", json={}).json()
    assert t["passed"], t
    pub = admin.send("POST", "/policy/publish", json={"comment": "feedback threshold"})
    assert pub.status_code == 201, pub.text
    wait_gateway_version(gw, pub.json()["version"])

    question = gw.post("/api/feedback", json={"message": "<script> 태그를 body 끝에 두는 이유?"})
    assert question.status_code == 200
    assert wait_event(admin, question.headers["x-request-id"])["action"] == "DETECT_ONLY"
    assert gw.post("/api/feedback", json={"message": "<script>alert(document.cookie)</script>"}).status_code == 403

    sb = admin.send("POST", "/policy/test", json={"value": "<script> 태그", "location": "json",
                                                  "path": "/api/feedback", "param": "message", "use": "active"}).json()
    assert (sb["threshold"], sb["detect_threshold"], sb["action"]) == (8, 6, "DETECT_ONLY")

    assert admin.send("DELETE", f"/thresholds/{tid}").status_code == 200
    v = admin.send("POST", "/policy/publish", json={"comment": "remove feedback threshold"}).json()["version"]
    wait_gateway_version(gw, v)
    assert gw.post("/api/feedback", json={"message": "<script> 태그를 body 끝에 두는 이유?"}).status_code == 403


def test_board_threshold_is_active(gw, admin):
    items = admin.get("/thresholds").json()["items"]
    assert any(t["path"] == "/api/qna/posts" and t["param"] == "content" and t["threshold"] == 8
               and t["published"] for t in items)
    r = gw.post("/api/qna/posts", json={"title": "질문", "content": "<script> 태그를 body 끝에 두는 이유?"})
    assert r.status_code == 201


EMBED = '<embed src="data:image/svg+xml;base64,PHN2Zz4=">'


def test_rule_override_flow(gw, admin, op):
    """경로별 룰 모드: 피드백 본문에서만 XSS-004(전역 탐지 모드)를 차단으로 올린다."""
    assert gw.post("/api/feedback", json={"message": EMBED}).status_code == 200  # 4+4, XSS-004는 탐지 모드
    body = {"path": "/api/feedback", "param": "message", "rule_id": "XSS-004", "mode": "BLOCK",
            "reason": "피드백 본문 외부 리소스 태그 차단(e2e)"}
    assert op.send("POST", "/rule-overrides", json=body).status_code == 403, "OPERATOR는 경로별 룰 모드를 바꿀 수 없다"
    r = admin.send("POST", "/rule-overrides", json=body)
    assert r.status_code == 201, r.text
    oid = r.json()["id"]
    assert admin.send("POST", "/rule-overrides", json=body).status_code == 409
    assert admin.send("POST", "/rule-overrides", json={**body, "rule_id": "XSS-001"}).status_code == 400  # 이미 BLOCK
    assert admin.send("POST", "/rule-overrides", json={**body, "path": "/api/*"}).status_code == 400
    changes = admin.get("/policy/changes").json()["changes"]
    assert {"type": "rule_override", "id": str(oid), "change": "added"} in changes
    pub = admin.send("POST", "/policy/publish", json={"comment": "feedback XSS-004 block"})
    assert pub.status_code == 201, pub.text
    wait_gateway_version(gw, pub.json()["version"])
    r = gw.post("/api/feedback", json={"message": EMBED})
    assert r.status_code == 403
    ev = wait_event(admin, r.json()["request_id"])
    assert any(m["rule_id"] == "XSS-004" and m["mode"] == "BLOCK" for m in ev["matches"])
    assert gw.post("/api/profile", data={"bio": EMBED}).status_code == 200  # 다른 경로는 전역 모드(탐지만)

    assert admin.send("DELETE", f"/rule-overrides/{oid}").status_code == 200
    v = admin.send("POST", "/policy/publish", json={"comment": "remove feedback override"}).json()["version"]
    wait_gateway_version(gw, v)
    assert gw.post("/api/feedback", json={"message": EMBED}).status_code == 200


def test_board_override_is_active(gw, admin):
    items = admin.get("/rule-overrides").json()
    assert any(o["path"] == "/api/qna/posts" and o["rule_id"] == "XSS-004" and o["published"] for o in items)
    assert gw.post("/api/qna/posts", json={"title": "q", "content": EMBED}).status_code == 403


def test_command_injection_and_path_traversal_blocked(gw, admin):
    r = gw.get("/api/tools/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd")
    assert r.status_code == 403
    rules = {m["rule_id"] for m in wait_event(admin, r.json()["request_id"])["matches"]}
    assert "CMD-001" in rules and "PATH-002" in rules
    assert gw.get("/api/download?file=..%2F..%2F..%2Fetc%2Fpasswd").status_code == 403
    assert gw.get("/api/download?file=php%3A%2F%2Ffilter%2Fresource%3Dindex.php").status_code == 403
    assert gw.get("/api/download?file=report_2026.pdf").status_code == 404  # 통과해서 백엔드가 404
    assert gw.get("/api/tools/ping?host=example.com").status_code == 404


def _multipart(filename: str, content: bytes, ctype: str) -> tuple[bytes, str]:
    b = "e2eBOUNDARY"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n").encode() + content + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"


def test_upload_inspection(gw, admin):
    png = b"\x89PNG\r\n\x1a\n" + bytes(64)
    body, ct = _multipart("사진.png", png, "image/png")
    assert gw.post("/api/upload", content=body, headers={"content-type": ct}).status_code == 200  # 한글 이름도 통과
    body, ct = _multipart("avatar.png", b"<?php system($_GET['c']); ?>", "image/png")
    r = gw.post("/api/upload", content=body, headers={"content-type": ct})
    assert r.status_code == 403
    rules = {m["rule_id"] for m in wait_event(admin, r.json()["request_id"])["matches"]}
    assert "FILE-003" in rules
    body, ct = _multipart("cat.jpg", b"\xff\xd8\xff\xe0" + bytes(32) + b"<?php eval($_POST[1]); ?>", "image/jpeg")
    assert gw.post("/api/upload", content=body, headers={"content-type": ct}).status_code == 403


def test_response_inspection(gw, admin):
    ok = gw.get("/api/demo/legacy-report?name=monthly")
    assert ok.status_code == 200
    r = gw.get("/api/demo/legacy-report?name=a%27")  # 요청은 통과, 백엔드가 DB 오류 원문을 500으로 내보냄
    assert r.status_code == 502 and r.json()["error"] == "response_blocked"
    assert "sql syntax" not in r.text.lower()
    ev = wait_event(admin, r.json()["request_id"])
    assert ev["action"] == "BLOCK" and ev["masked_sample"] == "[response redacted]"
    assert {m["rule_id"] for m in ev["matches"]} >= {"RESP-001", "RESP-007"}
    assert gw.get("/api/demo/file?kind=passwd").status_code == 502
    assert gw.get("/api/demo/file?kind=key").status_code == 502
    assert gw.get("/api/demo/file?kind=readme").status_code == 200


def test_multiple_gateways_report(admin):
    end = time.time() + 25
    while time.time() < end:
        gws = admin.get("/metrics/summary?period=1h").json()["gateways"]
        if len({g["instance"].split(":")[0] for g in gws}) >= GATEWAYS:
            return
        time.sleep(1)
    raise AssertionError(f"expected {GATEWAYS} gateway hosts, got {[g['instance'] for g in gws]}")


def test_rollback_and_audit(gw, admin):
    versions = admin.get("/policy/versions").json()
    current = versions[0]["version"]
    # 시드(최근 seed-rules 발행)로 되돌린다. v1로 되돌리면 이후 추가된 룰이 꺼진 채로 남는다.
    seed = max(v["version"] for v in versions if v["comment"].startswith("seed") and v["version"] < current)
    r = admin.send("POST", f"/policy/rollback/{seed}", json={"reason": "e2e"})
    assert r.status_code == 200, r.text
    v = r.json()["version"]
    assert v == current + 1
    wait_gateway_version(gw, v)
    assert gw.post("/api/qna/posts", json={"title": "q", "content": QNA}).status_code == 403
    actions = {a["action"] for a in admin.get("/audit?limit=200").json()}
    assert {"policy.rollback", "policy.publish", "exception.create", "event.view",
            "event.false_positive", "policy.publish_rejected", "threshold.create",
            "threshold.deactivate", "rule_override.create", "rule_override.deactivate"} <= actions


def test_summary(admin):
    s = admin.get("/metrics/summary?period=24h").json()
    assert s["counts"]["blocked"] >= 1
    assert s["active_policy"]["version"] >= 1
    assert s["gateways"], "gateway stats should be reported"
    assert s["regression"]["detection_rate"] >= 0.95


def test_login_lockout():
    name = "lockme"
    c = httpx.Client(base_url=ADMIN, verify=VERIFY)
    codes = [c.post("/admin/api/auth/login", json={"login_id": name, "password": "wrong-password"}).status_code
             for _ in range(6)]
    assert set(codes) <= {401, 423}
