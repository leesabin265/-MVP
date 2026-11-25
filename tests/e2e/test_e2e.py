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


def wait_gateway_version(gw: httpx.Client, version: int, timeout: float = 10.0) -> float:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if gw.get("/__mpg/health").json().get("policy_version") == version:
            return time.time() - t0
        time.sleep(0.05)
    raise AssertionError(f"gateway did not reach v{version}")


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
    body = {"path": "/api/qna/posts", "param": "content", "threshold": 8, "reason": "기술 Q&A 게시판 오탐 완화"}
    assert op.send("POST", "/thresholds", json=body).status_code == 403, "OPERATOR는 임계값을 바꿀 수 없다"
    r = admin.send("POST", "/thresholds", json=body)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    assert admin.send("POST", "/thresholds", json=body).status_code == 409
    assert admin.send("POST", "/thresholds", json={**body, "threshold": 11}).status_code == 400

    t = admin.send("POST", "/policy/test", json={}).json()
    assert t["passed"] and any(w.startswith("block_rate_dropped") for w in t["warnings"])
    pub = admin.send("POST", "/policy/publish", json={"comment": "board threshold"})
    assert pub.status_code == 201, pub.text
    wait_gateway_version(gw, pub.json()["version"])

    question = gw.post("/api/qna/posts", json={"title": "질문", "content": "<script> 태그를 body 끝에 두는 이유?"})
    assert question.status_code == 201
    assert wait_event(admin, question.headers["x-request-id"])["action"] == "DETECT_ONLY"
    assert gw.post("/api/qna/posts", json={"title": "q", "content": "<script>alert(document.cookie)</script>"}).status_code == 403
    assert gw.post("/api/qna/posts", json={"title": "<script> 태그를 body 끝에 두는 이유?", "content": "x"}).status_code == 403

    sb = admin.send("POST", "/policy/test", json={"value": "<script> 태그", "location": "json",
                                                  "path": "/api/qna/posts", "param": "content", "use": "active"}).json()
    assert (sb["threshold"], sb["detect_threshold"], sb["action"]) == (8, 6, "DETECT_ONLY")

    assert admin.send("DELETE", f"/thresholds/{tid}").status_code == 200
    v = admin.send("POST", "/policy/publish", json={"comment": "remove board threshold"}).json()["version"]
    wait_gateway_version(gw, v)
    assert gw.post("/api/qna/posts", json={"title": "질문", "content": "<script> 태그를 body 끝에 두는 이유?"}).status_code == 403


def test_rollback_and_audit(gw, admin):
    versions = admin.get("/policy/versions").json()
    current = versions[0]["version"]
    r = admin.send("POST", "/policy/rollback/1", json={"reason": "e2e"})
    assert r.status_code == 200, r.text
    v = r.json()["version"]
    assert v == current + 1
    wait_gateway_version(gw, v)
    assert gw.post("/api/qna/posts", json={"title": "q", "content": QNA}).status_code == 403
    actions = {a["action"] for a in admin.get("/audit?limit=200").json()}
    assert {"policy.rollback", "policy.publish", "exception.create", "event.view",
            "event.false_positive", "policy.publish_rejected", "threshold.create",
            "threshold.deactivate"} <= actions


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
