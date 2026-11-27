"""응답 검사(정보 유출)."""
import gzip
from dataclasses import replace

import pytest

from mpg.detection import Action, Mode, PathRuleOverride
from mpg.detection.pipeline import RESPONSE_PARAM, DetectionPipeline
from mpg.gateway.response_body import inspectable, read_prefix, replay, to_text

SQL_ERR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"


def ids(v):
    return sorted(m.rule_id for m in v.matches if not m.excepted)


@pytest.mark.parametrize("status,body,rule", [
    (500, f"<pre>{SQL_ERR}</pre>", "RESP-001"),
    (500, 'Traceback (most recent call last):\n  File "/app/x.py", line 3, in f\nKeyError', "RESP-002"),
    (200, "<pre>root:x:0:0:root:/root:/bin/bash\n</pre>", "RESP-003"),
    (200, "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...", "RESP-004"),
    (200, '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}', "RESP-005"),
])
def test_leaks_blocked(pipe, status, body, rule):
    v = pipe.inspect_response("/api/x", status, body)
    assert v.action is Action.BLOCK, ids(v)
    assert rule in ids(v)


def test_error_text_in_200_is_logged_not_blocked(pipe):
    """게시판 목록이 'SQL syntax 오류가 나요' 같은 글을 담아 돌려줘도 막지 않는다(5xx일 때만 차단 점수에 닿는다)."""
    v = pipe.inspect_response("/api/qna/posts", 200, '[{"content": "' + SQL_ERR + ' 오류가 나요"}]')
    assert v.action is Action.DETECT_ONLY and ids(v) == ["RESP-001"]
    v = pipe.inspect_response("/", 200, "<html><title>Index of /backup</title></html>")
    assert v.action is Action.DETECT_ONLY and ids(v) == ["RESP-006"]


@pytest.mark.parametrize("body", [
    '{"items": [{"id": 1, "name": "노트북"}]}',
    "<html><body>안녕하세요</body></html>",
    '{"error": "not found"}',
    "user root logged in at 10:00",
])
def test_ordinary_responses_pass(pipe, body):
    assert pipe.inspect_response("/api/x", 200, body).action is Action.ALLOW
    assert pipe.inspect_response("/api/x", 500, body).action is Action.ALLOW  # 5xx 신호만으로는 기록하지 않는다


def test_response_rules_never_run_on_requests(pipe):
    v = pipe.inspect_value("root:x:0:0:root", location="query", name="q")
    assert not any(m.rule_id.startswith("RESP") for m in v.matches)
    assert not any(c.startswith("RESP") for f in v.fields for c in f.candidates)


def test_path_override_on_response(policy):
    p = replace(policy, rule_overrides=policy.rule_overrides + (
        PathRuleOverride("/api/admin/export", "RESP-003", Mode.DETECT, param=RESPONSE_PARAM),))
    pipe = DetectionPipeline(p)
    v = pipe.inspect_response("/api/admin/export", 200, "root:x:0:0:root")
    assert v.action is Action.DETECT_ONLY
    assert pipe.inspect_response("/api/other", 200, "root:x:0:0:root").action is Action.BLOCK


def test_inspectable_and_decoding():
    h = {"content-type": "text/html; charset=utf-8"}
    assert inspectable("GET", 200, h, 1024)
    assert not inspectable("HEAD", 200, h, 1024)
    assert not inspectable("GET", 204, h, 1024)
    assert not inspectable("GET", 200, {"content-type": "image/png"}, 1024)
    assert not inspectable("GET", 200, {"content-type": "text/html", "content-encoding": "br"}, 1024)
    assert not inspectable("GET", 200, h, 0)
    assert inspectable("GET", 200, {"content-type": "application/problem+json"}, 1024)
    gz = gzip.compress("root:x:0:0:한글".encode())
    assert to_text(gz, {"content-type": "text/plain", "content-encoding": "gzip"}, 1024) == "root:x:0:0:한글"
    assert to_text("한글".encode("euc-kr"), {"content-type": "text/plain; charset=euc-kr"}, 1024) == "한글"


async def _chunks(*parts):
    for p in parts:
        yield p


@pytest.mark.asyncio
async def test_prefix_then_rest_is_streamed_unchanged():
    it = _chunks(b"a" * 10, b"b" * 10, b"c" * 10)
    prefix, complete = await read_prefix(it, 15)
    assert prefix == b"a" * 10 + b"b" * 10 and not complete
    out = b"".join([c async for c in replay(prefix, it)])
    assert out == b"a" * 10 + b"b" * 10 + b"c" * 10
    prefix, complete = await read_prefix(_chunks(b"xy"), 15)
    assert complete and b"".join([c async for c in replay(prefix, None)]) == b"xy"
