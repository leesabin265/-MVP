import json

import pytest

from mpg.common.masking import make_sample
from mpg.detection.models import Location
from mpg.gateway.extract import BadRequest, RawRequest, build_inspection


def req(body=b"", ctype=None, qs="", path="/api/x", headers=()):
    h = list(headers)
    if ctype:
        h.append(("content-type", ctype))
    return build_inspection(RawRequest("POST", path, qs, h, body))


def by_ref(insp):
    return {f.ref: f.value for f in insp.fields}


def test_query_values_stay_raw_and_duplicates_detected():
    insp = req(qs="username=admin%2527&id=1&id=2")
    refs = by_ref(insp)
    assert refs["query.username"] == "admin%2527"
    assert insp.duplicate_params == frozenset({"id"})
    assert refs["query.username#name"] == "username"


def test_json_values_and_keys_are_fields():
    body = json.dumps({"post": {"content": "hi", "tags": ["a", "<b>"]}, "n": 1}).encode()
    refs = by_ref(req(body, "application/json"))
    assert refs["json.post.content"] == "hi"
    assert refs["json.post.tags[1]"] == "<b>"
    assert refs["json.post#key"] == "post"
    assert "json.n" not in refs


def test_json_too_deep_or_broken_is_400():
    deep = ("[" * 40 + "]" * 40).encode()
    with pytest.raises(BadRequest):
        req(deep, "application/json")
    with pytest.raises(BadRequest):
        req(b'{"a":', "application/json")


def test_disguised_content_type_still_inspected():
    refs = by_ref(req(b'{"q":"<script>"}', "text/plain"))
    assert refs["json.q"] == "<script>"
    refs = by_ref(req(b"hello <script>", "application/octet-stream"))
    assert refs["body.body"] == "hello <script>"


def test_form_and_multipart():
    refs = by_ref(req(b"bio=a+b%3Cs&x=1", "application/x-www-form-urlencoded"))
    assert refs["form.bio"] == "a+b%3Cs"
    body = (b"--XX\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<svg onload=x>\r\n"
            b"--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\nBINARY\r\n--XX--\r\n")
    refs = by_ref(req(body, "multipart/form-data; boundary=XX"))
    assert refs["multipart.note"] == "<svg onload=x>"
    assert refs["multipart.f#filename"] == "a.php"
    assert "BINARY" not in refs.values()
    with pytest.raises(BadRequest):
        req(b"garbage", "multipart/form-data; boundary=XX")


def test_headers_and_cookies():
    insp = req(headers=[("User-Agent", "ua"), ("Referer", "r"), ("Cookie", "a=1; b=%3Cx"),
                        ("X-Other", "ignored")])
    refs = by_ref(insp)
    assert refs["header.user-agent"] == "ua" and refs["header.referer"] == "r"
    assert refs["cookie.b"] == "%3Cx"
    assert not any("x-other" in k for k in refs)


def test_path_is_decoded_for_exception_matching():
    insp = req(path="/api/qna/%70osts")
    assert insp.path == "/api/qna/posts"
    assert by_ref(insp)["path.path"] == "/api/qna/%70osts"


def test_masking():
    assert make_sample("query", "password", "x' or 1=1") == "[redacted]"
    assert make_sample("cookie", "sid", "abc") == "[redacted]"
    s = make_sample("json", "content", "mail me at kim@example.com or 010-1234-5678 <script>")
    assert "example.com" not in s and "1234" not in s and "<script>" in s
    long = "가나다 " * 250 + "<script>alert(1)</script>" + " 라마바" * 250
    s = make_sample("json", "c", long, "<script>alert(1)</script>")
    assert len(s) == 256 and "<script>" in s
