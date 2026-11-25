import time

import pytest

from mpg.detection import Field, InspectionRequest, Location

MB = 1 << 20


def _time(pipe, value, loc=Location.JSON, repeat=3):
    req = InspectionRequest("POST", "/x", (Field(loc, "body", value),))
    best = float("inf")
    for _ in range(repeat):
        t = time.perf_counter()
        pipe.inspect(req)
        best = min(best, time.perf_counter() - t)
    return best * 1000


@pytest.mark.parametrize("unit", ["a", "a" * 30 + "!", "(" * 10 + "a", "' or ", "<a onx", "union "])
def test_redos_style_1mb_meets_50ms_target(pipe, unit):
    value = (unit * (MB // len(unit) + 1))[:MB]
    ms = _time(pipe, value)
    assert ms < 100, f"{unit!r}: {ms:.0f} ms (목표 50 ms, CI 여유 2배)"


@pytest.mark.parametrize("unit", ["/*", "/**/a", "%25", "{{", "\\x41", "' ", "한글 본문 "])
def test_pathological_1mb_bounded(pipe, unit):
    value = (unit * (MB // len(unit) + 1))[:MB]
    ms = _time(pipe, value, loc=Location.QUERY, repeat=1)
    assert ms < 600, f"{unit!r}: {ms:.0f} ms"


def test_scaling_is_roughly_linear(pipe):
    small = _time(pipe, ("' or a <b on" * 20_000)[: MB // 8])
    big = _time(pipe, ("' or a <b on" * 160_000)[:MB])
    assert big < small * 8 * 3, (small, big)


def test_typical_request_is_fast(pipe):
    fields = (
        Field(Location.QUERY, "q", "%EB%85%B8%ED%8A%B8%EB%B6%81"),
        Field(Location.HEADER, "user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0"),
        Field(Location.JSON, "content", "SQL에서 JOIN과 서브쿼리 중 뭐가 빠른가요? " * 20),
    )
    req = InspectionRequest("POST", "/api/qna/posts", fields)
    for _ in range(50):
        pipe.inspect(req)
    n = 500
    t = time.perf_counter()
    for _ in range(n):
        pipe.inspect(req)
    per_ms = (time.perf_counter() - t) * 1000 / n
    assert per_ms < 2.0, per_ms
