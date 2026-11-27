from __future__ import annotations

import os
import time
from collections import deque

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

BUCKETS = (0.0005, 0.001, 0.002, 0.003, 0.005, 0.0075, 0.01, 0.015, 0.025, 0.05, 0.1, 0.25, 1.0)

REQUESTS = Counter("mpg_gateway_requests_total", "판정별 요청 수", ["action"])
RESPONSES = Counter("mpg_gateway_responses_total", "게이트웨이 응답 상태", ["status"])
INSPECTION = Histogram("mpg_gateway_inspection_seconds", "검사(파싱+탐지) 시간", buckets=BUCKETS)
OVERHEAD = Histogram("mpg_gateway_overhead_seconds", "게이트웨이 추가 지연(전체 - 백엔드)", buckets=BUCKETS)
UPSTREAM = Histogram("mpg_gateway_upstream_seconds", "백엔드 응답 시간", buckets=BUCKETS)
RULE_MATCHES = Counter("mpg_gateway_rule_matches_total", "판정된 요청의 룰 매칭", ["rule_id"])
POLICY_VERSION = Gauge("mpg_gateway_policy_version", "적용 중인 정책 버전", multiprocess_mode="max")
POLICY_RELOADS = Counter("mpg_gateway_policy_reloads_total", "정책 리로드", ["result"])
EVENTS_DROPPED = Counter("mpg_gateway_events_dropped_total", "버퍼 초과로 버린 이벤트")
EVENTS_SENT = Counter("mpg_gateway_events_sent_total", "Redis에 기록한 이벤트")
EVENT_BUFFER = Gauge("mpg_gateway_event_buffer", "전송 대기 이벤트 수", multiprocess_mode="livesum")
RESPONSE_INSPECTION = Histogram("mpg_gateway_response_inspection_seconds", "응답 검사 시간", buckets=BUCKETS)
RESPONSE_VERDICTS = Counter("mpg_gateway_response_verdicts_total", "응답 검사 판정", ["action"])
INTERNAL_ERRORS = Counter("mpg_gateway_internal_errors_total", "검사 중 예외(Fail-Closed)")


def render() -> tuple[bytes, str]:
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        from prometheus_client import multiprocess

        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return generate_latest(reg), CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST


class Window:
    """최근 N초 동안의 추가 지연·상태 코드. 대시보드용 p95를 Redis에 올리는 데 쓴다."""

    def __init__(self, seconds: int = 300, cap: int = 200_000) -> None:
        self.seconds = seconds
        self.samples: deque[tuple[float, float, int]] = deque(maxlen=cap)

    def add(self, overhead_ms: float, status: int) -> None:
        self.samples.append((time.time(), overhead_ms, status))

    def snapshot(self) -> dict:
        cutoff = time.time() - self.seconds
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()
        vals = sorted(s[1] for s in self.samples)
        n = len(vals)

        def pct(p: float) -> float | None:
            if not n:
                return None
            return round(vals[min(n - 1, int(p * n))], 3)

        errors = sum(1 for s in self.samples if s[2] >= 500)
        return {
            "count": n,
            "p50_ms": pct(0.50),
            "p95_ms": pct(0.95),
            "p99_ms": pct(0.99),
            "error_5xx_ratio": round(errors / n, 4) if n else 0.0,
        }
