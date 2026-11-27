from __future__ import annotations

import time
from datetime import datetime

from .detectors import (
    CommandDetector,
    PathDetector,
    ResponseDetector,
    ScriptDetector,
    SqliDetector,
    XssDetector,
)
from .models import (
    Action,
    Category,
    Field,
    FieldResult,
    InspectionRequest,
    Location,
    Policy,
    RuleKind,
    Verdict,
    utcnow,
)
from .normalizer import Normalizer
from .prefilter import KeywordPrefilter
from .scorer import RiskScorer

RESPONSE_PARAM = "$response"
_ACTION_RANK = {Action.ALLOW: 0, Action.DETECT_ONLY: 1, Action.BLOCK: 2}


class DetectionPipeline:
    """정규화 → 프리필터 → 정밀 분석 → 점수 판정. 정책 하나에 대해 컴파일된 불변 객체."""

    def __init__(self, policy: Policy, normalizer: Normalizer | None = None) -> None:
        self.policy = policy
        self.normalizer = normalizer or Normalizer()
        self.prefilter = KeywordPrefilter(policy.rules)
        self.detectors = (
            SqliDetector(policy.rules),
            XssDetector(policy.rules),
            ScriptDetector(policy.rules),
            CommandDetector(policy.rules),
            PathDetector(policy.rules),
        )
        self.response_detector = ResponseDetector(policy.rules)
        self._response_rules = {r.id for r in policy.rules if r.category is Category.RESPONSE
                                and r.kind is not RuleKind.SIGNAL and r.enabled}
        self.scorer = RiskScorer(policy.rules, policy.exceptions, policy.threshold, policy.path_thresholds,
                                 policy.rule_overrides)

    def inspect(self, req: InspectionRequest, now: datetime | None = None) -> Verdict:
        t0 = time.perf_counter()
        now = now or utcnow()
        results: list[FieldResult] = []
        best_action = Action.ALLOW
        best_score = 0
        for f in req.fields:
            norm = self.normalizer.normalize(f.value, f.location)
            if f.name in req.duplicate_params:
                norm.signals.add("duplicate_param")
            if f.signals:
                norm.signals |= f.signals
            cands = self.prefilter.candidates(norm.text)
            matches = []
            for det in self.detectors:
                matches.extend(det.detect(norm.text, cands, f.ref))
            matches.extend(self.scorer.signal_matches(norm.signals, f.ref))
            matches.sort(key=lambda m: m.rule_id)
            matches = self.scorer.apply_overrides(matches, req.path, f.name)
            matches = self.scorer.apply_exceptions(matches, req.path, f.name, now)
            total, block = self.scorer.score(matches)
            bt = self.scorer.block_threshold(req.path, f.name)
            results.append(FieldResult(f, norm, tuple(sorted(cands)), matches, total, block, bt))
            action = self.scorer.decide(total, block, bt)
            if (_ACTION_RANK[action], total) > (_ACTION_RANK[best_action], best_score):
                best_action, best_score = action, total
        all_matches = [m for r in results for m in r.matches]
        return Verdict(
            action=best_action,
            risk_score=best_score,
            policy_version=self.policy.version,
            matches=all_matches,
            fields=results,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    def inspect_response(self, path: str, status: int, text: str, now: datetime | None = None) -> Verdict:
        """백엔드 응답 본문에서 정보 유출(DB 오류·스택 트레이스·시스템 파일·키)을 찾는다.

        RESP 룰만 쓴다. 응답은 공격자가 아니라 백엔드가 만든 것이라 URL·엔티티 디코딩 같은 정규화는 하지 않고
        소문자로만 맞춘다. 차단 기준은 요청과 같고(경로·'$response' 파라미터의 임계값·룰 모드·예외가 적용된다),
        룰이 하나라도 걸리면 차단이 아니어도 기록한다. 5xx 같은 신호만으로는 기록하지 않는다.
        """
        t0 = time.perf_counter()
        now = now or utcnow()
        f = Field(Location.RESPONSE, RESPONSE_PARAM, text)
        low = text.lower()
        matches = self.response_detector.detect(low, self._response_rules, f.ref)
        if not matches:
            return Verdict(Action.ALLOW, 0, self.policy.version, [], [], (time.perf_counter() - t0) * 1000)
        if status >= 500:
            matches.extend(self.scorer.signal_matches({"response_5xx"}, f.ref))
        matches.sort(key=lambda m: m.rule_id)
        matches = self.scorer.apply_overrides(matches, path, RESPONSE_PARAM)
        matches = self.scorer.apply_exceptions(matches, path, RESPONSE_PARAM, now)
        total, block = self.scorer.score(matches)
        bt = self.scorer.block_threshold(path, RESPONSE_PARAM)
        live = [m for m in matches if not m.excepted and m.rule_id in self._response_rules]
        action = Action.BLOCK if block >= bt else Action.DETECT_ONLY if live else Action.ALLOW
        return Verdict(action, total, self.policy.version, matches, [], (time.perf_counter() - t0) * 1000)

    def inspect_value(self, value: str, location="query", name: str = "q", path: str = "/") -> Verdict:
        from .models import Field, Location

        loc = Location(location) if isinstance(location, str) else location
        return self.inspect(InspectionRequest("GET", path, (Field(loc, name, value),)))
