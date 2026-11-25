from __future__ import annotations

import time
from datetime import datetime

from .detectors import ScriptDetector, SqliDetector, XssDetector
from .models import (
    Action,
    FieldResult,
    InspectionRequest,
    Policy,
    Verdict,
    utcnow,
)
from .normalizer import Normalizer
from .prefilter import KeywordPrefilter
from .scorer import RiskScorer

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
        )
        self.scorer = RiskScorer(policy.rules, policy.exceptions, policy.threshold)

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
            cands = self.prefilter.candidates(norm.text)
            matches = []
            for det in self.detectors:
                matches.extend(det.detect(norm.text, cands, f.ref))
            matches.extend(self.scorer.signal_matches(norm.signals, f.ref))
            matches.sort(key=lambda m: m.rule_id)
            matches = self.scorer.apply_exceptions(matches, req.path, f.name, now)
            total, block = self.scorer.score(matches)
            results.append(FieldResult(f, norm, tuple(sorted(cands)), matches, total, block))
            action = self.scorer.decide(total, block)
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

    def inspect_value(self, value: str, location="query", name: str = "q", path: str = "/") -> Verdict:
        from .models import Field, Location

        loc = Location(location) if isinstance(location, str) else location
        return self.inspect(InspectionRequest("GET", path, (Field(loc, name, value),)))
