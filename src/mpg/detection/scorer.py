from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .models import Action, Match, Mode, PathThreshold, Rule, RuleException, RuleKind


class RiskScorer:
    def __init__(self, rules: Iterable[Rule], exceptions: Iterable[RuleException], threshold: int,
                 path_thresholds: Iterable[PathThreshold] = ()) -> None:
        self.threshold = threshold
        self.exceptions = tuple(exceptions)
        # 구체적인 것부터: 정확한 경로 > 접두사, 파라미터 지정 > 경로 전체, 긴 경로 > 짧은 경로
        self.path_thresholds = tuple(sorted(path_thresholds, key=lambda t: t.specificity(), reverse=True))
        self._signal_rules = {
            r.signal: r for r in rules if r.kind is RuleKind.SIGNAL and r.enabled
        }

    def signal_matches(self, signals: set[str], field_ref: str) -> list[Match]:
        out = []
        for sig in sorted(signals):
            rule = self._signal_rules.get(sig)
            if rule:
                out.append(
                    Match(rule.id, rule.category, field_ref, rule.weight, rule.mode, sig)
                )
        return out

    def apply_exceptions(
        self, matches: list[Match], path: str, param: str, now: datetime
    ) -> list[Match]:
        if not self.exceptions:
            return matches
        out = []
        for m in matches:
            if any(e.applies(m.rule_id, path, param, now) for e in self.exceptions):
                m = Match(m.rule_id, m.category, m.field_ref, m.score, m.mode, m.evidence, True)
            out.append(m)
        return out

    @staticmethod
    def score(matches: list[Match]) -> tuple[int, int]:
        total = sum(m.score for m in matches if not m.excepted)
        block = sum(m.score for m in matches if not m.excepted and m.mode is Mode.BLOCK)
        return total, block

    def block_threshold(self, path: str, param: str) -> int:
        for t in self.path_thresholds:
            if t.matches(path, param):
                return t.threshold
        return self.threshold

    def decide(self, total: int, block: int, block_threshold: int | None = None) -> Action:
        """BLOCK 모드 점수 ≥ 차단 임계값 → BLOCK, 전체 점수 ≥ 탐지 임계값 → DETECT_ONLY.

        탐지 임계값 = min(전역, 차단 임계값): 경로 임계값을 올려도 탐지 기준은 그대로이고,
        내리면(더 엄격) 그 아래 점수도 기록된다.
        """
        bt = self.threshold if block_threshold is None else block_threshold
        if block >= bt:
            return Action.BLOCK
        if total >= min(self.threshold, bt):
            return Action.DETECT_ONLY
        return Action.ALLOW
