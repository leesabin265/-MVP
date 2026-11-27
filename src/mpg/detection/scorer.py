from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import datetime
from typing import Iterable

from .models import Action, Match, Mode, PathRuleOverride, PathThreshold, Rule, RuleException, RuleKind


class RiskScorer:
    def __init__(self, rules: Iterable[Rule], exceptions: Iterable[RuleException], threshold: int,
                 path_thresholds: Iterable[PathThreshold] = (),
                 rule_overrides: Iterable[PathRuleOverride] = ()) -> None:
        self.threshold = threshold
        by_rule: dict[str, list[PathRuleOverride]] = defaultdict(list)
        for o in rule_overrides:
            by_rule[o.rule_id].append(o)
        self.rule_overrides = {rid: tuple(sorted(v, key=lambda o: o.specificity(), reverse=True))
                               for rid, v in by_rule.items()}
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

    def apply_overrides(self, matches: list[Match], path: str, param: str) -> list[Match]:
        """이 경로·파라미터에 맞는 룰 모드 설정이 있으면 매칭의 모드를 바꾼다(가장 구체적인 하나)."""
        if not self.rule_overrides:
            return matches
        out = []
        for m in matches:
            for o in self.rule_overrides.get(m.rule_id, ()):
                if o.matches(path, param):
                    if o.mode is not m.mode:
                        m = replace(m, mode=o.mode, overridden=True)
                    break
            out.append(m)
        return out

    def apply_exceptions(
        self, matches: list[Match], path: str, param: str, now: datetime
    ) -> list[Match]:
        if not self.exceptions:
            return matches
        out = []
        for m in matches:
            if any(e.applies(m.rule_id, path, param, now) for e in self.exceptions):
                m = replace(m, excepted=True)
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
