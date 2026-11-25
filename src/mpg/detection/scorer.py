from __future__ import annotations

from datetime import datetime
from typing import Iterable

from .models import Action, Match, Mode, Rule, RuleException, RuleKind


class RiskScorer:
    def __init__(self, rules: Iterable[Rule], exceptions: Iterable[RuleException], threshold: int) -> None:
        self.threshold = threshold
        self.exceptions = tuple(exceptions)
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

    def decide(self, total: int, block: int) -> Action:
        if block >= self.threshold:
            return Action.BLOCK
        if total >= self.threshold:
            return Action.DETECT_ONLY
        return Action.ALLOW
