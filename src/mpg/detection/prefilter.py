from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import ahocorasick

from .models import Category, Rule, RuleKind


class KeywordPrefilter:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self._by_keyword: dict[str, set[str]] = defaultdict(set)
        self._always: set[str] = set()
        for rule in rules:
            if rule.kind is RuleKind.SIGNAL or not rule.enabled or rule.category is Category.RESPONSE:
                continue
            if not rule.keywords:
                self._always.add(rule.id)
            for kw in rule.keywords:
                self._by_keyword[kw].add(rule.id)
        self._automaton = ahocorasick.Automaton()
        for kw in self._by_keyword:
            self._automaton.add_word(kw, kw)
        if self._by_keyword:
            self._automaton.make_automaton()

    def candidates(self, text: str) -> set[str]:
        found = set(self._always)
        if not self._by_keyword or not text:
            return found
        for _, kw in self._automaton.iter(text):
            found |= self._by_keyword[kw]
        return found
