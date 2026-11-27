from __future__ import annotations

from typing import Callable, Iterable

from .models import Category, Match, Rule, RuleKind
from .rules import compile_pattern

EVIDENCE_MAX = 64

SQL_BREAK_KEYWORDS = {
    "union", "select", "insert", "update", "delete", "drop", "exec", "execute",
    "having", "order", "group", "procedure", "into", "waitfor", "declare", "limit",
}
COMMENT_TOKENS = ("--", "#", "/*")


def _tokens(window: str, limit: int = 4) -> list[str]:
    out: list[str] = []
    i, n = 0, len(window)
    while i < n and len(out) < limit:
        ch = window[i]
        if ch.isspace():
            i += 1
            continue
        if window.startswith(COMMENT_TOKENS, i):
            out.append("c")
            break
        if ch in "'\"`":
            out.append("q")
            i += 1
            continue
        if ch.isalnum() or ch == "_":
            j = i
            while j < n and (window[j].isalnum() or window[j] == "_"):
                j += 1
            word = window[i:j]
            if word in SQL_BREAK_KEYWORDS:
                out.append("k")
            elif word.isdigit():
                out.append("n")
            else:
                out.append("w")
            i = j
            continue
        out.append(ch)
        i += 1
    return out


QUOTE = compile_pattern(r"['\"]")


def sqli_quote_break(text: str, max_quotes: int = 2048) -> str | None:
    """값 안에서 '문자열을 여는' 따옴표(같은 종류의 홀수 번째) 뒤에 SQL 키워드·주석·세미콜론이 오는지 본다.

    공격자가 넣는 첫 따옴표는 애플리케이션 쿼리의 문자열을 닫지만, 값만 놓고 보면 '여는' 위치다.
    닫는 따옴표('fine' 의 뒤쪽)나 단어 안 아포스트로피(It's, O'Brien)는 후보에서 뺀다.
    """
    open_quote: dict[str, bool] = {"'": False, '"': False}
    for seen, m in enumerate(QUOTE.finditer(text)):
        if seen >= max_quotes:
            return None
        i = m.start()
        q = text[i]
        prev = text[i - 1] if i > 0 else " "
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if prev.isalpha() and nxt.isalpha():
            continue
        if open_quote[q]:
            open_quote[q] = False
            continue
        open_quote[q] = True
        toks = _tokens(text[i + 1 : i + 48])
        while toks and toks[0] == ")":
            toks.pop(0)
        if not toks:
            continue
        head = toks[0]
        if head == "k" and len(toks) > 1 and toks[1] == "q":
            continue
        if head in ("c", ";") or head == "k":
            return text[max(0, i - 8) : i + 24]
    return None


ANALYZERS: dict[str, Callable[[str], str | None]] = {
    "sqli_quote_break": sqli_quote_break,
}


class CategoryDetector:
    category: Category

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._regex = {}
        self._analyzer = {}
        for r in rules:
            if r.category is not self.category or not r.enabled:
                continue
            if r.kind is RuleKind.REGEX:
                self._regex[r.id] = (r, compile_pattern(r.pattern))
            elif r.kind is RuleKind.ANALYZER:
                self._analyzer[r.id] = (r, ANALYZERS[r.analyzer])

    def detect(self, text: str, candidates: set[str], field_ref: str) -> list[Match]:
        matches: list[Match] = []
        for rid in sorted(candidates):
            if rid in self._regex:
                rule, rx = self._regex[rid]
                m = rx.search(text)
                if m:
                    matches.append(_match(rule, field_ref, m.group(0)))
            elif rid in self._analyzer:
                rule, fn = self._analyzer[rid]
                ev = fn(text)
                if ev is not None:
                    matches.append(_match(rule, field_ref, ev))
        return matches


class SqliDetector(CategoryDetector):
    category = Category.SQLI


class XssDetector(CategoryDetector):
    category = Category.XSS


class ScriptDetector(CategoryDetector):
    category = Category.SCRIPT


class CommandDetector(CategoryDetector):
    category = Category.COMMAND


class PathDetector(CategoryDetector):
    category = Category.PATH


class ResponseDetector(CategoryDetector):
    """백엔드 응답 본문 검사(정보 유출). 요청 파이프라인에서는 쓰지 않는다."""
    category = Category.RESPONSE


def _match(rule: Rule, field_ref: str, evidence: str) -> Match:
    return Match(
        rule_id=rule.id,
        category=rule.category,
        field_ref=field_ref,
        score=rule.weight,
        mode=rule.mode,
        evidence=evidence[:EVIDENCE_MAX],
    )
