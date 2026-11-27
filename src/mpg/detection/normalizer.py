from __future__ import annotations

import html
import itertools
import re
import unicodedata
from urllib.parse import unquote, unquote_plus

import re2

from .models import PLUS_AS_SPACE, Location, NormalizationResult

_OPTS = re2.Options()
_OPTS.log_errors = False


def _c(pattern: str):
    return re2.compile(pattern, _OPTS)


PCT_ESCAPE = _c(r"%[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}")
# 고정 내부 패턴 중 치환(sub)이 필요한 것은 표준 re를 쓴다. google-re2 바인딩의 sub는 매치마다
# UTF-8 오프셋 변환을 Python에서 해서 매치가 많으면 느리다. 아래 패턴들은 모호한 반복이 없어 선형이다.
PCT_U = re.compile(r"%u([0-9a-fA-F]{4})")
ENTITY = _c(r"&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});?")
CONTROL_CHARS = {c: None for c in [*range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0x7F]}
MIXED_CASE_KEYWORD = _c(
    r"(?i)\b(select|union|insert|update|delete|drop|script|alert|onerror|onload|"
    r"javascript|iframe|svg|sleep|benchmark|exec)\b"
)
SPECIAL = set("<>'\"`;=()")
DISGUISE_SPECIAL = set("<>'\"`;=")
JS_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]{1,6}\})")
JS_ESCAPE_RUN = _c(r"(\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})){4,}")
# 셸에서 개행은 명령 구분자다. 정규화 마지막에 공백으로 합쳐지므로 그 전에 신호로 남긴다.
NEWLINE_COMMAND = _c(r"(?i)[\r\n][ \t]*(?:sudo[ \t]+)?(?:cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|"
                     r"python[23]?|perl|ping|nslookup|sleep|rm|chmod|base64|powershell)(?:[ \t;|&]|$)")


class Normalizer:
    def __init__(self, max_url_rounds: int = 3, max_entity_rounds: int = 2) -> None:
        self.max_url_rounds = max_url_rounds
        self.max_entity_rounds = max_entity_rounds

    def normalize(self, value: str, location: Location = Location.QUERY) -> NormalizationResult:
        steps: list[tuple[str, str]] = [("raw", value)]
        signals: set[str] = set()

        text, rounds = self._url_decode(value, location)
        if rounds:
            steps.append((f"url_decode x{rounds}", text))
        if rounds >= 2:
            signals.add("multi_encoding")
        if rounds == self.max_url_rounds and PCT_ESCAPE.search(text):
            signals.add("excessive_encoding")

        decoded = self._entity_decode(text)
        if decoded != text:
            if _gained_special(text, decoded):
                signals.add("html_entity")
            steps.append(("html_entity", decoded))
            text = decoded

        if JS_ESCAPE_RUN.search(text):
            signals.add("js_escape")
            text = JS_ESCAPE.sub(_js_unescape, text)
            steps.append(("js_escape", text))

        nfkc = unicodedata.normalize("NFKC", text)
        if nfkc != text:
            if _gained_special(text, nfkc, DISGUISE_SPECIAL):
                signals.add("fullwidth")
            steps.append(("nfkc", nfkc))
            text = nfkc

        if _has_mixed_case_keyword(text):
            signals.add("mixed_case")

        canonical = self._canonicalize(text, signals)
        if canonical != text:
            steps.append(("canonical", canonical))

        return NormalizationResult(
            raw=value, text=canonical, steps=steps, signals=signals, url_rounds=rounds
        )

    def _url_decode(self, value: str, location: Location) -> tuple[str, int]:
        text = value
        rounds = 0
        for i in range(self.max_url_rounds):
            # 유효한 이스케이프(%XX·%uXXXX)가 없으면 unquote 결과는 입력과 같다. 그 경우 순수 Python
            # unquote(1 MB의 '%'에 수백 ms)를 부르지 않고 끝낸다. 판정은 바뀌지 않는다(tests/test_normalizer.py).
            plus = i == 0 and location in PLUS_AS_SPACE and "+" in text
            if not plus and ("%" not in text or not PCT_ESCAPE.search(text)):
                break
            decoded = PCT_U.sub(_pct_u, text) if "%u" in text or "%U" in text else text
            if i == 0 and location in PLUS_AS_SPACE:
                decoded = unquote_plus(decoded, errors="replace")
            else:
                decoded = unquote(decoded, errors="replace")
            if decoded == text:
                break
            text = decoded
            rounds += 1
        return text, rounds

    def _entity_decode(self, text: str) -> str:
        for _ in range(self.max_entity_rounds):
            if "&" not in text or not ENTITY.search(text):
                break
            decoded = html.unescape(text)
            if decoded == text:
                break
            text = decoded
        return text

    def _canonicalize(self, text: str, signals: set[str]) -> str:
        if ("\n" in text or "\r" in text) and NEWLINE_COMMAND.search(text):
            signals.add("newline_command")
        stripped = text.translate(CONTROL_CHARS)
        if len(stripped) != len(text):
            signals.add("control_char")
            text = stripped
        if "/*" in text:
            text, obfuscated = strip_comments(text)
            if obfuscated:
                signals.add("comment_obfuscation")
        return " ".join(text.lower().split())


def strip_comments(text: str) -> tuple[str, bool]:
    """/* … */ 를 공백으로 바꾸고, MySQL 버전 주석 /*!50000 … */ 은 내용을 살린다.

    str.find 기반 단일 패스라 닫히지 않은 /* 가 많아도 O(n)이다.
    """
    out: list[str] = []
    obfuscated = False
    i, n = 0, len(text)
    while i < n:
        j = text.find("/*", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        if j + 2 < n and text[j + 2] == "!":
            obfuscated = True
            k = j + 3
            while k < n and text[k].isdigit():
                k += 1
            out.append(" ")
            i = k
            continue
        end = text.find("*/", j + 2)
        if end < 0:
            out.append(" ")
            break
        if j > 0 and end + 2 < n and _is_word(text[j - 1]) and _is_word(text[end + 2]):
            obfuscated = True
        out.append(" ")
        i = end + 2
    return "".join(out).replace("*/", " "), obfuscated


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _pct_u(m) -> str:
    return chr(int(m.group(1), 16))


def _js_unescape(m) -> str:
    body = m.group(1)
    hexdigits = body[1:].strip("{}")
    try:
        return chr(int(hexdigits, 16))
    except (ValueError, OverflowError):
        return m.group(0)


def _gained_special(before: str, after: str, chars: set[str] = SPECIAL) -> bool:
    for ch in chars:
        if after.count(ch) > before.count(ch):
            return True
    return False


def _has_mixed_case_keyword(text: str) -> bool:
    for m in itertools.islice(MIXED_CASE_KEYWORD.finditer(text), 256):
        word = m.group(0)
        if word.islower() or word.isupper() or word.istitle():
            continue
        return True
    return False
