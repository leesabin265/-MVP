from __future__ import annotations

import re

SAMPLE_MAX = 256
SENSITIVE_PARAM = re.compile(r"(pass(word|wd)?|pwd|token|secret|api[_-]?key|auth|session|credential|otp)", re.I)
REDACTED_LOCATIONS = {"cookie"}
EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(\.[\w-]{1,63})+")
PHONE = re.compile(r"(\+?\d{1,3}[-. ]?)?0?1[016789][-. ]?\d{3,4}[-. ]?\d{4}")
LONG_TOKEN = re.compile(r"\b(eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{5,}|[A-Za-z0-9_\-]{32,})\b")


def is_sensitive(location: str, name: str) -> bool:
    return location in REDACTED_LOCATIONS or bool(SENSITIVE_PARAM.search(name))


def mask_text(text: str) -> str:
    text = EMAIL.sub("***", text)
    text = PHONE.sub("***", text)
    return LONG_TOKEN.sub("***", text)


def make_sample(location: str, name: str, raw: str, evidence: str = "") -> str:
    """매칭 위치 주변 원문을 최대 256자로 자르고 개인정보 형태를 가린다."""
    if is_sensitive(location, name):
        return "[redacted]"
    if len(raw) <= SAMPLE_MAX:
        return mask_text(raw)
    start = 0
    probe = evidence.strip()[:12]
    if probe:
        idx = raw.lower().find(probe)
        if idx >= 0:
            start = max(0, idx - SAMPLE_MAX // 4)
    return mask_text(raw[start : start + SAMPLE_MAX])
