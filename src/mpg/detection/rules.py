from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import re2
import yaml

from .models import Category, Mode, PathRuleOverride, PathThreshold, Policy, Rule, RuleException, RuleKind

THRESHOLD_MIN = 3
THRESHOLD_MAX_RAISE = 4

_OPTS = re2.Options()
_OPTS.log_errors = False
_OPTS.max_mem = 8 << 20

KNOWN_SIGNALS = {
    "excessive_encoding",
    "multi_encoding",
    "fullwidth",
    "comment_obfuscation",
    "control_char",
    "html_entity",
    "mixed_case",
    "duplicate_param",
    "js_escape",
    "newline_command",
    "upload_script_ext",
    "upload_double_ext",
    "upload_type_mismatch",
    "upload_embedded_code",
    "upload_executable",
    "response_5xx",
}


class RuleError(ValueError):
    pass


def compile_pattern(pattern: str):
    try:
        return re2.compile(pattern, _OPTS)
    except re2.error as e:
        msg = e.args[0].decode() if e.args and isinstance(e.args[0], bytes) else str(e)
        raise RuleError(f"RE2 compile failed: {msg}") from None


def rule_from_dict(d: dict[str, Any]) -> Rule:
    for key in ("id", "category", "weight", "mode"):
        if key not in d:
            raise RuleError(f"rule {d.get('id', '?')}: missing '{key}'")
    rid = str(d["id"])
    try:
        category = Category(d["category"])
        mode = Mode(d["mode"])
        kind = RuleKind(d.get("kind", "regex"))
    except ValueError as e:
        raise RuleError(f"rule {rid}: {e}") from None
    weight = int(d["weight"])
    if not 1 <= weight <= 10:
        raise RuleError(f"rule {rid}: weight must be 1..10")
    keywords = tuple(str(k).lower() for k in d.get("keywords") or ())
    rule = Rule(
        id=rid,
        category=category,
        kind=kind,
        weight=weight,
        mode=mode,
        description=str(d.get("description", "")),
        pattern=d.get("pattern"),
        keywords=keywords,
        signal=d.get("signal"),
        analyzer=d.get("analyzer"),
        enabled=bool(d.get("enabled", True)),
    )
    validate_rule(rule)
    return rule


def validate_rule(rule: Rule) -> None:
    if rule.kind is RuleKind.REGEX:
        if not rule.pattern:
            raise RuleError(f"rule {rule.id}: regex rule needs 'pattern'")
        compile_pattern(rule.pattern)
    elif rule.kind is RuleKind.SIGNAL:
        if rule.signal not in KNOWN_SIGNALS:
            raise RuleError(f"rule {rule.id}: unknown signal {rule.signal!r}")
    elif rule.kind is RuleKind.ANALYZER:
        from .detectors import ANALYZERS

        if rule.analyzer not in ANALYZERS:
            raise RuleError(f"rule {rule.id}: unknown analyzer {rule.analyzer!r}")


def load_rules(source: str | Path | Iterable[dict[str, Any]]) -> tuple[Rule, ...]:
    if isinstance(source, (str, Path)):
        data = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
        items = data["rules"] if isinstance(data, dict) else data
    else:
        items = list(source)
    rules = tuple(rule_from_dict(d) for d in items)
    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise RuleError(f"duplicate rule id {r.id}")
        seen.add(r.id)
    return rules


def exception_from_dict(d: dict[str, Any]) -> RuleException:
    for key in ("rule_id", "path", "param", "expires_at"):
        if not d.get(key):
            raise RuleError(f"exception: '{key}' is required")
    if any(ch in str(d["path"]) + str(d["param"]) for ch in "*?"):
        raise RuleError("exception: wildcards are not allowed")
    expires = d["expires_at"]
    if isinstance(expires, str):
        expires = datetime.fromisoformat(expires)
    if expires.tzinfo is None:
        raise RuleError("exception: expires_at must be timezone-aware")
    return RuleException(
        rule_id=d["rule_id"], path=d["path"], param=d["param"], expires_at=expires, id=d.get("id")
    )


def path_threshold_from_dict(d: dict[str, Any], global_threshold: int = 6) -> PathThreshold:
    path = str(d.get("path") or "")
    param = d.get("param") or None
    _check_scope("path threshold", path, param)
    try:
        t = int(d["threshold"])
    except (KeyError, TypeError, ValueError):
        raise RuleError("path threshold: 'threshold' must be an integer") from None
    hi = global_threshold + THRESHOLD_MAX_RAISE
    if not THRESHOLD_MIN <= t <= hi:
        raise RuleError(f"path threshold: threshold must be {THRESHOLD_MIN}..{hi}")
    prefix = bool(d.get("prefix", False))
    if prefix and len(path) < 2:
        raise RuleError("path threshold: prefix '/' would cover every path; change the global threshold instead")
    return PathThreshold(path=path, threshold=t, param=param, prefix=prefix,
                         id=str(d["id"]) if d.get("id") is not None else None)


def _check_scope(kind: str, path: str, param: str | None) -> None:
    if not path.startswith("/"):
        raise RuleError(f"{kind}: path must start with '/'")
    if any(ch in path + (param or "") for ch in "*?"):
        raise RuleError(f"{kind}: wildcards are not allowed (use prefix: true)")


def rule_override_from_dict(d: dict[str, Any], rules: Iterable[Rule] | None = None,
                            strict: bool = False) -> PathRuleOverride:
    """경로별 룰 모드. rules를 주면 룰이 있는지 검사한다.

    strict(새로 등록할 때만)는 전역 모드와 같아 바꾸는 게 없는 설정도 거부한다. 스냅샷을 읽을 때는 쓰지 않는다:
    나중에 룰의 전역 모드를 바꿨다고 이미 발행된 정책을 못 읽게 되면 게이트웨이 리로드가 실패한다.
    """
    path = str(d.get("path") or "")
    param = d.get("param") or None
    _check_scope("rule override", path, param)
    prefix = bool(d.get("prefix", False))
    if prefix and len(path) < 2:
        raise RuleError("rule override: prefix '/' would cover every path; change the rule's mode instead")
    rid = str(d.get("rule_id") or "")
    if not rid:
        raise RuleError("rule override: 'rule_id' is required")
    try:
        mode = Mode(d.get("mode"))
    except ValueError:
        raise RuleError("rule override: mode must be BLOCK or DETECT") from None
    if rules is not None:
        by_id = {r.id: r for r in rules}
        if rid not in by_id:
            raise RuleError(f"rule override: unknown rule {rid!r}")
        if strict and by_id[rid].mode is mode:
            raise RuleError(f"rule override: {rid} is already {mode.value} globally")
    return PathRuleOverride(path=path, rule_id=rid, mode=mode, param=param, prefix=prefix,
                            id=str(d["id"]) if d.get("id") is not None else None)


def load_policy(path: str | Path, version: int = 1, threshold: int = 6) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = load_rules(data["rules"])
    exceptions = tuple(exception_from_dict(e) for e in data.get("exceptions") or ())
    th = int(data.get("threshold", threshold))
    pts = tuple(path_threshold_from_dict(t, th) for t in data.get("path_thresholds") or ())
    ovs = tuple(rule_override_from_dict(o, rules) for o in data.get("rule_overrides") or ())
    return Policy(
        version=int(data.get("version", version)),
        rules=rules,
        exceptions=exceptions,
        threshold=th,
        path_thresholds=pts,
        rule_overrides=ovs,
    )
