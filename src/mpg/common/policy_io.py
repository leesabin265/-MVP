"""정책 스냅샷 직렬화. policy_versions.snapshot(JSONB), gateway 로컬 캐시 파일, 회귀 테스트가 같은 형식을 쓴다."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mpg.detection.models import Policy, Rule, RuleException
from mpg.detection.rules import exception_from_dict, rule_from_dict


def rule_to_dict(r: Rule) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": r.id,
        "category": r.category.value,
        "kind": r.kind.value,
        "weight": r.weight,
        "mode": r.mode.value,
        "description": r.description,
        "enabled": r.enabled,
    }
    if r.pattern is not None:
        d["pattern"] = r.pattern
    if r.keywords:
        d["keywords"] = list(r.keywords)
    if r.signal:
        d["signal"] = r.signal
    if r.analyzer:
        d["analyzer"] = r.analyzer
    return d


def exception_to_dict(e: RuleException) -> dict[str, Any]:
    return {
        "id": e.id,
        "rule_id": e.rule_id,
        "path": e.path,
        "param": e.param,
        "expires_at": e.expires_at.isoformat(),
    }


def policy_to_snapshot(p: Policy) -> dict[str, Any]:
    return {
        "version": p.version,
        "threshold": p.threshold,
        "rules": [rule_to_dict(r) for r in p.rules],
        "exceptions": [exception_to_dict(e) for e in p.exceptions],
    }


def policy_from_snapshot(snap: dict[str, Any] | str, version: int | None = None) -> Policy:
    if isinstance(snap, str):
        snap = json.loads(snap)
    rules = tuple(rule_from_dict(d) for d in snap["rules"])
    excs = []
    for e in snap.get("exceptions") or ():
        e = dict(e)
        if e.get("id") is not None:
            e["id"] = str(e["id"])
        excs.append(exception_from_dict(e))
    return Policy(
        version=int(version if version is not None else snap.get("version", 0)),
        rules=rules,
        exceptions=tuple(excs),
        threshold=int(snap.get("threshold", 6)),
    )


def write_cache(path: Path, p: Policy) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy_to_snapshot(p), ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def read_cache(path: Path) -> Policy | None:
    if not path.exists():
        return None
    return policy_from_snapshot(path.read_text(encoding="utf-8"))


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
