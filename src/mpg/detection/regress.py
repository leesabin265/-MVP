from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Action, Field, InspectionRequest, Location, Policy
from .pipeline import DetectionPipeline
from .rules import load_policy


@dataclass(frozen=True)
class Sample:
    path: str
    param: str
    payload: str
    location: Location = Location.QUERY
    variant: str = ""
    category: str = ""

    def request(self) -> InspectionRequest:
        return InspectionRequest("POST", self.path, (Field(self.location, self.param, self.payload),))


@dataclass
class TestReport:
    policy_version: int
    attack_total: int
    normal_total: int
    detected: int
    blocked: int
    false_positives: int
    blocked_fp: int = 0
    misses: list[dict] = field(default_factory=list)
    fp_list: list[dict] = field(default_factory=list)
    by_variant: dict[str, dict[str, int]] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def detection_rate(self) -> float:
        return self.detected / self.attack_total if self.attack_total else 0.0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.attack_total if self.attack_total else 0.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.normal_total if self.normal_total else 0.0

    @property
    def block_fp_rate(self) -> float:
        return self.blocked_fp / self.normal_total if self.normal_total else 0.0

    def to_dict(self) -> dict:
        return {
            "policy_version": self.policy_version,
            "attack_total": self.attack_total,
            "normal_total": self.normal_total,
            "detection_rate": round(self.detection_rate, 4),
            "block_rate": round(self.block_rate, 4),
            "fp_rate": round(self.fp_rate, 4),
            "block_fp_rate": round(self.block_fp_rate, 4),
            "blocked_fp": self.blocked_fp,
            "detected": self.detected,
            "blocked": self.blocked,
            "false_positives": self.false_positives,
            "by_variant": self.by_variant,
            "misses": self.misses,
            "false_positive_list": self.fp_list,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }

    def regressed_from(self, baseline: "TestReport") -> bool:
        return self.detection_rate < baseline.detection_rate or self.fp_rate > baseline.fp_rate

    @staticmethod
    def gate(candidate: dict, baseline: dict | None) -> list[str]:
        """발행 가능 여부. 탐지율이 떨어지거나 차단 오탐이 늘면 사유를 돌려준다(빈 목록이면 통과)."""
        if not baseline:
            return []
        reasons = []
        if candidate["detection_rate"] < baseline["detection_rate"]:
            reasons.append("detection_rate_dropped")
        if candidate.get("blocked_fp", 0) > baseline.get("blocked_fp", 0):
            reasons.append("blocked_false_positives_increased")
        return reasons


def load_samples(path: str | Path) -> list[Sample]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out.append(
                Sample(
                    path=d["path"],
                    param=d["param"],
                    payload=d["payload"],
                    location=Location(d.get("location", "query")),
                    variant=d.get("variant", ""),
                    category=d.get("category", ""),
                )
            )
    return out


class RegressionTester:
    def __init__(self, attacks: Iterable[Sample], normals: Iterable[Sample]) -> None:
        self.attacks = list(attacks)
        self.normals = list(normals)

    def run(self, policy: Policy) -> TestReport:
        t0 = time.perf_counter()
        pipe = DetectionPipeline(policy)
        rep = TestReport(policy.version, len(self.attacks), len(self.normals), 0, 0, 0)
        for s in self.attacks:
            v = pipe.inspect(s.request())
            bucket = rep.by_variant.setdefault(s.variant or "-", {"total": 0, "detected": 0})
            bucket["total"] += 1
            if v.action is not Action.ALLOW:
                rep.detected += 1
                bucket["detected"] += 1
                if v.action is Action.BLOCK:
                    rep.blocked += 1
            else:
                rep.misses.append(_summ(s, v))
        for s in self.normals:
            v = pipe.inspect(s.request())
            if v.action is not Action.ALLOW:
                rep.false_positives += 1
                if v.action is Action.BLOCK:
                    rep.blocked_fp += 1
                rep.fp_list.append(_summ(s, v))
        rep.elapsed_ms = (time.perf_counter() - t0) * 1000
        return rep


def _summ(s: Sample, v) -> dict:
    return {
        "path": s.path,
        "param": s.param,
        "variant": s.variant,
        "payload": s.payload[:200],
        "action": v.action.value,
        "score": v.risk_score,
        "rules": [m.rule_id for m in v.matches if not m.excepted],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="정책 회귀 테스트")
    ap.add_argument("--rules", default="rules/rules.yaml")
    ap.add_argument("--attack", default="datasets/attack.jsonl")
    ap.add_argument("--normal", default="datasets/normal.jsonl")
    ap.add_argument("--out", help="리포트 JSON 경로(기본: 표준 출력)")
    ap.add_argument("--min-detection", type=float, default=0.95)
    ap.add_argument("--max-fp", type=float, default=0.01)
    a = ap.parse_args(argv)
    rep = RegressionTester(load_samples(a.attack), load_samples(a.normal)).run(load_policy(a.rules))
    text = json.dumps(rep.to_dict(), ensure_ascii=False, indent=2)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    print(
        f"detection={rep.detection_rate:.2%} block={rep.block_rate:.2%} fp={rep.fp_rate:.2%} "
        f"({rep.attack_total} attack / {rep.normal_total} normal, {rep.elapsed_ms:.0f} ms)",
        file=sys.stderr,
    )
    return 0 if rep.detection_rate >= a.min_detection and rep.fp_rate <= a.max_fp else 1


if __name__ == "__main__":
    raise SystemExit(main())
