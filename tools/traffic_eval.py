"""실제 운영 트래픽으로 다시 재기(오프라인, 게이트웨이와 같은 판정 코드).

    # nginx/Apache combined 로그(메서드·URI·Referer·User-Agent만 있음 — 본문은 없다)
    python tools/traffic_eval.py --format combined /var/log/nginx/access.log --out report.json --review review.jsonl

    # JSONL 캡처: 한 줄에 {"method","uri","headers":{...},"body" 또는 "body_b64","label"?}
    python tools/traffic_eval.py --format jsonl capture.jsonl --out report.json

운영 트래픽은 정답(공격/정상)이 없다. 그래서
  1) 판정 분포·많이 걸린 룰·경로를 내고,
  2) 차단·기록된 요청을 --review 파일로 뽑아(민감 값 마스킹) 사람이 'label' 을 달게 하고,
  3) label 이 달린 줄이 있으면(attack|normal) 탐지율·오탐률을 그 표본으로 계산한다.
라벨을 단 review 파일을 다시 --format jsonl 로 넣으면 2)→3)이 이어진다.
원본 로그에는 개인정보가 있을 수 있다. 보고서와 review 파일에는 마스킹한 샘플만 남긴다.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterator

from mpg.common.masking import make_sample
from mpg.detection import DetectionPipeline, load_policy
from mpg.detection.models import Action
from mpg.gateway.extract import BadRequest, RawRequest, build_inspection

ROOT = Path(__file__).resolve().parents[1]
COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<uri>\S+)(?: HTTP/[\d.]+)?" \d{3} \S+'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')


def read_combined(path: Path) -> Iterator[tuple[RawRequest, str | None]]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = COMBINED.match(line)
            if not m:
                continue
            uri = m["uri"]
            p, _, qs = uri.partition("?")
            headers = []
            for name, key in (("Referer", "referer"), ("User-Agent", "ua")):
                v = m[key]
                if v and v != "-":
                    headers.append((name, v.replace('\\"', '"')))
            yield RawRequest(m["method"], p or "/", qs, headers, b""), None


def read_jsonl(path: Path) -> Iterator[tuple[RawRequest, str | None]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            uri = d.get("uri") or d.get("path") or "/"
            p, _, qs = uri.partition("?")
            headers = [(str(k), str(v)) for k, v in (d.get("headers") or {}).items()]
            if d.get("body_b64"):
                body = base64.b64decode(d["body_b64"])
            else:
                body = str(d.get("body") or "").encode("utf-8")
            label = d.get("label")
            yield RawRequest(str(d.get("method") or "GET").upper(), p, qs, headers, body), label


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="운영 트래픽 오프라인 재측정")
    ap.add_argument("input", type=Path)
    ap.add_argument("--format", choices=["combined", "jsonl"], required=True)
    ap.add_argument("--rules", type=Path, default=ROOT / "rules" / "rules.yaml")
    ap.add_argument("--out", type=Path, help="요약 JSON")
    ap.add_argument("--review", type=Path, help="차단·기록된 요청을 라벨링용 JSONL로 저장(마스킹)")
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args(argv)

    pipe = DetectionPipeline(load_policy(a.rules))
    reader = read_combined if a.format == "combined" else read_jsonl
    actions, rules, paths = Counter(), Counter(), Counter()
    labeled = Counter()
    total = 0
    review = a.review.open("w", encoding="utf-8", newline="\n") if a.review else None
    for raw, label in reader(a.input):
        total += 1
        try:
            v = pipe.inspect(build_inspection(raw))
            action = v.action.value
        except BadRequest:
            v, action = None, "REJECTED_400"
        actions[action] += 1
        if label in ("attack", "normal"):
            flagged = action != Action.ALLOW.value
            stopped = action in (Action.BLOCK.value, "REJECTED_400")
            labeled[(label, "flagged" if flagged else "allowed")] += 1
            labeled[(label, "stopped" if stopped else "passed")] += 1
        if v is None or v.action is Action.ALLOW:
            continue
        paths[raw.raw_path] += 1
        for m in v.matches:
            if not m.excepted:
                rules[m.rule_id] += 1
        if review:
            top = max(v.fields, key=lambda f: (f.block_score, f.score))
            ev = next((m.evidence for m in top.matches if not m.excepted), "")
            review.write(json.dumps({
                "method": raw.method, "uri": raw.raw_path, "action": action, "score": v.risk_score,
                "field": top.field.ref, "rules": sorted({m.rule_id for m in v.matches if not m.excepted}),
                "sample": make_sample(top.field.location.value, top.field.name, top.field.value, ev),
                "label": label or "",
            }, ensure_ascii=False) + "\n")
    if review:
        review.close()

    report = {"total": total, "actions": dict(actions),
              "flagged_rate": round((total - actions["ALLOW"]) / total, 5) if total else None,
              "top_rules": rules.most_common(a.top), "top_paths": paths.most_common(a.top)}
    att = labeled[("attack", "flagged")] + labeled[("attack", "allowed")]
    nor = labeled[("normal", "flagged")] + labeled[("normal", "allowed")]
    if att or nor:
        report["labeled"] = {
            "attack": att, "normal": nor,
            "detection_rate": round(labeled[("attack", "flagged")] / att, 4) if att else None,
            "block_rate": round(labeled[("attack", "stopped")] / att, 4) if att else None,
            "fp_rate": round(labeled[("normal", "flagged")] / nor, 4) if nor else None,
            "blocked_fp_rate": round(labeled[("normal", "stopped")] / nor, 4) if nor else None,
        }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if a.out:
        a.out.write_text(text, encoding="utf-8", newline="\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
