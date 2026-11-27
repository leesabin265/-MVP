"""외부 공개 데이터로 다시 재기: OWASP CRS 회귀 테스트(Apache-2.0)를 MPG 엔진에 넣어 본다.

    git clone --depth 1 https://github.com/coreruleset/coreruleset.git /tmp/crs
    python tools/crs_eval.py /tmp/crs --out docs/crs-eval.json

- 요청 테스트(930 LFI · 931 RFI · 932 RCE · 933 PHP · 934 일반 · 941 XSS · 942 SQLi · 944 Java)를
  게이트웨이와 같은 코드(build_inspection → DetectionPipeline)로 판정한다. HTTP 연결은 하지 않는다.
- expect_ids 가 있는 테스트 = 공격. CRS 룰의 paranoia level(PL)별로 나눠 센다. CRS 기본값은 PL1이고,
  PL2~4는 CRS도 오탐을 감수하고 켜는 약한 신호라 MPG가 못 잡아도 이상하지 않다.
- no_expect_ids 만 있는 테스트 = '그 룰이 걸리면 안 되는' 사례. 정상 요청이 많지만 다른 룰이 잡아야 하는 공격도
  섞여 있어 오탐률로 쓰면 안 된다. 참고 수치로만 낸다.
- 응답 테스트(950~956 정보 유출)는 본문을 inspect_response 에 넣는다(200·500 두 경우).
MPG 룰은 이 데이터로 튜닝하지 않았다(측정 전용).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

from mpg.detection import DetectionPipeline, load_policy
from mpg.detection.models import Action
from mpg.gateway.extract import BadRequest, RawRequest, build_inspection

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {"930": "LFI", "931": "RFI", "932": "RCE", "933": "PHP", "934": "GENERIC", "941": "XSS",
            "942": "SQLI", "944": "JAVA"}
RESPONSE_FAMILIES = {"950": "LEAK", "951": "LEAK-SQL", "952": "LEAK-JAVA", "953": "LEAK-PHP",
                     "954": "LEAK-IIS", "955": "WEBSHELL", "956": "LEAK-RUBY"}


def paranoia_levels(crs: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for conf in (crs / "rules").glob("*.conf"):
        for block in re.split(r"\n(?=Sec(?:Rule|Action) )", conf.read_text(encoding="utf-8", errors="replace")):
            ids = re.findall(r"\bid:(\d{6})", block)
            pl = re.search(r"paranoia-level/(\d)", block)
            for i in ids:
                out.setdefault(i, int(pl.group(1)) if pl else 1)
    return out


def raw_request(inp: dict) -> RawRequest | None:
    if "encoded_request" in inp:
        return None
    uri = str(inp.get("uri") or "/")
    path, _, qs = uri.partition("?")
    headers = [(str(k), str(v)) for k, v in (inp.get("headers") or {}).items()]
    data = inp.get("data")
    if isinstance(data, list):
        data = "\r\n".join(str(x) for x in data)
    body = str(data).encode("utf-8", "surrogateescape") if data not in (None, "") else b""
    if body and not any(k.lower() == "content-type" for k, _ in headers):
        headers.append(("Content-Type", "application/x-www-form-urlencoded"))  # ftw 기본
    return RawRequest(str(inp.get("method") or "GET").upper(), path or "/", qs, headers, body)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("crs", type=Path)
    ap.add_argument("--rules", type=Path, default=ROOT / "rules" / "rules.yaml")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--examples", type=int, default=5, help="종류별로 남길 놓친 사례 수")
    a = ap.parse_args(argv)

    pipe = DetectionPipeline(load_policy(a.rules))
    pls = paranoia_levels(a.crs)
    tests_dir = a.crs / "tests" / "regression" / "tests"
    attack = defaultdict(lambda: defaultdict(lambda: {"total": 0, "blocked": 0, "detected": 0, "rejected_400": 0}))
    negative = defaultdict(lambda: {"total": 0, "blocked": 0, "detected": 0, "rejected_400": 0})
    misses = defaultdict(list)
    neg_examples = defaultdict(list)
    skipped = 0
    resp = defaultdict(lambda: {"total": 0, "detected": 0, "blocked_200": 0, "blocked_500": 0})
    resp_misses = defaultdict(list)

    for f in sorted(tests_dir.glob("*/*.yaml")):
        prefix = f.parent.name.split("-")[1]
        doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace")) or {}
        rule_id = str(doc.get("rule_id", f.stem))
        for t in doc.get("tests") or []:
            for st in t.get("stages") or []:
                inp, out = st.get("input") or {}, (st.get("output") or {}).get("log") or {}
                positive = bool(out.get("expect_ids"))
                if prefix in RESPONSE_FAMILIES:
                    if not positive:
                        continue
                    try:
                        body = json.loads(inp.get("data") or "{}").get("body", "")
                    except (ValueError, AttributeError):
                        skipped += 1
                        continue
                    fam = RESPONSE_FAMILIES[prefix]
                    v200 = pipe.inspect_response("/reflect", 200, str(body))
                    v500 = pipe.inspect_response("/reflect", 500, str(body))
                    r = resp[fam]
                    r["total"] += 1
                    r["detected"] += v200.action is not Action.ALLOW
                    r["blocked_200"] += v200.action is Action.BLOCK
                    r["blocked_500"] += v500.action is Action.BLOCK
                    if v200.action is Action.ALLOW and len(resp_misses[fam]) < a.examples:
                        resp_misses[fam].append({"rule": rule_id, "body": str(body)[:160]})
                    continue
                if prefix not in FAMILIES:
                    continue
                raw = raw_request(inp)
                if raw is None:
                    skipped += 1
                    continue
                try:
                    v = pipe.inspect(build_inspection(raw))
                    action = v.action
                except BadRequest:
                    action = None
                fam = FAMILIES[prefix]
                bucket = attack[fam][f"PL{pls.get(rule_id, 1)}"] if positive else negative[fam]
                bucket["total"] += 1
                if action is None:
                    bucket["rejected_400"] += 1
                else:
                    bucket["blocked"] += action is Action.BLOCK
                    bucket["detected"] += action is not Action.ALLOW
                sample = {"rule": rule_id, "pl": pls.get(rule_id, 1), "method": raw.method,
                          "uri": (raw.raw_path + ("?" + raw.query_string if raw.query_string else ""))[:160],
                          "body": raw.body[:160].decode("utf-8", "replace"),
                          "action": action.value if action else "400"}
                if positive and action is Action.ALLOW and len(misses[f"{fam}/PL{sample['pl']}"]) < a.examples:
                    misses[f"{fam}/PL{sample['pl']}"].append(sample)
                if not positive and action is Action.BLOCK and len(neg_examples[fam]) < a.examples:
                    neg_examples[fam].append(sample)

    def rate(n, d):
        return round(n / d, 4) if d else None

    report = {"source": "OWASP CRS regression tests (Apache-2.0)", "skipped_encoded_or_bad": skipped,
              "attack": {}, "negative": {}, "response": {}, "misses": misses, "negative_blocked_examples": neg_examples,
              "response_misses": resp_misses}
    print("| 분류 | PL | 공격 | 차단 | 탐지(차단+기록) | 400 거부 |")
    print("|---|---|---:|---:|---:|---:|")
    for fam in FAMILIES.values():
        for pl in sorted(attack[fam]):
            b = attack[fam][pl]
            stopped = b["blocked"] + b["rejected_400"]
            report["attack"].setdefault(fam, {})[pl] = {**b, "block_rate": rate(stopped, b["total"]),
                                                       "detect_rate": rate(b["detected"] + b["rejected_400"], b["total"])}
            print(f"| {fam} | {pl} | {b['total']} | {rate(stopped, b['total']):.1%} | "
                  f"{rate(b['detected'] + b['rejected_400'], b['total']):.1%} | {b['rejected_400']} |")
    print()
    print("| 분류 | no_expect_ids 사례 | 차단 | 기록 |")
    print("|---|---:|---:|---:|")
    for fam in FAMILIES.values():
        b = negative[fam]
        if not b["total"]:
            continue
        report["negative"][fam] = {**b, "block_rate": rate(b["blocked"], b["total"])}
        print(f"| {fam} | {b['total']} | {rate(b['blocked'], b['total']):.1%} | "
              f"{rate(b['detected'] - b['blocked'], b['total']):.1%} |")
    print()
    print("| 응답 분류 | 사례 | 탐지 | 차단(200) | 차단(500) |")
    print("|---|---:|---:|---:|---:|")
    for fam, b in resp.items():
        report["response"][fam] = {**b, "detect_rate": rate(b["detected"], b["total"])}
        print(f"| {fam} | {b['total']} | {rate(b['detected'], b['total']):.1%} | "
              f"{rate(b['blocked_200'], b['total']):.1%} | {rate(b['blocked_500'], b['total']):.1%} |")
    if a.out:
        a.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
