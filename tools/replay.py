"""데이터셋을 실제 HTTP 요청으로 게이트웨이에 보내 응답 코드를 오프라인 엔진 판정과 대조한다.

    python tools/replay.py https://localhost --insecure
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import httpx

from mpg.detection import DetectionPipeline, load_policy
from mpg.detection.models import Action
from mpg.detection.regress import Sample, load_samples

ROOT = Path(__file__).resolve().parents[1]


def build(s: Sample) -> dict | None:
    loc = s.location.value
    if loc == "query":
        return {"method": "GET", "url": f"{s.path}?{s.param}={s.payload}"}
    if loc == "form":
        return {"method": "POST", "url": s.path, "content": f"{s.param}={s.payload}".encode(),
                "headers": {"content-type": "application/x-www-form-urlencoded"}}
    if loc == "json":
        return {"method": "POST", "url": s.path, "json": {s.param: s.payload}}
    if loc == "header":
        try:
            s.payload.encode("latin-1")
        except UnicodeEncodeError:
            return None
        if any(c in s.payload for c in "\r\n\x00"):
            return None
        return {"method": "GET", "url": s.path, "headers": {s.param: s.payload}}
    return None


async def run(base: str, samples: list[Sample], verify: bool, concurrency: int) -> list[tuple[Sample, int | None]]:
    sem = asyncio.Semaphore(concurrency)
    out: list[tuple[Sample, int | None]] = []
    async with httpx.AsyncClient(base_url=base, verify=verify, timeout=15,
                                 limits=httpx.Limits(max_connections=concurrency)) as c:
        async def one(s: Sample):
            req = build(s)
            if req is None:
                out.append((s, None))
                return
            async with sem:
                r = await c.request(**req)
            out.append((s, r.status_code))

        await asyncio.gather(*(one(s) for s in samples))
    return out


def summarize(name: str, results, pipe: DetectionPipeline, attack: bool) -> dict:
    statuses = Counter()
    mismatch = []
    skipped = 0
    for s, code in results:
        if code is None:
            skipped += 1
            continue
        statuses[code] += 1
        expected = pipe.inspect(s.request()).action
        blocked = code == 403
        if blocked != (expected is Action.BLOCK):
            mismatch.append({"payload": s.payload[:120], "path": s.path, "location": s.location.value,
                             "status": code, "engine": expected.value})
    sent = sum(statuses.values())
    blocked = statuses.get(403, 0)
    return {
        "set": name, "sent": sent, "skipped": skipped, "status_counts": dict(sorted(statuses.items())),
        ("block_rate" if attack else "false_block_rate"): round(blocked / sent, 4) if sent else 0,
        "engine_mismatch": len(mismatch), "mismatch_examples": mismatch[:10],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--out")
    a = ap.parse_args()
    pipe = DetectionPipeline(load_policy(ROOT / "rules" / "rules.yaml"))
    rep = []
    for name, attack in (("attack", True), ("normal", False), ("normal_hard", False)):
        samples = load_samples(ROOT / "datasets" / f"{name}.jsonl")
        res = asyncio.run(run(a.base, samples, not a.insecure, a.concurrency))
        rep.append(summarize(name, res, pipe, attack))
    text = json.dumps(rep, ensure_ascii=False, indent=2)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0 if all(r["engine_mismatch"] == 0 for r in rep) else 1


if __name__ == "__main__":
    sys.exit(main())
