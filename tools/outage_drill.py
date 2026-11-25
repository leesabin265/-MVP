"""장애 격리 시연(기획서 4장 가용성·이벤트 유실 목표, 6-3 장애 대응 원칙).

1) admin-api + postgres 를 내린 채 공격·정상 셋 일부를 보낸다 → 차단 판정이 평소와 같아야 한다.
2) redis 를 내린 채 공격을 보낸다 → 차단은 그대로, 이벤트는 게이트웨이 버퍼에 쌓인다.
3) 모두 되살린 뒤, 1)·2)에서 받은 요청 ID가 전부 DB에 적재됐는지 대조한다(유실 0건).

    python tools/outage_drill.py --gateway https://localhost
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
import time
from pathlib import Path

import httpx

from mpg.detection import DetectionPipeline, load_policy
from mpg.detection.models import Action
from mpg.detection.regress import load_samples

ROOT = Path(__file__).resolve().parents[1]


def compose(*args: str) -> str:
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout


def psql(sql: str) -> str:
    return compose("exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "mpg", "-At", "-c", sql).strip()


def wait_healthy(service: str, timeout: float = 120) -> None:
    end = time.time() + timeout
    while time.time() < end:
        out = compose("ps", "--format", "json", service)
        if '"Health":"healthy"' in out.replace(" ", ""):
            return
        time.sleep(1)
    raise RuntimeError(f"{service} not healthy")


async def send(base: str, samples, limit: int = 32):
    from importlib import util

    spec = util.spec_from_file_location("replay", ROOT / "tools" / "replay.py")
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sem = asyncio.Semaphore(limit)
    out = []
    async with httpx.AsyncClient(base_url=base, verify=False, timeout=15) as c:
        async def one(s):
            req = mod.build(s)
            if req is None:
                return
            async with sem:
                r = await c.request(**req)
            out.append((s, r.status_code, r.headers.get("x-request-id")))
        await asyncio.gather(*(one(s) for s in samples))
    return out


def check(results, pipe) -> dict:
    agree = sum(1 for s, code, _ in results if (code == 403) == (pipe.inspect(s.request()).action is Action.BLOCK))
    return {"sent": len(results), "blocked": sum(1 for _, c, _ in results if c == 403),
            "agree_with_engine": agree, "errors_5xx": sum(1 for _, c, _ in results if c >= 500)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="https://localhost")
    ap.add_argument("--n", type=int, default=300)
    a = ap.parse_args()
    rnd = random.Random(7)
    attacks = rnd.sample(load_samples(ROOT / "datasets" / "attack.jsonl"), a.n)
    normals = rnd.sample(load_samples(ROOT / "datasets" / "normal.jsonl"), a.n)
    pipe = DetectionPipeline(load_policy(ROOT / "rules" / "rules.yaml"))
    report: dict = {}
    expected_ids: list[str] = []

    def health():
        return httpx.get(a.gateway + "/__mpg/health", verify=False, timeout=5).json()

    print("phase 1: admin-api + postgres down")
    compose("stop", "admin-api", "postgres")
    res_a = asyncio.run(send(a.gateway, attacks))
    res_n = asyncio.run(send(a.gateway, normals))
    report["db_down"] = {"attack": check(res_a, pipe), "normal": check(res_n, pipe), "gateway": health()}
    expected_ids += [rid for s, c, rid in res_a if pipe.inspect(s.request()).action is not Action.ALLOW]
    compose("start", "postgres")
    wait_healthy("postgres")
    compose("start", "admin-api")
    wait_healthy("admin-api")

    print("phase 2: redis down")
    compose("stop", "redis")
    res_r = asyncio.run(send(a.gateway, attacks[:200]))
    report["redis_down"] = {"attack": check(res_r, pipe), "gateway_during": health()}
    expected_ids += [rid for s, c, rid in res_r if pipe.inspect(s.request()).action is not Action.ALLOW]
    compose("start", "redis")
    wait_healthy("redis")

    print("phase 3: recovery, verify zero loss")
    deadline = time.time() + 120
    missing = expected_ids
    while time.time() < deadline:
        ids = ",".join(f"'{i}'" for i in expected_ids)
        found = int(psql(f"SELECT count(*) FROM security_events WHERE request_id IN ({ids})"))
        if found == len(set(expected_ids)):
            missing = []
            break
        time.sleep(2)
    else:
        ids_in_db = set(psql(f"SELECT request_id FROM security_events WHERE request_id IN ({ids})").split())
        missing = [i for i in expected_ids if i not in ids_in_db]
    report["recovery"] = {"expected_events": len(set(expected_ids)), "missing": len(missing),
                          "gateway_after": health()}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    out = ROOT / "docs" / "outage-drill.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    ok = (not missing and report["db_down"]["attack"]["agree_with_engine"] == report["db_down"]["attack"]["sent"]
          and report["redis_down"]["attack"]["agree_with_engine"] == report["redis_down"]["attack"]["sent"])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
