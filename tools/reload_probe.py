"""부하 중 정책 발행 → 게이트웨이 모든 워커가 새 버전을 쓰기까지 걸린 시간을 잰다(목표 3초 이내).

    python tools/reload_probe.py --admin https://localhost:9443 --gateway https://localhost --user lee
"""
from __future__ import annotations

import argparse
import json
import os
import time

import httpx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin", default="https://localhost:9443")
    ap.add_argument("--gateway", default="https://localhost")
    ap.add_argument("--user", default="lee")
    ap.add_argument("--password", default=os.environ.get("MPG_PROBE_PASSWORD", "admin-password-123"))
    ap.add_argument("--rule", default="SQLI-013")
    a = ap.parse_args()

    adm = httpx.Client(base_url=a.admin + "/admin/api", verify=False, timeout=30)
    gw = httpx.Client(base_url=a.gateway, verify=False, timeout=5)
    csrf = adm.post("/auth/login", json={"login_id": a.user, "password": a.password}).json()["csrf_token"]
    h = {"X-CSRF-Token": csrf}
    adm.patch(f"/rules/{a.rule}", headers=h,
              json={"description": f"긴 16진 리터럴(문자열 우회) [probe {int(time.time())}]"}).raise_for_status()
    t0 = time.time()
    r = adm.post("/policy/publish", headers=h, json={"comment": "reload probe under load"})
    r.raise_for_status()
    t_pub = time.time()
    version = r.json()["version"]

    first_seen = None
    consecutive = 0
    samples = []
    while time.time() - t_pub < 15:
        v = gw.get("/__mpg/health").json()["policy_version"]
        now = time.time()
        samples.append((round(now - t_pub, 3), v))
        if v == version:
            first_seen = first_seen or now
            consecutive += 1
            if consecutive >= 40:
                break
        else:
            consecutive = 0
        time.sleep(0.01)
    all_workers = max((t for t, v in samples if v != version), default=0.0)
    print(json.dumps({
        "version": version,
        "publish_api_seconds": round(t_pub - t0, 3),
        "first_worker_seconds": round(first_seen - t_pub, 3) if first_seen else None,
        "all_workers_seconds": round(all_workers, 3),
        "polls": len(samples),
    }, indent=2))


if __name__ == "__main__":
    main()
