"""mpgctl — admin-api 컨테이너 안에서 쓰는 운영 CLI."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path

import yaml


def _settings():
    from mpg.admin.app import Settings

    return Settings()


async def _pool(s):
    from mpg.admin.db import create_pool

    return await create_pool(s.db_url, max_size=2)


async def _redis(s):
    import redis.asyncio as aioredis

    return aioredis.from_url(s.redis_url)


async def cmd_migrate(a) -> int:
    from mpg.admin.db import migrate

    s = _settings()
    pool = await _pool(s)
    async with pool.acquire() as conn:
        await migrate(conn)
    await pool.close()
    print("schema up to date")
    return 0


async def cmd_create_admin(a) -> int:
    from mpg.admin.auth import ROLES, hash_password
    from mpg.admin.db import audit

    if a.role not in ROLES:
        print(f"role must be one of {sorted(ROLES)}", file=sys.stderr)
        return 2
    if sys.stdin.isatty():
        pw = getpass.getpass("password: ")
        if pw != getpass.getpass("again: "):
            print("passwords differ", file=sys.stderr)
            return 2
    else:
        pw = sys.stdin.readline().rstrip("\n")
    try:
        h = hash_password(pw)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    s = _settings()
    pool = await _pool(s)
    if a.if_missing:
        async with pool.acquire() as conn:
            exists = await conn.fetchval("SELECT 1 FROM admin_users WHERE login_id=$1", a.id)
        if exists:
            await pool.close()
            print(f"user {a.id} exists; unchanged")
            return 0
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO admin_users(login_id, password_hash, role) VALUES ($1,$2,$3)"
                " ON CONFLICT (login_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,"
                " role=EXCLUDED.role, failed_count=0, locked_until=NULL, disabled=false",
                a.id, h, a.role)
            await audit(conn, "mpgctl", "user.upsert", a.id, None, {"role": a.role})
    await pool.close()
    print(f"user {a.id} ({a.role}) ready")
    return 0


async def cmd_seed_rules(a) -> int:
    from mpg.admin import policy_service as ps
    from mpg.admin.db import audit
    from mpg.detection.rules import load_rules, path_threshold_from_dict

    data = yaml.safe_load(Path(a.file).read_text(encoding="utf-8"))
    items = data["rules"] if isinstance(data, dict) else data
    load_rules(items)
    global_t = int(data.get("threshold", 6)) if isinstance(data, dict) else 6
    pts = data.get("path_thresholds") or [] if isinstance(data, dict) else []
    for t in pts:
        path_threshold_from_dict(t, global_t)
    s = _settings()
    pool = await _pool(s)
    r = await _redis(s)
    async with pool.acquire() as conn:
        async with conn.transaction():
            for d in items:
                await ps.upsert_rule(conn, d, "mpgctl")
            await audit(conn, "mpgctl", "rule.seed", a.file, None, {"count": len(items)})
            seeded = await _seed_path_thresholds(conn, pts, audit)
    print(f"{len(items)} rules loaded, path thresholds: {seeded}")
    try:
        res = await ps.publish(pool, r, ps.Datasets.load(s.datasets_dir), "mpgctl",
                               comment=f"seed {Path(a.file).name}", force_initial=a.force)
        print(f"published v{res['version']}: detection={res['report']['detection_rate']:.2%}"
              f" fp={res['report']['fp_rate']:.2%}")
    except ps.PolicyError as e:
        if e.code == "no_changes":
            print("no changes to publish")
        else:
            print(json.dumps({"error": e.code, "detail": e.detail}, ensure_ascii=False, indent=2))
            return 1
    finally:
        await pool.close()
        await r.aclose()
    return 0


async def _seed_path_thresholds(conn, pts: list[dict], audit) -> str:
    """파일의 경로 임계값을 DB에 맞춘다. 같은 (경로, 파라미터, 접두사)가 같은 값으로 있으면 그대로 두고,
    값이 다르면 기존 것을 비활성화하고 새로 넣는다(이력 보존). 파일에 없는 DB 항목은 건드리지 않는다."""
    added = kept = replaced = 0
    for t in pts:
        param = t.get("param") or None
        prefix = bool(t.get("prefix", False))
        row = await conn.fetchrow(
            "SELECT id, threshold FROM path_thresholds WHERE active AND path=$1 AND coalesce(param,'')=$2"
            " AND prefix=$3", t["path"], param or "", prefix)
        if row and row["threshold"] == int(t["threshold"]):
            kept += 1
            continue
        if row:
            await conn.execute("UPDATE path_thresholds SET active=false WHERE id=$1", row["id"])
            replaced += 1
        else:
            added += 1
        tid = await conn.fetchval(
            "INSERT INTO path_thresholds(path, param, prefix, threshold, reason, created_by)"
            " VALUES ($1,$2,$3,$4,$5,'mpgctl') RETURNING id",
            t["path"], param, prefix, int(t["threshold"]), str(t.get("reason") or "seed"))
        await audit(conn, "mpgctl", "threshold.seed", str(tid),
                    {"id": row["id"], "threshold": row["threshold"]} if row else None,
                    {"path": t["path"], "param": param, "prefix": prefix, "threshold": int(t["threshold"])},
                    str(t.get("reason") or ""))
    return f"{added} added, {replaced} replaced, {kept} unchanged"


def cmd_regress(a) -> int:
    from mpg.detection.regress import main as regress_main

    argv = ["--rules", a.rules, "--attack", a.attack, "--normal", a.normal]
    if a.out:
        argv += ["--out", a.out]
    return regress_main(argv)


async def cmd_rollback(a) -> int:
    from mpg.admin import policy_service as ps

    s = _settings()
    pool = await _pool(s)
    r = await _redis(s)
    try:
        res = await ps.rollback(pool, r, ps.Datasets.load(s.datasets_dir), a.version, "mpgctl",
                                reason=a.reason or "emergency rollback via mpgctl")
    except ps.PolicyError as e:
        print(json.dumps({"error": e.code, "detail": e.detail}), file=sys.stderr)
        return 1
    finally:
        await pool.close()
        await r.aclose()
    print(f"rolled back: new v{res['version']} = v{res['restored_from']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mpgctl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="스키마 적용")
    p = sub.add_parser("create-admin", help="관리자 계정 생성(비밀번호는 표준 입력)")
    p.add_argument("--id", required=True)
    p.add_argument("--role", default="ADMIN")
    p.add_argument("--if-missing", action="store_true", help="이미 있으면 바꾸지 않음")
    p = sub.add_parser("seed-rules", help="룰 적재 + 발행")
    p.add_argument("file")
    p.add_argument("--force", action="store_true", help="회귀 게이트 무시(최초 적재용)")
    p = sub.add_parser("regress", help="회귀 테스트 단독 실행")
    p.add_argument("--rules", default="rules/rules.yaml")
    p.add_argument("--attack", default="datasets/attack.jsonl")
    p.add_argument("--normal", default="datasets/normal.jsonl")
    p.add_argument("--out")
    p = sub.add_parser("rollback", help="비상 롤백")
    p.add_argument("version", type=int)
    p.add_argument("--reason", default="")
    a = ap.parse_args(argv)
    if a.cmd == "regress":
        return cmd_regress(a)
    fn = {"migrate": cmd_migrate, "create-admin": cmd_create_admin, "seed-rules": cmd_seed_rules,
          "rollback": cmd_rollback}[a.cmd]
    return asyncio.run(fn(a))


if __name__ == "__main__":
    raise SystemExit(main())
