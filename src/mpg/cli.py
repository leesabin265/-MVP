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
    from mpg.detection.rules import load_rules

    data = yaml.safe_load(Path(a.file).read_text(encoding="utf-8"))
    items = data["rules"] if isinstance(data, dict) else data
    load_rules(items)
    s = _settings()
    pool = await _pool(s)
    r = await _redis(s)
    async with pool.acquire() as conn:
        async with conn.transaction():
            for d in items:
                await ps.upsert_rule(conn, d, "mpgctl")
            await audit(conn, "mpgctl", "rule.seed", a.file, None, {"count": len(items)})
    print(f"{len(items)} rules loaded")
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
