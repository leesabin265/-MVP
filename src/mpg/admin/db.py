from __future__ import annotations

import json
from importlib import resources
from typing import Any

import asyncpg


async def _init_conn(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
    await conn.set_type_codec("json", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def create_pool(dsn: str, **kw) -> asyncpg.Pool:
    return await asyncpg.create_pool(dsn, init=_init_conn, min_size=kw.pop("min_size", 1),
                                     max_size=kw.pop("max_size", 10), command_timeout=30, **kw)


def schema_sql() -> str:
    return resources.files("mpg.admin").joinpath("schema.sql").read_text(encoding="utf-8")


async def migrate(conn: asyncpg.Connection) -> None:
    await conn.execute("SELECT pg_advisory_lock(424242)")
    try:
        await conn.execute(schema_sql())
    finally:
        await conn.execute("SELECT pg_advisory_unlock(424242)")


async def audit(conn, actor: str, action: str, target: str = "", before: Any = None,
                after: Any = None, reason: str = "", client_ip: str | None = None) -> None:
    await conn.execute(
        "INSERT INTO audit_log(actor, action, target, before, after, reason, client_ip)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7)",
        actor, action, target, before, after, reason, client_ip or None,
    )
