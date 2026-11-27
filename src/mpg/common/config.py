from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path


def env(name: str, default: str | None = None) -> str | None:
    """NAME 또는 NAME_FILE(Docker secrets)에서 값을 읽는다. 파일이 우선."""
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)


def env_int(name: str, default: int) -> int:
    v = env(name)
    return int(v) if v not in (None, "") else default


def env_float(name: str, default: float) -> float:
    v = env(name)
    return float(v) if v not in (None, "") else default


def env_bool(name: str, default: bool) -> bool:
    v = env(name)
    if v in (None, ""):
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def parse_networks(spec: str | None) -> tuple[ipaddress._BaseNetwork, ...]:
    if not spec:
        return ()
    return tuple(ipaddress.ip_network(p.strip(), strict=False) for p in spec.split(",") if p.strip())


def ip_in(ip: str | None, nets) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


PRIVATE_DEFAULT = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"


def database_url(user_var: str, password_var: str) -> str:
    host = env("MPG_DB_HOST", "localhost")
    port = env("MPG_DB_PORT", "5432")
    name = env("MPG_DB_NAME", "mpg")
    user = env(user_var, "mpg_admin")
    pw = env(password_var, "")
    from urllib.parse import quote

    url = f"postgresql://{quote(user)}:{quote(pw)}@{host}:{port}/{name}"
    # 내부망 TLS: MPG_DB_SSLMODE=verify-full + MPG_DB_SSLROOTCERT=사설 CA. 비우면 평문(로컬 개발용).
    sslmode = env("MPG_DB_SSLMODE")
    if sslmode:
        url += f"?sslmode={quote(sslmode)}"
        root = env("MPG_DB_SSLROOTCERT")
        if root:
            url += f"&sslrootcert={quote(root)}"
    return url


def redis_url(user_var: str, password_var: str) -> str:
    url = env("MPG_REDIS_URL")
    if url:
        return url
    host = env("MPG_REDIS_HOST", "localhost")
    port = env("MPG_REDIS_PORT", "6379")
    user = env(user_var)
    pw = env(password_var)
    from urllib.parse import quote

    auth = ""
    if user and pw:
        auth = f"{quote(user)}:{quote(pw)}@"
    elif pw:
        auth = f":{quote(pw)}@"
    # 내부망 TLS: MPG_REDIS_TLS_CA=사설 CA 경로가 있으면 rediss:// + 인증서·호스트 이름 검증.
    ca = env("MPG_REDIS_TLS_CA")
    if ca:
        return (f"rediss://{auth}{host}:{port}/0?ssl_ca_certs={quote(ca)}"
                "&ssl_cert_reqs=required&ssl_check_hostname=true")
    return f"redis://{auth}{host}:{port}/0"


@lru_cache
def project_root() -> Path:
    return Path(env("MPG_HOME", str(Path(__file__).resolve().parents[3])))
