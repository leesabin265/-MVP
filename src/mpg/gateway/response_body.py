"""응답 검사용 본문 읽기. 텍스트 응답의 앞부분(기본 256 KB)만 메모리에 담아 검사하고, 나머지는 그대로 흘려보낸다."""
from __future__ import annotations

import zlib
from typing import AsyncIterator

TEXT_TYPES = ("text/", "application/json", "application/xml", "application/javascript",
              "application/problem+json", "application/x-www-form-urlencoded")
MAX_INFLATE = 4 << 20  # 압축 해제 상한(압축 폭탄 방지)


def inspectable(method: str, status: int, headers, limit: int) -> bool:
    if limit <= 0 or method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return False
    ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    if not (ctype.startswith(TEXT_TYPES) or ctype.endswith(("+json", "+xml"))):
        return False
    return headers.get("content-encoding", "identity").strip().lower() in ("identity", "", "gzip", "deflate")


async def read_prefix(it: AsyncIterator[bytes], limit: int) -> tuple[bytes, bool]:
    """(앞부분, 끝까지 읽었는지). limit를 넘으면 그 청크까지 담고 멈춘다."""
    buf = bytearray()
    async for chunk in it:
        buf += chunk
        if len(buf) > limit:
            return bytes(buf), False
    return bytes(buf), True


def to_text(raw: bytes, headers, limit: int) -> str:
    enc = headers.get("content-encoding", "identity").strip().lower()
    data = raw[:limit] if enc in ("identity", "") else raw
    if enc in ("gzip", "deflate"):
        wbits = 16 + zlib.MAX_WBITS if enc == "gzip" else zlib.MAX_WBITS
        try:
            data = zlib.decompressobj(wbits).decompress(data, MAX_INFLATE)
        except zlib.error:
            try:
                data = zlib.decompressobj(-zlib.MAX_WBITS).decompress(data, MAX_INFLATE)
            except zlib.error:
                return ""
    charset = "utf-8"
    for part in headers.get("content-type", "").split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            charset = v.strip('"').lower()
    try:
        return data[: limit * 4].decode(charset, errors="replace")
    except LookupError:
        return data[: limit * 4].decode("utf-8", errors="replace")


async def replay(prefix: bytes, rest: AsyncIterator[bytes] | None) -> AsyncIterator[bytes]:
    if prefix:
        yield prefix
    if rest is not None:
        async for chunk in rest:
            yield chunk
