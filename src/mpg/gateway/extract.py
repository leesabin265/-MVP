"""HTTP 요청 → 검사 대상 필드. 값은 가능한 한 '전송된 그대로(raw)' 넘겨 Normalizer가 디코딩 횟수를 셀 수 있게 한다."""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import unquote_plus

from mpg.detection.models import Field, InspectionRequest, Location

from .uploads import inspect_upload

INSPECTED_HEADERS = ("user-agent", "referer")
JSON_MAX_DEPTH = 32
MAX_FIELDS = 2000
# 요청 전체의 '%' 개수 상한. 퍼센트 디코딩은 순수 Python(urllib)이라 1 MB가 전부 이스케이프면 100~300 ms가 든다.
# 백엔드와 다른 디코더를 쓰면 그 차이가 우회 경로가 되므로 디코더는 바꾸지 않고 입력 크기를 제한한다.
# 10만 개 ≈ URL 인코딩된 한글 3만 3천 자(폼 본문 약 300 KB). 점수가 아니라 파서 제한이라 경로별 설정으로 풀 수 없다.
MAX_PCT_ESCAPES = 100_000


class BadRequest(Exception):
    pass


@dataclass(frozen=True)
class RawRequest:
    method: str
    raw_path: str
    query_string: str
    headers: list[tuple[str, str]]
    body: bytes


def _split_pairs(qs: str, location: Location, fields: list[Field], seen: dict[str, int]) -> None:
    if not qs:
        return
    for part in qs.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        dname = unquote_plus(name, errors="replace")
        if dname:
            fields.append(Field(location, f"{dname}#name", name))
        fields.append(Field(location, dname, value))
        seen[dname] = seen.get(dname, 0) + 1


def _parse_cookies(header: str, fields: list[Field]) -> None:
    for part in header.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep:
            fields.append(Field(Location.COOKIE, name.strip(), value.strip()))


def _json_fields(obj, path: str, depth: int, fields: list[Field]) -> None:
    if depth > JSON_MAX_DEPTH:
        raise BadRequest("json too deep")
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            child = f"{path}.{key}" if path else key
            fields.append(Field(Location.JSON, f"{child}#key", key))
            _json_fields(v, child, depth + 1, fields)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _json_fields(v, f"{path}[{i}]", depth + 1, fields)
    elif isinstance(obj, str):
        fields.append(Field(Location.JSON, path or "$", obj))


def _decode(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def _parse_json(body: bytes, fields: list[Field]) -> None:
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError) as e:
        raise BadRequest(f"invalid json: {type(e).__name__}") from None
    _json_fields(obj, "", 0, fields)


def _part_headers(head: bytes) -> dict[str, str]:
    """파트 헤더를 UTF-8로 읽는다. 브라우저는 한글 파일 이름을 인코딩 없이 UTF-8 그대로 보낸다
    (email 파서는 이때 Header 객체를 돌려줘 예외가 났고, Fail-Closed라 한글 이름 업로드가 전부 403이 됐다)."""
    out: dict[str, str] = {}
    for line in head.decode("utf-8", "replace").split("\r\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip():
            out.setdefault(name.strip().lower(), value.strip())
    return out


def _parse_multipart(body: bytes, content_type: str, fields: list[Field]) -> None:
    from python_multipart.multipart import parse_options_header

    _, params = parse_options_header(content_type)
    boundary = params.get(b"boundary")
    if not boundary:
        raise BadRequest("multipart without boundary")
    delim = b"--" + boundary
    if delim not in body:
        raise BadRequest("multipart boundary not found")
    parts = body.split(delim)
    if not parts[-1].startswith(b"--") and not parts[-1].strip() == b"":
        raise BadRequest("multipart not terminated")
    for part in parts[1:]:
        if part.startswith(b"--"):
            break
        part = part[2:] if part.startswith(b"\r\n") else part
        head, sep, content = part.partition(b"\r\n\r\n")
        if not sep:
            raise BadRequest("malformed multipart part")
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers = _part_headers(head)
        disp = headers.get("content-disposition", "")
        if not disp.lower().startswith("form-data"):
            raise BadRequest("multipart part without form-data disposition")
        _, dparams = parse_options_header(disp.encode())
        name = dparams.get(b"name", b"").decode("utf-8", "replace")
        filename = dparams.get(b"filename")
        if filename is not None:
            fname = filename.decode("utf-8", "replace")
            signals, text = inspect_upload(fname, headers.get("content-type", ""), content)
            fields.append(Field(Location.MULTIPART, f"{name}#filename", fname, frozenset(signals)))
            if text is not None:
                fields.append(Field(Location.MULTIPART, f"{name}#content", text))
            continue
        fields.append(Field(Location.MULTIPART, name, _decode(content)))


def build_inspection(req: RawRequest, max_pct_escapes: int = MAX_PCT_ESCAPES) -> InspectionRequest:
    fields: list[Field] = []
    seen: dict[str, int] = {}

    fields.append(Field(Location.PATH, "path", req.raw_path))
    _split_pairs(req.query_string, Location.QUERY, fields, seen)

    hdr = {}
    for k, v in req.headers:
        k = k.lower()
        hdr.setdefault(k, []).append(v)
    for name in INSPECTED_HEADERS:
        for v in hdr.get(name, ()):
            fields.append(Field(Location.HEADER, name, v))
    for c in hdr.get("cookie", ()):
        _parse_cookies(c, fields)

    if req.body:
        ctype = (hdr.get("content-type") or [""])[0]
        base = ctype.split(";")[0].strip().lower()
        if base == "application/x-www-form-urlencoded":
            _split_pairs(_decode(req.body), Location.FORM, fields, seen)
        elif base == "application/json" or base.endswith("+json"):
            _parse_json(req.body, fields)
        elif base == "multipart/form-data":
            _parse_multipart(req.body, ctype, fields)
        else:
            text = _decode(req.body)
            stripped = text.lstrip()
            if stripped[:1] in ("{", "["):
                try:
                    _parse_json(req.body, fields)
                except BadRequest:
                    fields.append(Field(Location.BODY, "body", text))
            else:
                fields.append(Field(Location.BODY, "body", text))

    if len(fields) > MAX_FIELDS:
        raise BadRequest("too many fields")
    if max_pct_escapes and sum(f.value.count("%") for f in fields) > max_pct_escapes:
        raise BadRequest("too many percent escapes")
    dups = frozenset(k for k, n in seen.items() if n > 1)
    path = req.raw_path.split("?", 1)[0]
    from urllib.parse import unquote

    return InspectionRequest(req.method, unquote(path), tuple(fields), dups)
