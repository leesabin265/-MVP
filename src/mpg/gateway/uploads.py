"""업로드 파일 내용 검사.

multipart 파일 파트마다
  - 텍스트 파일(UTF-8로 읽히고 NUL이 없음)은 내용을 검사 필드 `이름#content` 로 넘겨 XSS·스크립트·명령 룰이 그대로 본다.
  - 파일 자체에 대한 사실은 `이름#filename` 필드의 신호로 붙여 FILE 룰이 점수를 준다.
      upload_script_ext    서버에서 실행되는 확장자(.php .jsp .aspx .cgi .shtml .htaccess …)
      upload_double_ext    실행 확장자가 마지막이 아닌 곳에 숨음(shell.php.jpg)
      upload_type_mismatch 선언(Content-Type·확장자)은 이미지·문서인데 실제 바이트는 HTML·스크립트·실행 파일
      upload_embedded_code 이미지·PDF 같은 바이너리 안에 <?php · <script · <% 가 들어 있음(폴리글롯 웹셸)
      upload_executable    ELF·PE·Mach-O 실행 파일
판정은 바이트(매직 넘버)를 기준으로 한다. 파일 이름과 Content-Type 은 공격자가 마음대로 정한다.
"""
from __future__ import annotations

import re

SCRIPT_EXT = {
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht", "phar", "phps", "inc",
    "jsp", "jspx", "jspf", "jsw", "jsv", "asp", "aspx", "ashx", "asmx", "asa", "cer", "cshtml", "vbhtml",
    "cgi", "pl", "shtml", "shtm", "stm", "htaccess", "user.ini", "war", "jar",
}
IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "heic", "avif"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "hwp", "hwpx", "txt", "csv", "zip"}

MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"BM", "bmp"), (b"\x00\x00\x01\x00", "ico"),
    (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
    (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"\xcf\xfa\xed\xfe", "macho"), (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xca\xfe\xba\xbe", "macho"),
)
BINARY_KINDS = {"png", "jpeg", "gif", "pdf", "zip", "bmp", "ico", "tiff", "webp", "elf", "pe", "macho"}
EXECUTABLE_KINDS = {"elf", "pe", "macho"}
EMBEDDED_CODE = re.compile(rb"<\?php|<\?=|<script[\s>/]|<%[@=!\s]|<jsp:|#!/(usr/)?bin/", re.I)
ACTIVE_TEXT = re.compile(rb"^\s*(<\?php|<\?=|<%|<!doctype\s+html|<html|<script|<svg|#!/)", re.I)
CONTENT_LIMIT = 1 << 20


def sniff(content: bytes) -> str:
    for magic, kind in MAGIC:
        if content.startswith(magic):
            return kind
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "webp"
    if ACTIVE_TEXT.match(content[:512]):
        return "active-text"
    return "text" if _is_text(content) else "binary"


def _is_text(content: bytes) -> bool:
    if b"\x00" in content[:8192]:
        return False
    try:
        content[:CONTENT_LIMIT].decode("utf-8")
    except UnicodeDecodeError as e:
        # 잘린 끝의 멀티바이트 문자는 텍스트로 본다
        return e.start >= min(len(content), CONTENT_LIMIT) - 3
    return True


def extensions(filename: str) -> list[str]:
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].strip().strip(".").lower()
    if base == ".htaccess" or base == "htaccess":
        return ["htaccess"]
    if base.endswith("user.ini"):
        return ["user.ini"]
    parts = [p.strip() for p in base.split(".")[1:]]
    # 'shell.php%00.jpg'·'shell.php .jpg' 처럼 NUL·공백·세미콜론 뒤를 자르는 서버가 있다
    return [re.split(r"[\x00;\s]", p)[0] for p in parts if p]


def inspect_upload(filename: str, content_type: str, content: bytes) -> tuple[set[str], str | None]:
    """(filename 필드에 붙일 신호, 텍스트면 검사할 내용)."""
    signals: set[str] = set()
    exts = extensions(filename)
    last = exts[-1] if exts else ""
    if last in SCRIPT_EXT:
        signals.add("upload_script_ext")
    if any(e in SCRIPT_EXT for e in exts[:-1]):
        signals.add("upload_double_ext")

    kind = sniff(content)
    declared = (content_type or "").split(";")[0].strip().lower()
    claims_media = declared.startswith("image/") or declared == "application/pdf" or last in IMAGE_EXT | {"pdf"}
    if kind in EXECUTABLE_KINDS:
        signals.add("upload_executable")
        if claims_media or last in DOC_EXT:
            signals.add("upload_type_mismatch")
    elif kind == "active-text" and claims_media and declared != "image/svg+xml" and last != "svg":
        signals.add("upload_type_mismatch")
    elif kind in BINARY_KINDS and EMBEDDED_CODE.search(content[:CONTENT_LIMIT]):
        signals.add("upload_embedded_code")

    text = None
    if kind in ("text", "active-text"):
        text = content[:CONTENT_LIMIT].decode("utf-8", errors="replace")
    return signals, text
