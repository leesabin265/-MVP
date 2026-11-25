#!/usr/bin/env python3
"""컨테이너 헬스체크: 주어진 URL이 2xx면 0. 자체 서명 인증서를 쓰는 내부 점검이라 검증을 끈다."""
import ssl
import sys
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with urllib.request.urlopen(sys.argv[1], timeout=3, context=ctx) as r:
        sys.exit(0 if 200 <= r.status < 300 else 1)
except Exception:
    sys.exit(1)
