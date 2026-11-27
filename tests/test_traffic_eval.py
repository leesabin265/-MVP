"""tools/traffic_eval.py — 운영 트래픽 재측정 도구."""
import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import traffic_eval  # noqa: E402

COMBINED = (
    '10.0.0.1 - - [27/Nov/2026:10:00:00 +0900] "GET /api/products?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
    '10.0.0.2 - - [27/Nov/2026:10:00:01 +0900] "GET /api/login?username=admin%27%20OR%201%3D1-- HTTP/1.1" 403 40 '
    '"https://example.com/" "curl/8.0"\n'
    'garbage line\n'
)


def test_combined_log(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(COMBINED, encoding="utf-8")
    out, review = tmp_path / "r.json", tmp_path / "review.jsonl"
    assert traffic_eval.main([str(log), "--format", "combined", "--out", str(out), "--review", str(review)]) == 0
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["total"] == 2 and rep["actions"] == {"ALLOW": 1, "BLOCK": 1}
    rows = [json.loads(x) for x in review.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["uri"] == "/api/login" and "SQLI-001" in rows[0]["rules"]


def test_labeled_jsonl(tmp_path):
    cap = tmp_path / "cap.jsonl"
    rows = [
        {"method": "GET", "uri": "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "label": "attack"},
        {"method": "POST", "uri": "/api/qna/posts", "headers": {"Content-Type": "application/json"},
         "body": json.dumps({"content": "JOIN과 서브쿼리 중 뭐가 빠른가요?"}), "label": "normal"},
        {"method": "GET", "uri": "/api/products?id=2", "label": "normal"},
    ]
    cap.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    out = tmp_path / "r.json"
    traffic_eval.main([str(cap), "--format", "jsonl", "--out", str(out)])
    lab = json.loads(out.read_text(encoding="utf-8"))["labeled"]
    assert lab == {"attack": 1, "normal": 2, "detection_rate": 1.0, "block_rate": 1.0, "fp_rate": 0.0,
                   "blocked_fp_rate": 0.0}
