from dataclasses import replace

import pytest

from conftest import ROOT, rule_ids
from mpg.admin.policy_service import gate_warnings
from mpg.common.policy_io import policy_from_snapshot, policy_to_snapshot
from mpg.detection import (
    Action,
    DetectionPipeline,
    Field,
    InspectionRequest,
    Location,
    PathThreshold,
    RuleError,
)
from mpg.detection.regress import RegressionTester, load_samples
from mpg.detection.rules import path_threshold_from_dict
from mpg.detection.scorer import RiskScorer

QNA = "/api/qna/posts"


def req(path, name, value, loc=Location.JSON):
    return InspectionRequest("POST", path, (Field(loc, name, value),))


def with_pt(policy, *pts):
    return DetectionPipeline(replace(policy, path_thresholds=tuple(pts)))


def test_most_specific_rule_wins():
    s = RiskScorer([], [], 6, [
        PathThreshold("/api", 9, prefix=True),
        PathThreshold("/api/qna", 8, prefix=True),
        PathThreshold(QNA, 7),
        PathThreshold(QNA, 10, param="content"),
    ])
    assert s.block_threshold(QNA, "content") == 10
    assert s.block_threshold(QNA, "title") == 7
    assert s.block_threshold("/api/qna/posts/3", "content") == 8
    assert s.block_threshold("/api/login", "username") == 9
    assert s.block_threshold("/other", "x") == 6


def test_raised_threshold_logs_instead_of_blocking(policy):
    pipe = with_pt(policy, PathThreshold(QNA, 8, param="content"))
    v = pipe.inspect(req(QNA, "content", "<script> 태그를 body 끝에 두는 이유?"))
    assert v.action is Action.DETECT_ONLY
    assert v.risk_score == 7
    assert v.fields[0].block_threshold == 8

    strong = pipe.inspect(req(QNA, "content", "<script>alert(document.cookie)</script>"))
    assert strong.action is Action.BLOCK

    other_param = pipe.inspect(req(QNA, "title", "<script> 태그를 body 끝에 두는 이유?"))
    assert other_param.action is Action.BLOCK
    other_path = pipe.inspect(req("/api/feedback", "content", "<script> 태그를 body 끝에 두는 이유?"))
    assert other_path.action is Action.BLOCK


def test_lowered_threshold_is_stricter(policy):
    pipe = with_pt(policy, PathThreshold("/api/login", 4, param="username"))
    v = pipe.inspect(req("/api/login", "username", "1 and sleep(1)", Location.QUERY))
    assert v.risk_score >= 4
    assert v.action is Action.BLOCK
    weak = pipe.inspect(req("/api/login", "username", "<svg>", Location.QUERY))
    assert weak.action is Action.DETECT_ONLY
    assert rule_ids(weak) == ["XSS-004"]


def test_exceptions_and_thresholds_compose(policy):
    from datetime import datetime, timedelta, timezone

    from mpg.detection import RuleException

    exc = RuleException("SQLI-002", QNA, "content", datetime.now(timezone.utc) + timedelta(days=1))
    pipe = DetectionPipeline(replace(policy, exceptions=(exc,),
                                     path_thresholds=(PathThreshold(QNA, 8, param="content"),)))
    v = pipe.inspect(req(QNA, "content", "x' UNION SELECT password FROM users--"))
    assert v.action is Action.BLOCK


@pytest.mark.parametrize("bad, msg", [
    ({"path": "/api/*", "threshold": 8}, "wildcards"),
    ({"path": "api", "threshold": 8}, "start with"),
    ({"path": "/api", "threshold": 11}, "3..10"),
    ({"path": "/api", "threshold": 2}, "3..10"),
    ({"path": "/", "threshold": 8, "prefix": True}, "every path"),
    ({"path": "/api"}, "integer"),
])
def test_validation(bad, msg):
    with pytest.raises(RuleError, match=msg):
        path_threshold_from_dict(bad, 6)


def test_snapshot_round_trip(policy):
    p = replace(policy, path_thresholds=(PathThreshold(QNA, 8, "content", False, "3"),
                                         PathThreshold("/api/admin", 4, None, True, "4")))
    back = policy_from_snapshot(policy_to_snapshot(p))
    assert back.path_thresholds == p.path_thresholds


def test_board_threshold_removes_hard_false_positives_without_losing_detection(policy):
    attacks = load_samples(ROOT / "datasets" / "attack.jsonl")
    normals = load_samples(ROOT / "datasets" / "normal.jsonl")
    hard = load_samples(ROOT / "datasets" / "normal_hard.jsonl")
    tuned = replace(policy, path_thresholds=(PathThreshold(QNA, 8, param="content"),))
    base_rep = RegressionTester(attacks, normals).run(policy).to_dict()
    tuned_rep = RegressionTester(attacks, normals).run(tuned).to_dict()
    assert tuned_rep["detection_rate"] == base_rep["detection_rate"] == 1.0
    assert tuned_rep["block_rate"] < base_rep["block_rate"]
    assert RegressionTester([], hard).run(tuned).blocked_fp == 0
    assert RegressionTester([], hard).run(policy).blocked_fp == 4
    assert gate_warnings(tuned_rep, base_rep)[0].startswith("block_rate_dropped:")
    assert gate_warnings(base_rep, base_rep) == []
