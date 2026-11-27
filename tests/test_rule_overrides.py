"""경로별 룰 모드(경로별 룰 그룹)."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from conftest import ROOT
from mpg.common.policy_io import policy_from_snapshot, policy_to_snapshot
from mpg.detection import (
    Action,
    DetectionPipeline,
    Field,
    InspectionRequest,
    Location,
    Mode,
    PathRuleOverride,
    PathThreshold,
    RuleError,
    RuleException,
)
from mpg.detection.regress import RegressionTester, load_samples
from mpg.detection.rules import rule_override_from_dict
from mpg.detection.scorer import RiskScorer

QNA = "/api/qna/posts"
SCRIPT_Q = "<script> 태그를 body 끝에 두는 이유?"  # XSS-001(+7, BLOCK)만 걸리는 정상 질문
EMBED = '<embed src="data:image/svg+xml;base64,PHN2Zz4=">'  # XSS-004(+4, DETECT) + XSS-016(+4)


def req(path, name, value, loc=Location.JSON):
    return InspectionRequest("POST", path, (Field(loc, name, value),))


def pipe_with(policy, overrides=(), thresholds=()):
    return DetectionPipeline(replace(policy, rule_overrides=tuple(overrides), path_thresholds=tuple(thresholds)))


@pytest.fixture
def bare(policy):
    return replace(policy, rule_overrides=(), path_thresholds=())


def test_detect_override_logs_instead_of_blocking_only_on_that_path(bare):
    pipe = pipe_with(bare, [PathRuleOverride(QNA, "XSS-001", Mode.DETECT, param="content")])
    v = pipe.inspect(req(QNA, "content", SCRIPT_Q))
    assert v.action is Action.DETECT_ONLY
    m = next(m for m in v.matches if m.rule_id == "XSS-001")
    assert m.mode is Mode.DETECT and m.overridden and m.score == 7
    # 다른 파라미터·다른 경로는 전역 모드 그대로
    assert pipe.inspect(req(QNA, "title", SCRIPT_Q)).action is Action.BLOCK
    assert pipe.inspect(req("/api/feedback", "content", SCRIPT_Q)).action is Action.BLOCK
    # 낮춘 룰 말고 다른 차단 룰이 충분하면 여전히 차단
    assert pipe.inspect(req(QNA, "content", "<script>alert(document.cookie)</script>")).action is Action.BLOCK


def test_block_override_tightens_detect_rule(bare):
    assert DetectionPipeline(bare).inspect(req(QNA, "content", EMBED)).action is Action.DETECT_ONLY
    pipe = pipe_with(bare, [PathRuleOverride(QNA, "XSS-004", Mode.BLOCK, param="content")])
    v = pipe.inspect(req(QNA, "content", EMBED))
    assert v.action is Action.BLOCK
    assert pipe.inspect(req("/api/feedback", "content", EMBED)).action is Action.DETECT_ONLY


def test_most_specific_override_wins():
    s = RiskScorer([], [], 6, rule_overrides=[
        PathRuleOverride("/api", "XSS-001", Mode.DETECT, prefix=True),
        PathRuleOverride(QNA, "XSS-001", Mode.BLOCK),
        PathRuleOverride(QNA, "XSS-001", Mode.DETECT, param="content"),
    ])
    from mpg.detection import Category, Match
    m = Match("XSS-001", Category.XSS, "json.x", 7, Mode.BLOCK, "<script")
    assert s.apply_overrides([m], QNA, "content")[0].mode is Mode.DETECT
    assert s.apply_overrides([m], QNA, "title")[0].mode is Mode.BLOCK
    assert not s.apply_overrides([m], QNA, "title")[0].overridden  # 이미 BLOCK이면 바뀐 게 없다
    assert s.apply_overrides([m], "/api/login", "username")[0].mode is Mode.DETECT
    assert s.apply_overrides([m], "/other", "x")[0].mode is Mode.BLOCK


def test_exception_still_wins_over_override(bare):
    exp = datetime.now(timezone.utc) + timedelta(days=1)
    p = replace(bare, exceptions=(RuleException("XSS-004", QNA, "content", exp),))
    pipe = pipe_with(p, [PathRuleOverride(QNA, "XSS-004", Mode.BLOCK, param="content")])
    v = pipe.inspect(req(QNA, "content", EMBED))
    assert next(m for m in v.matches if m.rule_id == "XSS-004").excepted
    assert v.action is not Action.BLOCK


def test_validation(bare):
    ok = {"path": QNA, "param": "content", "rule_id": "XSS-004", "mode": "BLOCK"}
    assert rule_override_from_dict(ok, bare.rules, strict=True).mode is Mode.BLOCK
    for bad in (
        {**ok, "path": "api"},
        {**ok, "path": "/api/*"},
        {**ok, "param": "con?tent"},
        {**ok, "path": "/", "prefix": True},
        {**ok, "mode": "ALLOW"},
        {**ok, "rule_id": ""},
        {**ok, "rule_id": "NOPE-1"},
    ):
        with pytest.raises(RuleError):
            rule_override_from_dict(bad, bare.rules, strict=True)
    # 전역 모드와 같으면 등록 거부(strict), 스냅샷 읽기에서는 허용(나중에 전역 모드를 바꿔도 리로드가 깨지지 않게)
    noop = {**ok, "rule_id": "XSS-001"}
    with pytest.raises(RuleError):
        rule_override_from_dict(noop, bare.rules, strict=True)
    assert rule_override_from_dict(noop, bare.rules).rule_id == "XSS-001"


def test_snapshot_round_trip(policy):
    p = replace(policy, rule_overrides=(PathRuleOverride("/api", "SQLI-002", Mode.DETECT, prefix=True, id="7"),))
    back = policy_from_snapshot(policy_to_snapshot(p))
    assert back.rule_overrides == p.rule_overrides
    snap = policy_to_snapshot(p)
    snap["rule_overrides"][0]["rule_id"] = "NOPE-1"
    with pytest.raises(RuleError):
        policy_from_snapshot(snap)


def test_rules_file_ships_board_override(policy):
    assert any(o.path == QNA and o.param == "content" and o.rule_id == "XSS-004" and o.mode is Mode.BLOCK
               for o in policy.rule_overrides)


def test_board_override_halves_logged_only_attacks_without_new_false_positives(policy):
    """게시판 임계값 8만 쓸 때 차단되지 않던 이 경로 공격 21건 → XSS-004 차단 설정으로 11건 이하.
    기술 Q&A 어려운 셋 차단 0/40, 정상 셋 차단 오탐 0은 그대로.
    (기록만 되는 정상 4건은 CMD-006: 게시판 글 속 여러 줄 코드의 줄 머리 curl. 게시판 임계값 8이라 차단은 안 된다.)"""
    attacks = [s for s in load_samples(ROOT / "datasets" / "attack.jsonl") if s.path == QNA and s.param == "content"]
    threshold_only = replace(policy, rule_overrides=())
    t_only = RegressionTester(attacks, []).run(threshold_only)
    shipped = RegressionTester(attacks, []).run(policy)
    assert t_only.attack_total - t_only.blocked == 21
    assert shipped.attack_total - shipped.blocked <= 11
    assert shipped.detection_rate == 1.0
    hard = RegressionTester([], load_samples(ROOT / "datasets" / "normal_hard.jsonl")).run(policy)
    assert hard.blocked_fp == 0
    normal = RegressionTester([], load_samples(ROOT / "datasets" / "normal.jsonl")).run(policy)
    assert normal.blocked_fp == 0
    assert normal.false_positives <= 4


def test_override_and_threshold_compose(bare):
    pipe = pipe_with(bare, [PathRuleOverride(QNA, "XSS-004", Mode.BLOCK, param="content")],
                     [PathThreshold(QNA, 8, param="content")])
    assert pipe.inspect(req(QNA, "content", EMBED)).action is Action.BLOCK  # 4+4 = 8 ≥ 8
    iframe = '<iframe src="https://www.youtube.com/embed/abc"></iframe> 임베드'
    assert pipe.inspect(req(QNA, "content", iframe)).action is Action.DETECT_ONLY  # 4+2 = 6 < 8
