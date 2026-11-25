from dataclasses import replace

from conftest import ROOT
from mpg.detection.regress import RegressionTester, load_samples


def _tester():
    return RegressionTester(
        load_samples(ROOT / "datasets" / "attack.jsonl"),
        load_samples(ROOT / "datasets" / "normal.jsonl"),
    )


def test_dataset_sizes():
    t = _tester()
    assert len(t.attacks) >= 500
    assert len(t.normals) >= 300


def test_targets_met(policy):
    rep = _tester().run(policy)
    assert rep.detection_rate >= 0.95, rep.misses[:5]
    assert rep.fp_rate <= 0.01, rep.fp_list[:5]


def test_removing_a_rule_is_flagged_as_regression(policy):
    t = _tester()
    base = t.run(policy)
    weakened = replace(policy, rules=tuple(r for r in policy.rules if r.id != "XSS-001"))
    assert t.run(weakened).regressed_from(base)


def test_hard_normal_set_is_tracked(policy):
    """튜닝에 쓰지 않은 기술 Q&A 문장. 남은 차단은 문자열만으로 공격과 구분할 수 없는 경우(예외로 처리)."""
    hard = load_samples(ROOT / "datasets" / "normal_hard.jsonl")
    rep = RegressionTester([], hard).run(policy)
    blocked = [f for f in rep.fp_list if f["action"] == "BLOCK"]
    assert len(blocked) <= 4, blocked
