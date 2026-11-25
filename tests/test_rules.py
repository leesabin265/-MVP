import pytest

from mpg.detection import RuleError, load_rules
from mpg.detection.rules import exception_from_dict

BASE = {"id": "T-1", "category": "SQLI", "weight": 5, "mode": "BLOCK"}


def test_rule_file_has_enough_rules(policy):
    assert len(policy.rules) >= 30
    assert len({r.id for r in policy.rules}) == len(policy.rules)


@pytest.mark.parametrize("pattern", [r"(a)\1", r"union(?=\s)", r"(?<!x)select"])
def test_re2_rejects_backtracking_features(pattern):
    with pytest.raises(RuleError, match="RE2"):
        load_rules([{**BASE, "pattern": pattern}])


def test_duplicate_ids_rejected():
    with pytest.raises(RuleError, match="duplicate"):
        load_rules([{**BASE, "pattern": "a"}, {**BASE, "pattern": "b"}])


@pytest.mark.parametrize(
    "patch, msg",
    [
        ({"weight": 0}, "weight"),
        ({"mode": "MAYBE"}, "MAYBE"),
        ({"kind": "signal", "signal": "nope"}, "unknown signal"),
        ({"kind": "analyzer", "analyzer": "nope"}, "unknown analyzer"),
        ({}, "pattern"),
    ],
)
def test_invalid_rules(patch, msg):
    with pytest.raises(RuleError, match=msg):
        load_rules([{**BASE, **patch}])


def test_exception_requires_fields_and_forbids_wildcards():
    ok = {"rule_id": "SQLI-002", "path": "/api/qna/posts", "param": "content",
          "expires_at": "2026-12-25T00:00:00+09:00"}
    assert exception_from_dict(ok).param == "content"
    with pytest.raises(RuleError, match="wildcards"):
        exception_from_dict({**ok, "path": "/api/*"})
    with pytest.raises(RuleError, match="expires_at"):
        exception_from_dict({**ok, "expires_at": ""})
    with pytest.raises(RuleError, match="timezone"):
        exception_from_dict({**ok, "expires_at": "2026-12-25T00:00:00"})
