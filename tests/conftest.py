from pathlib import Path

import pytest

from mpg.detection import DetectionPipeline, load_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def policy():
    return load_policy(ROOT / "rules" / "rules.yaml")


@pytest.fixture(scope="session")
def pipe(policy):
    return DetectionPipeline(policy)


def rule_ids(verdict):
    return sorted(m.rule_id for m in verdict.matches if not m.excepted)
