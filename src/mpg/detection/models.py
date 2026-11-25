from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Location(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    FORM = "form"
    JSON = "json"
    MULTIPART = "multipart"
    BODY = "body"


PLUS_AS_SPACE = {Location.QUERY, Location.FORM}


class Mode(str, Enum):
    BLOCK = "BLOCK"
    DETECT = "DETECT"


class Action(str, Enum):
    ALLOW = "ALLOW"
    DETECT_ONLY = "DETECT_ONLY"
    BLOCK = "BLOCK"


class RuleKind(str, Enum):
    REGEX = "regex"
    SIGNAL = "signal"
    ANALYZER = "analyzer"


class Category(str, Enum):
    SQLI = "SQLI"
    XSS = "XSS"
    SCRIPT = "SCR"
    ENCODING = "ENC"


@dataclass(frozen=True)
class Field:
    location: Location
    name: str
    value: str

    @property
    def ref(self) -> str:
        return f"{self.location.value}.{self.name}"


@dataclass(frozen=True)
class InspectionRequest:
    method: str
    path: str
    fields: tuple[Field, ...]
    duplicate_params: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Rule:
    id: str
    category: Category
    kind: RuleKind
    weight: int
    mode: Mode
    description: str = ""
    pattern: str | None = None
    keywords: tuple[str, ...] = ()
    signal: str | None = None
    analyzer: str | None = None
    enabled: bool = True


@dataclass(frozen=True)
class RuleException:
    rule_id: str
    path: str
    param: str
    expires_at: datetime
    id: str | None = None

    def applies(self, rule_id: str, path: str, param: str, now: datetime) -> bool:
        return (
            self.rule_id == rule_id
            and self.path == path
            and self.param == param
            and now < self.expires_at
        )


@dataclass(frozen=True)
class PathThreshold:
    """경로(·파라미터)별 차단 임계값. 탐지 임계값은 전역값을 유지한다.

    차단 임계값을 올리면 그 사이 점수는 차단 대신 DETECT_ONLY로 기록된다(조용히 통과하지 않는다).
    """
    path: str
    threshold: int
    param: str | None = None
    prefix: bool = False
    id: str | None = None

    def matches(self, path: str, param: str) -> bool:
        if self.param is not None and self.param != param:
            return False
        if self.prefix:
            return path.startswith(self.path)
        return path == self.path

    def specificity(self) -> tuple[int, int, int]:
        return (0 if self.prefix else 1, 1 if self.param is not None else 0, len(self.path))


@dataclass(frozen=True)
class Policy:
    version: int
    rules: tuple[Rule, ...]
    exceptions: tuple[RuleException, ...] = ()
    threshold: int = 6
    path_thresholds: tuple[PathThreshold, ...] = ()


@dataclass
class NormalizationResult:
    raw: str
    text: str
    steps: list[tuple[str, str]]
    signals: set[str]
    url_rounds: int


@dataclass(frozen=True)
class Match:
    rule_id: str
    category: Category
    field_ref: str
    score: int
    mode: Mode
    evidence: str
    excepted: bool = False


@dataclass
class FieldResult:
    field: Field
    normalization: NormalizationResult
    candidates: tuple[str, ...]
    matches: list[Match]
    score: int
    block_score: int
    block_threshold: int = 6


@dataclass
class Verdict:
    action: Action
    risk_score: int
    policy_version: int
    matches: list[Match]
    fields: list[FieldResult] = field(default_factory=list)
    elapsed_ms: float = 0.0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
