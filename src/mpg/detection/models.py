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
class Policy:
    version: int
    rules: tuple[Rule, ...]
    exceptions: tuple[RuleException, ...] = ()
    threshold: int = 6


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
