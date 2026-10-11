"""Finding model and rule registry."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    level: str
    protocol: str
    description: str
    remediation: str
    rationale: str
    references: tuple[str, ...] = ()


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: str
    protocol: str
    target: str
    title: str
    description: str
    remediation: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        raw = "|".join((self.rule_id, self.target, self.detail))
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["id"] = self.id
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = {k: v for k, v in data.items() if k != "id"}
        return cls(**data)


REGISTRY: dict[str, Rule] = {}


def make_finding(
    rule_id: str,
    target: str,
    confidence: str = "medium",
    *,
    detail: str = "",
    evidence: list[str] | None = None,
    severity: str | None = None,
) -> Finding:
    rule = REGISTRY[rule_id]
    sev = severity or rule.severity
    if sev not in SEVERITIES:
        raise ValueError(f"unknown severity {sev!r}")
    if confidence not in CONFIDENCES:
        raise ValueError(f"unknown confidence {confidence!r}")
    return Finding(
        rule_id=rule.id,
        severity=sev,
        confidence=confidence,
        protocol=rule.protocol,
        target=target,
        title=rule.title,
        description=rule.description,
        remediation=rule.remediation,
        detail=detail,
        evidence=list(evidence or []),
        references=list(rule.references),
        tags=[rule.protocol, rule.level],
    )
