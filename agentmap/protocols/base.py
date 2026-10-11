"""Shared protocol plugin types."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Observation:
    kind: str
    target: str
    data: dict
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target, "data": self.data,
                "evidence": list(self.evidence)}

    @classmethod
    def from_dict(cls, d: dict) -> "Observation":
        return cls(d["kind"], d["target"], d["data"], list(d.get("evidence", [])))


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    path: str = ""

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def base(self) -> str:
        return self.origin + self.path

    def url(self, path: str) -> str:
        return self.base + path


@dataclass
class ProbeContext:
    http: object
    level: str
    store: object

    def evidence(self, name: str, data: bytes) -> str:
        return self.store.write_evidence(name, data)


class Protocol:
    """Plugin interface. probe() does all I/O through ctx.http; analyze() is pure."""

    name = ""
    min_level = "passive"

    async def probe(self, ep: Endpoint, ctx: ProbeContext) -> list[Observation]:
        raise NotImplementedError

    def analyze(self, observations: list[Observation]) -> list:
        raise NotImplementedError
