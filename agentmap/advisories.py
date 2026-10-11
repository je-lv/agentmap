"""Match reported server name/version against curated advisories."""
from __future__ import annotations

import re

from .datafiles import load


def _version_tuple(version: str) -> tuple[int, int, int] | None:
    nums = [int(n) for n in re.findall(r"\d+", version or "")[:3]]
    if not nums:
        return None
    return tuple(nums + [0] * (3 - len(nums)))  # type: ignore[return-value]


def match_advisories(server_name: str, version: str,
                     advisories: list[dict] | None = None) -> list[dict]:
    if advisories is None:
        advisories = load("advisories") or []
    have = _version_tuple(version)
    if have is None:
        return []
    out = []
    for adv in advisories:
        if not re.search(adv["product"], server_name or "", re.IGNORECASE):
            continue
        limit = _version_tuple(adv["affected_below"])
        if limit is not None and have < limit:
            out.append(adv)
    return out
