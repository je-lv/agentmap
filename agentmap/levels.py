"""Operation levels. Each level includes everything below it."""
from __future__ import annotations

LEVELS = ("passive", "probe", "active")


def rank(level: str) -> int:
    return LEVELS.index(level)


def allows(current: str, required: str) -> bool:
    return rank(current) >= rank(required)
