"""Typed acknowledgement for the active level, recorded in the manifest."""
from __future__ import annotations

from datetime import datetime, timezone

ACK_PHRASE = "I am authorized to test these targets"


class Refused(Exception):
    """Scope or acknowledgement was refused."""


def _ack() -> dict:
    return {
        "level": "active",
        "phrase": ACK_PHRASE,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def require_ack(level: str, provided: str | None, *, prompt_fn=None,
                interactive: bool = False) -> dict | None:
    if level != "active":
        return None
    if provided is not None:
        if provided.strip().lower() == ACK_PHRASE.lower():
            return _ack()
        raise Refused("acknowledgement phrase does not match")
    if interactive and prompt_fn is not None:
        answer = prompt_fn(f"Active checks send requests that test access control.\nType exactly: {ACK_PHRASE}\n> ")
        if answer.strip().lower() == ACK_PHRASE.lower():
            return _ack()
        raise Refused("acknowledgement phrase does not match")
    raise Refused("active level requires --acknowledge with the exact phrase")
