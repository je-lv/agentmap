"""Colour, glyph and label per endpoint state; ANSI stripping for embedded text."""
from __future__ import annotations

import re

STATE_STYLE: dict[str, tuple[str, str, str]] = {
    "open":    ("#00ff88", "●", "OPEN"),
    "closed":  ("grey42",  "·", "closed"),
    "error":   ("#ff3366", "✖", "ERROR"),
    "scope":   ("grey42",  "·", "skip"),
    "resumed": ("grey42",  "·", "resumed"),
}

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)
