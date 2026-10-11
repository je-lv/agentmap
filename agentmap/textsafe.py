"""Make untrusted strings inert for terminal display."""
from __future__ import annotations


def printable(value: object, limit: int = 200) -> str:
    try:
        text = value if isinstance(value, str) else str(value)
    except Exception:  # noqa: BLE001 - hostile __str__
        text = "<unprintable>"
    text = text[: limit * 6 + 1]
    out = []
    for ch in text:
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) < 256:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    result = "".join(out)
    if len(result) > limit:
        result = result[:limit] + "…"
    return result
