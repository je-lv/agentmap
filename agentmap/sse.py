"""Minimal Server-Sent Events parsing."""
from __future__ import annotations


def _block(block: str) -> tuple[str, str] | None:
    event = "message"
    data: list[str] = []
    for line in block.split("\n"):
        if not line or line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            event = value
        elif name == "data":
            data.append(value)
    if not data and event == "message":
        return None
    return event, "\n".join(data)


def parse_events(text: str) -> list[tuple[str, str]]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    for block in text.split("\n\n"):
        parsed = _block(block)
        if parsed:
            out.append(parsed)
    return out


def first_event(buf: bytes) -> tuple[str, str] | None:
    text = buf.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    blocks = text.split("\n\n")
    for block in blocks[:-1]:
        parsed = _block(block)
        if parsed:
            return parsed
    return None
