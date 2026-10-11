"""Bounded JSON loading for untrusted bodies."""
from __future__ import annotations

import json


def _depth_ok(obj: object, max_depth: int) -> bool:
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return True


def loads(data: bytes | str, max_depth: int = 32) -> object | None:
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
    if not data or not data.strip():
        return None
    try:
        obj = json.loads(data)
    except (ValueError, RecursionError):
        return None
    return obj if _depth_ok(obj, max_depth) else None
