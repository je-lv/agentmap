"""Credential-shaped value detection and masking."""
from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]
_GENERIC = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|authorization)\b[\"']?\s*[:=]\s*[\"']?"
    r"(?P<v>[A-Za-z0-9_\-./+=]{16,})"
)


@dataclass(frozen=True)
class SecretHit:
    kind: str
    start: int
    end: int


def _random_looking(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def find_secrets(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            hits.append(SecretHit(kind, m.start(), m.end()))
    for m in _GENERIC.finditer(text):
        if _random_looking(m.group("v")):
            hits.append(SecretHit("generic_secret", m.start("v"), m.end("v")))
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    out: list[SecretHit] = []
    last_end = -1
    for hit in hits:
        if hit.start >= last_end:
            out.append(hit)
            last_end = hit.end
    return out


def mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}" + chr(0x2026) + f"[{len(value)}]"


def redact_text(text: str) -> str:
    hits = find_secrets(text)
    if not hits:
        return text
    parts = []
    pos = 0
    for hit in hits:
        parts.append(text[pos:hit.start])
        parts.append(f"<{hit.kind}:{mask(text[hit.start:hit.end])}>")
        pos = hit.end
    parts.append(text[pos:])
    return "".join(parts)


def scan_json(obj, prefix: str = "") -> list[dict]:
    found: list[dict] = []
    if isinstance(obj, str):
        for hit in find_secrets(obj):
            found.append({"path": prefix or "$", "kind": hit.kind})
    elif isinstance(obj, dict):
        for key, value in obj.items():
            found.extend(scan_json(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            found.extend(scan_json(value, f"{prefix}[{index}]"))
    return found


def mask_json(obj):
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {key: mask_json(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [mask_json(value) for value in obj]
    return obj
