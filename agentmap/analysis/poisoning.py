"""Heuristic indicators of prompt or tool poisoning in server-supplied text."""
from __future__ import annotations

import re

_PHRASES = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|do\s+not\s+(?:tell|mention|reveal|inform)\s+(?:the\s+)?user"
    r"|without\s+(?:telling|informing)\s+the\s+user"
    r"|<\s*important\s*>"
    r"|system\s+prompt"
    r"|you\s+must\s+(?:always|never)"
    r"|before\s+(?:using|calling)\s+this\s+tool[,\s]+(?:you\s+)?(?:must|first|always))"
)
_MARKUP = re.compile(r"(?i)(<\s*script\b|<!--|<\s*iframe\b|javascript:)")


def _hidden(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if (0x200B <= cp <= 0x200F or 0x202A <= cp <= 0x202E
                or 0x2060 <= cp <= 0x2064 or 0x2066 <= cp <= 0x2069
                or cp == 0xFEFF or 0xE0000 <= cp <= 0xE007F):
            return True
    return False


def scan_text(text: str, *, long_over: int = 2000) -> list[str]:
    if not text:
        return []
    kinds = set()
    if _PHRASES.search(text):
        kinds.add("instruction_phrase")
    if _hidden(text):
        kinds.add("hidden_unicode")
    if len(text) > long_over:
        kinds.add("long_text")
    if _MARKUP.search(text):
        kinds.add("markup")
    return sorted(kinds)
