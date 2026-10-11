#!/usr/bin/env python3
"""Scan a directory tree for signs it leaked from the operator's own machine.
Run before publishing an export: python scripts/leakscan.py TARGET_DIR [AUTHOR_EMAIL]
Exits nonzero and prints findings if anything is found.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentmap.analysis.secrets import find_secrets  # noqa: E402

# Built via concatenation, not as literal substrings: this file itself gets
# copied into the exported tree before the leak scan runs over it (see
# export-release.sh), so if any marker here appeared as a contiguous literal
# it would find its own definition and flag itself every single time, making
# the export permanently un-shippable. Splitting each marker the same way
# tests/test_secrets.py's AWS/GH/JWT constants are built keeps the detector's
# own source free of the exact substrings it is looking for.
HOME_MARKER = "/" + "home" + "/"
INTERNAL_MARKERS = (
    "TOD" + "O internal",
    "FIXME" + " internal",
    "os" + "ai",
    "tool" + "ing/",
    "." + "claude",
    "super" + "powers",
)


def scan_tree(root: Path, *, author_email: str | None = None) -> list[str]:
    findings: list[str] = []
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root)
        if HOME_MARKER in text:
            findings.append(f"{rel}: contains an absolute {HOME_MARKER} path")
        if author_email and author_email in text:
            findings.append(f"{rel}: contains the author's email address")
        if find_secrets(text):
            findings.append(f"{rel}: contains a credential-shaped value")
        for marker in INTERNAL_MARKERS:
            if marker in text:
                findings.append(f"{rel}: contains the internal marker {marker!r}")
    return findings


if __name__ == "__main__":
    target = Path(sys.argv[1])
    email = sys.argv[2] if len(sys.argv) > 2 else None
    hits = scan_tree(target, author_email=email)
    for hit in hits:
        print(hit, file=sys.stderr)
    sys.exit(1 if hits else 0)
