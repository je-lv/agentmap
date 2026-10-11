"""Reporting: JSON, JSONL, Markdown and HTML, all from a RunStore."""
from __future__ import annotations

from ..findings import SEVERITIES

SCHEMA_VERSION = 1


def summarize(store) -> dict:
    by_severity = {s: 0 for s in SEVERITIES}
    findings = store.findings()
    for f in findings:
        by_severity[f.severity] += 1
    return {"total": len(findings), "by_severity": by_severity}
