#!/usr/bin/env python3
"""Render agentmap.findings.REGISTRY as docs/RULES.md. Run from the repo root:
    python scripts/gen_rules_doc.py > docs/RULES.md
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentmap.findings import REGISTRY  # noqa: E402

print("# agentmap rules")
print()
print("Generated from `agentmap/rules.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.")
print()
print("| ID | Severity | Level | Protocol | Title |")
print("|---|---|---|---|---|")
for rule_id in sorted(REGISTRY):
    r = REGISTRY[rule_id]
    print(f"| {r.id} | {r.severity} | {r.level} | {r.protocol} | {r.title} |")
print()
for rule_id in sorted(REGISTRY):
    r = REGISTRY[rule_id]
    print(f"## {r.id}: {r.title}")
    print()
    print(r.description)
    print()
    print(f"**Remediation:** {r.remediation}")
    print()
    print(f"**Rationale:** {r.rationale}")
    print()
    for ref in r.references:
        print(f"- {ref}")
    print()
