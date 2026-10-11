"""Self-contained HTML report. No external requests."""
from __future__ import annotations

from importlib import resources

from jinja2 import Environment

from ..findings import SEVERITIES, severity_rank
from ..textsafe import printable
from . import summarize


def render(store) -> str:
    manifest = store.read_manifest()
    findings = sorted(store.findings(), key=lambda f: -severity_rank(f.severity))
    for f in findings:
        f.target = printable(f.target, limit=300)
        f.detail = printable(f.detail, limit=500)
    template_text = resources.files("agentmap.report.templates").joinpath(
        "report.html.j2").read_text(encoding="utf-8")
    env = Environment(autoescape=True)
    template = env.from_string(template_text)
    return template.render(manifest=manifest, findings=findings,
                           summary=summarize(store), severities=SEVERITIES)
