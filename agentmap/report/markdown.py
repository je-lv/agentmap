"""Markdown report: one table row per finding."""
from __future__ import annotations

from ..findings import SEVERITIES, severity_rank
from ..textsafe import printable
from . import summarize


def md_escape(value: str) -> str:
    text = printable(value, limit=300)
    # Escape backslashes first so the backslashes introduced by the escapes
    # below are never themselves re-escaped.
    text = text.replace("\\", "\\\\")
    # Escape every backtick, not just a leading one. GFM-style table parsers
    # treat pipe characters inside a code span (a matched pair of backtick
    # runs) as non-delimiters. A bare backtick anywhere in one cell can pair
    # with a bare backtick later in the same raw row (e.g. in a different
    # cell) and turn the pipe between them into inert code-span content,
    # merging table cells. Escaping only a leading backtick misses this.
    text = text.replace("`", "\\`")
    # HTML-entity-encode "&", "<", ">" (ampersand first) so a raw HTML tag
    # such as "<script>" embedded in hostile server text cannot pass through
    # as inline raw HTML when the report is later rendered by some other
    # Markdown viewer (GitHub, a static site generator, an unsanitized
    # markdown-it instance, ...). Encoding "&" first stops a pre-existing
    # "&lt;"-like sequence in the hostile input from being reinterpreted
    # after our own encoding runs. A backslash escape (e.g. "\<") would not
    # be enough here: the literal substring "<script>" survives inside
    # "\<script>", so a naive string search for it - or a non-CommonMark-
    # compliant viewer that doesn't honor backslash escapes - would still
    # see it.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if text[:1] in ("#", "-", "*"):
        text = "\\" + text
    return text


def render(store) -> str:
    manifest = store.read_manifest()
    findings = sorted(store.findings(), key=lambda f: -severity_rank(f.severity))
    summary = summarize(store)
    lines = [
        "# agentmap report", "",
        f"Level: `{md_escape(str(manifest.get('level', '')))}`  ",
        f"Total findings: {summary['total']}  ",
        "Counts: " + ", ".join(f"{s}={summary['by_severity'][s]}" for s in SEVERITIES), "",
        "| Severity | Rule | Target | Detail |", "|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.severity} | {f.rule_id} | {md_escape(f.target)} | {md_escape(f.detail)} |")
    if not findings:
        lines.append("| - | - | - | no findings |")
    return "\n".join(lines) + "\n"
