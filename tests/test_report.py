import json
import re

import pytest

from agentmap.findings import make_finding
from agentmap.report import SCHEMA_VERSION, summarize
from agentmap.report.html import render as render_html
from agentmap.report.json_out import write_findings_json, write_results_jsonl
from agentmap.report.markdown import md_escape, render as render_md
from agentmap.store import RunStore

HOSTILE = "pipe|here\nnewline <script>alert(1)</script> \x1b[2J ‮RTL"


def seeded_store(tmp_path):
    store = RunStore.new(tmp_path)
    store.write_manifest({"tool": "agentmap", "level": "passive", "targets": 1})
    # NOTE: make_finding's third positional parameter is `confidence`, not
    # `severity` (signature: make_finding(rule_id, target, confidence="medium",
    # *, detail="", evidence=None, severity=None)). The brief's own fixture
    # passed "high"/"info" positionally, which either silently sets
    # confidence instead of severity (AM-A2A-002's rule default severity is
    # "medium", so the finding would come out medium, not high) or raises
    # ValueError outright ("info" is not a valid confidence). Severity must
    # be passed as an explicit keyword to get the severities this test
    # actually asserts on.
    store.add_finding(make_finding("AM-A2A-002", "http://h:1/", detail=HOSTILE, severity="high"))
    store.add_finding(make_finding("AM-MCP-001", "http://h:2/", detail="transport=streamable-http", severity="info"))
    return store


def test_summarize_counts_by_severity(tmp_path):
    store = seeded_store(tmp_path)
    s = summarize(store)
    assert s["total"] == 2 and s["by_severity"]["high"] == 1 and s["by_severity"]["info"] == 1


def test_json_schema_and_manifest(tmp_path):
    store = seeded_store(tmp_path)
    out = store.run_dir / "findings.json"
    write_findings_json(store, out)
    data = json.loads(out.read_text())
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["manifest"]["level"] == "passive"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] == "AM-A2A-002"


def test_jsonl_copy_is_already_masked(tmp_path):
    store = seeded_store(tmp_path)
    store.add_observation(type("O", (), {"to_dict": lambda self: {"kind": "t", "target": "x",
                                                                   "data": {}, "evidence": []}})())
    out = store.run_dir / "results_copy.jsonl"
    write_results_jsonl(store, out)
    assert out.read_text() == (store.run_dir / "results.jsonl").read_text()


def _unescaped_pipe_count(line: str) -> int:
    """Count pipes that act as cell delimiters (not preceded by a backslash).

    A literal "|" in hostile content is correctly rendered as "\\|" by
    md_escape: the character is still present (so raw ``str.count("|")``
    legitimately differs row to row depending on content), but it is no
    longer a delimiter. The structural invariant that must hold is that the
    number of *unescaped* pipes - i.e. actual column delimiters - is the
    same on every row, not that the raw character count matches.
    """
    count, i = 0, 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == "|":
            count += 1
        i += 1
    return count


def test_markdown_table_is_not_broken_by_hostile_detail(tmp_path):
    md = render_md(seeded_store(tmp_path))
    assert "\x1b" not in md
    rows = [line for line in md.splitlines() if line.startswith("|") and "AM-" in line]
    assert len(rows) == 2
    for row in rows:
        # 4 columns -> 5 delimiter pipes, regardless of escaped content.
        assert _unescaped_pipe_count(row) == 5 == _unescaped_pipe_count(rows[0])
    assert "<script>" not in md


def test_html_is_self_contained_and_escapes_hostile_text(tmp_path):
    html = render_html(seeded_store(tmp_path))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    for pattern in (r'href="https?://', r'src="https?://', r"@import\s+url\(https?://",
                    r'<link[^>]+href="https?://'):
        assert not re.search(pattern, html)
    assert "fonts.googleapis.com" not in html and "cdnjs" not in html and "jsdelivr" not in html
    assert "AM-A2A-002" in html and "high" in html.lower()


def test_html_counts_match_summary(tmp_path):
    store = seeded_store(tmp_path)
    html = render_html(store)
    s = summarize(store)
    assert str(s["total"]) in html


def test_empty_store_reports_render_without_error(tmp_path):
    store = RunStore.new(tmp_path)
    store.write_manifest({"tool": "agentmap", "level": "passive"})
    assert "0" in render_html(store)
    assert isinstance(render_md(store), str)


# --- Additional injection-safety probes beyond the brief's HOSTILE string ---

def test_md_escape_never_leaves_a_bare_backtick():
    """A backtick anywhere in hostile text (not just leading) must be escaped.

    GFM-style table parsers treat pipes inside a code span (a matched pair of
    backtick runs) as non-delimiters. An unescaped backtick in one cell can
    pair with an unescaped backtick in a later cell on the same raw line,
    turning the pipe between them into inert code-span content and merging
    table cells. Escaping only a *leading* backtick misses this: a backtick
    anywhere else in the string stays bare.
    """
    for value in ("a`b", "mid`dle backtick", "``double``", "end with backtick`"):
        escaped = md_escape(value)
        # Every backtick in the escaped output must be immediately preceded
        # by a backslash (i.e. no bare, unescaped backtick survives).
        for i, ch in enumerate(escaped):
            if ch == "`":
                assert i > 0 and escaped[i - 1] == "\\", (value, escaped)


def test_markdown_table_survives_cross_cell_backtick_pairing():
    """Regression test for the cross-cell code-span table-corruption bug.

    A finding whose target and detail each carry a single backtick (odd
    count individually, but an even, pairable count across the raw row) can
    make a real Markdown table renderer treat the pipe between the two
    cells as part of a code span, merging "Target" and "Detail" into one
    cell. Verify with python-markdown's tables extension that the row still
    renders as four separate cells once passed through md_escape.
    """
    md_pkg = pytest.importorskip("markdown")

    header = ["| Severity | Rule | Target | Detail |", "|---|---|---|---|"]
    row = (
        "| high | AM-RULE | "
        + md_escape("a`b has a backtick")
        + " | "
        + md_escape("c`d also has one | and a pipe")
        + " |"
    )
    table_src = "\n".join(header + [row])
    html = md_pkg.markdown(table_src, extensions=["tables"])
    assert html.count("<td>") == 4, html
    # The literal backtick characters must still be visible as plain text,
    # not consumed as code-span delimiters.
    assert "<code>" not in html, html


def test_markdown_rejects_leading_structural_markers():
    for value in ("# heading", "- list item", "* bullet"):
        escaped = md_escape(value)
        assert escaped[0] == "\\"
    # ">" (blockquote marker) is neutralized by HTML-entity encoding instead
    # of a leading backslash: no raw ">" survives anywhere in the output.
    escaped = md_escape("> quote")
    assert escaped[0] != ">"
    assert ">" not in escaped


def test_html_rtl_override_and_control_bytes_are_not_raw_in_output(tmp_path):
    store = RunStore.new(tmp_path)
    store.write_manifest({"tool": "agentmap", "level": "passive"})
    store.add_finding(make_finding("AM-MCP-001", "http://h:1/", detail=HOSTILE))
    html = render_html(store)
    assert "\x1b" not in html
    assert "‮" not in html
