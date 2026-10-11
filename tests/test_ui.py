import io

from rich.console import Console

from agentmap.ui.theme import STATE_STYLE, strip_ansi
from agentmap.ui.views import Row, ScanView, build_row, footer_line, plain_line, render_panel


def test_state_style_covers_every_state():
    assert set(STATE_STYLE) == {"open", "closed", "error", "scope", "resumed"}
    for colour, glyph, label in STATE_STYLE.values():
        assert colour and glyph and label


def test_strip_ansi_removes_escape_sequences_from_embedded_tool_text():
    assert strip_ansi("\x1b[31mred\x1b[0m text") == "red text"
    assert strip_ansi("plain") == "plain"


def test_plain_line_omits_empty_fields_and_strips_ansi():
    row = Row("open", "10.0.1.1:8000", matched="a2a", elapsed="0.4s",
              reason="2 findings (\x1b[31m1 high\x1b[0m)")
    line = plain_line(row)
    assert line == "OPEN  10.0.1.1:8000  a2a  0.4s  2 findings (1 high)"
    assert "\x1b" not in line
    closed = Row("closed", "10.0.1.1:8001")
    assert plain_line(closed) == "closed  10.0.1.1:8001"


def test_build_row_returns_six_cells():
    cells = build_row(Row("error", "h:1", reason="boom"))
    assert len(cells) == 6


def test_reason_is_truncated_not_wrapped_in_plain_line():
    long_reason = "x" * 300
    row = Row("open", "h:1", reason=long_reason)
    line = plain_line(row)
    assert "\n" not in line and len(line) < 300


def test_render_panel_uses_expand_and_single_ratio_column():
    panel = render_panel("agentmap  level=passive", [Row("open", "h:1", reason="ok")], "1 endpoint")
    table = panel.renderable.renderables[2]
    assert table.expand is True
    ratio_cols = [c for c in table.columns if getattr(c, "ratio", None)]
    assert len(ratio_cols) == 1


def test_footer_line_omits_zero_counts_except_total():
    class Cov:
        endpoints_total = 5
        tcp_open = 0
        tcp_closed = 5
        skipped_resumed = 0
        skipped_scope = 0
        errors = 0
    line = footer_line(Cov(), {"total": 0, "by_severity": {}}, 1.2).plain
    assert "5 endpoints" in line and "closed" in line
    assert "open" not in line.replace("endpoints", "") and "error" not in line and "skip" not in line


def test_footer_line_shows_findings_when_present():
    class Cov:
        endpoints_total = 1
        tcp_open = 1
        tcp_closed = 0
        skipped_resumed = 0
        skipped_scope = 0
        errors = 0
    line = footer_line(Cov(), {"total": 2, "by_severity": {"high": 1, "info": 1}}, 0.5).plain
    assert "2 findings" in line and "1 high" in line


def test_scan_view_tty_mode_does_not_print_each_row(monkeypatch):
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=80)
    view = ScanView(console=console)
    assert view.is_tty is True
    view.start("agentmap  level=passive")
    view.update(Row("open", "h:1"))
    view.update(Row("closed", "h:2"))
    out_before_finish = buf.getvalue()
    view.finish(type("C", (), {"endpoints_total": 2, "tcp_open": 1, "tcp_closed": 1,
                               "skipped_resumed": 0, "skipped_scope": 0, "errors": 0})(),
               {"total": 0, "by_severity": {}}, 1.0)
    assert "h:1" in buf.getvalue()


def test_scan_view_non_tty_prints_plain_lines_immediately():
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=80)
    view = ScanView(console=console)
    assert view.is_tty is False
    view.start("agentmap  level=passive")
    view.update(Row("open", "h:1", matched="a2a"))
    out = buf.getvalue()
    assert "OPEN  h:1  a2a" in out and "\x1b" not in out


def test_scan_view_never_raises_on_bad_data():
    console = Console(file=io.StringIO(), force_terminal=True, width=80)
    view = ScanView(console=console)
    view.start("h")
    view.update(Row("open", "h:1", reason=None))  # type: ignore[arg-type]
    view.finish(None, {"total": 0, "by_severity": {}}, 0.0)
