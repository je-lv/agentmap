import time

from agentmap.textsafe import printable


def test_escapes_terminal_control_sequences():
    out = printable("a\x1b[2Jb\x07c")
    assert "\x1b" not in out and "\x07" not in out
    assert "\\x1b" in out


def test_hidden_unicode_is_made_visible():
    out = printable("ab​cd‮ef")
    assert "​" not in out and "‮" not in out
    assert "\\u200b" in out and "\\u202e" in out


def test_rich_markup_text_is_left_literal():
    assert printable("[red]x[/]") == "[red]x[/]"


def test_truncates_and_never_raises():
    assert printable("x" * 500, limit=10) == "x" * 10 + "…"
    assert printable(None) == "None"
    assert printable(b"bytes") == "b'bytes'"


def test_dos_protection_huge_control_chars():
    """Verify printable() bounds work even on arbitrarily large hostile input.

    The function must not do O(input length) work: it should slice input
    before escaping to prevent DoS via huge strings of control characters.
    """
    huge = "\x1b" * 5_000_000
    limit = 10
    start = time.perf_counter()
    result = printable(huge, limit=limit)
    elapsed = time.perf_counter() - start

    # Verify correct output: control chars escaped and truncated to limit
    # Each \x1b becomes 4 output chars (\, x, 1, b), so the output is
    # truncated to the first 10 chars plus ellipsis.
    assert result.startswith("\\x1b\\x1b\\x")
    assert result.endswith("…")
    assert len(result) == limit + 1  # 10 + 1 (ellipsis)
    # Verify bounded time: should complete in well under 1 second (typically <1ms)
    assert elapsed < 1.0
