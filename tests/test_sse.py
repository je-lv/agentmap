from agentmap.sse import first_event, parse_events


def test_parse_events_basic_and_default_event():
    text = "event: endpoint\ndata: /messages?s=1\n\ndata: {\"a\":1}\n\n"
    assert parse_events(text) == [("endpoint", "/messages?s=1"), ("message", '{"a":1}')]


def test_comments_and_crlf_and_multiline_data():
    text = ": ping\r\n\r\nevent: x\r\ndata: a\r\ndata: b\r\n\r\n"
    assert parse_events(text) == [("x", "a\nb")]


def test_trailing_partial_block_kept_if_it_has_data():
    assert parse_events("data: tail") == [("message", "tail")]


def test_first_event_requires_complete_block():
    assert first_event(b"event: endpoint\ndata: /m") is None
    assert first_event(b"event: endpoint\ndata: /m\n\nevent: x\n") == ("endpoint", "/m")
    assert first_event(b": keepalive\n\nevent: endpoint\ndata: /m\n\n") == ("endpoint", "/m")
