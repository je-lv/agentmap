from agentmap.jsonsafe import loads


def test_valid_json_and_bom():
    assert loads(b'{"a": 1}') == {"a": 1}
    assert loads(b'\xef\xbb\xbf{"a": 1}') == {"a": 1}
    assert loads('{"a": [1,2]}') == {"a": [1, 2]}


def test_invalid_and_binary_return_none():
    assert loads(b"not json") is None
    assert loads(b"\xff\xfe\x00\x01") is None
    assert loads(b"") is None


def test_depth_bomb_returns_none_not_raises():
    bomb = b"[" * 100_000 + b"]" * 100_000
    assert loads(bomb) is None


def test_depth_limit_enforced_below_recursion_limit():
    ok = b"[" * 20 + b"]" * 20
    deep = b"[" * 40 + b"]" * 40
    assert loads(ok) is not None
    assert loads(deep, max_depth=32) is None
