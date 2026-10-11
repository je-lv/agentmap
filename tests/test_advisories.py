from agentmap.advisories import match_advisories

ADV = [{
    "id": "TEST-1", "product": r"^acme-mcp$", "affected_below": "1.4.0",
    "fixed_in": "1.4.0", "reference": "https://example.invalid/adv/1",
    "summary": "test advisory",
}]


def test_affected_version_matches():
    got = match_advisories("acme-mcp", "1.3.9", ADV)
    assert [a["id"] for a in got] == ["TEST-1"]


def test_fixed_or_newer_version_does_not_match():
    assert match_advisories("acme-mcp", "1.4.0", ADV) == []
    assert match_advisories("acme-mcp", "2.0.0", ADV) == []


def test_other_product_does_not_match():
    assert match_advisories("other", "1.0.0", ADV) == []


def test_unparsable_version_does_not_match():
    assert match_advisories("acme-mcp", "latest", ADV) == []
    assert match_advisories("acme-mcp", "", ADV) == []


def test_product_regex_is_case_insensitive():
    assert match_advisories("ACME-MCP", "1.0.0", ADV)


def test_version_with_suffix():
    assert match_advisories("acme-mcp", "1.3.0-beta.2", ADV)
