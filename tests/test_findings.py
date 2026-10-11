import pytest
from agentmap.findings import (
    REGISTRY, SEVERITIES, Finding, make_finding, severity_rank,
)


def test_registry_populated_on_import():
    assert len(REGISTRY) == 21
    assert "AM-A2A-001" in REGISTRY and "AM-MCP-012" in REGISTRY


def test_every_rule_is_documented():
    for rule in REGISTRY.values():
        assert rule.title and rule.description and rule.remediation and rule.rationale
        assert rule.severity in SEVERITIES
        assert rule.level in ("passive", "probe", "active")
        assert rule.protocol in ("a2a", "mcp")
        assert rule.id.startswith("AM-" + rule.protocol.upper() + "-")


def test_make_finding_copies_rule_text_and_ids_are_stable():
    a = make_finding("AM-A2A-002", "http://h:1/x", "high", detail="d")
    b = make_finding("AM-A2A-002", "http://h:1/x", "high", detail="d")
    assert a.id == b.id
    assert a.severity == REGISTRY["AM-A2A-002"].severity
    assert a.title == REGISTRY["AM-A2A-002"].title
    c = make_finding("AM-A2A-002", "http://h:1/x", "high", detail="other")
    assert c.id != a.id


def test_overrides_are_validated():
    with pytest.raises(ValueError):
        make_finding("AM-A2A-001", "t", severity="bogus")
    with pytest.raises(ValueError):
        make_finding("AM-A2A-001", "t", "certain")
    assert make_finding("AM-MCP-003", "t", severity="critical").severity == "critical"


def test_roundtrip_dict():
    f = make_finding("AM-MCP-001", "u", "high", detail="transport=streamable-http")
    assert Finding.from_dict(f.to_dict()) == f


def test_severity_rank_orders():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
