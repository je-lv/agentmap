from agentmap import datafiles
from agentmap.targets import parse_ports


def test_paths_contract():
    paths = datafiles.load("paths")
    assert paths["a2a"]["card_paths"][0] == "/.well-known/agent-card.json"
    assert "/.well-known/agent.json" in paths["a2a"]["card_paths"]
    assert "/mcp" in paths["mcp"]["endpoint_paths"]
    assert paths["mcp"]["oauth_resource_path"] == "/.well-known/oauth-protected-resource"
    for fp in paths["mcp"]["fingerprints"]:
        assert fp["path"].startswith("/") and fp["body_contains"] and fp["product"]


def test_ports_presets_parse_and_are_sane():
    presets = datafiles.ports_presets()
    assert {"agent-default", "web"} <= set(presets)
    for name, ports in presets.items():
        assert len(ports) == len(set(ports))
        assert all(1 <= p <= 65535 for p in ports)
    default = presets["agent-default"]
    assert 8000 in default and 8010 in default      # the old script's range stays covered
    assert 6274 in default and 6275 in default      # MCP inspector web UI and v2 sandbox port
    assert parse_ports("agent-default", presets) == default


def test_load_is_cached_and_empty_advisories_ok():
    assert datafiles.load("paths") is datafiles.load("paths")
    adv = datafiles.load("advisories") or []
    assert isinstance(adv, list)
    for entry in adv:
        assert {"id", "product", "affected_below", "fixed_in", "reference", "summary"} <= set(entry)
        assert entry["reference"].startswith("https://")
