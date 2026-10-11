from agentmap.diff import compare
from agentmap.findings import make_finding
from agentmap.protocols.base import Observation
from agentmap.store import RunStore


def seed(tmp_path, name, observations, findings):
    store = RunStore.new(tmp_path / name)
    for o in observations:
        store.add_observation(o)
    for f in findings:
        store.add_finding(f)
    return store


def test_new_and_removed_endpoints(tmp_path):
    a = seed(tmp_path, "a", [Observation("a2a.card", "http://h1:8000/x", {})], [])
    b = seed(tmp_path, "b", [Observation("a2a.card", "http://h2:8000/x", {})], [])
    d = compare(a, b)
    assert d["new_endpoints"] == ["h2:8000"] and d["removed_endpoints"] == ["h1:8000"]


def test_new_and_resolved_findings_ignore_detail_changes(tmp_path):
    a = seed(tmp_path, "a", [], [make_finding("AM-A2A-002", "http://h:1/", "high", detail="x")])
    b = seed(tmp_path, "b", [], [make_finding("AM-A2A-002", "http://h:1/", "high", detail="y"),
                                make_finding("AM-MCP-001", "http://h:2/", "medium")])
    d = compare(a, b)
    assert d["new_findings"] == [f.to_dict() for f in b.findings() if f.rule_id == "AM-MCP-001"]
    assert d["resolved_findings"] == []


def test_resolved_finding_detected(tmp_path):
    a = seed(tmp_path, "a", [], [make_finding("AM-MCP-002", "http://h:1/", "high")])
    b = seed(tmp_path, "b", [], [])
    assert len(compare(a, b)["resolved_findings"]) == 1


def test_auth_posture_change_flagged(tmp_path):
    a = seed(tmp_path, "a", [Observation("mcp.initialize", "http://h:1/mcp",
                                         {"auth_required": True})], [])
    b = seed(tmp_path, "b", [Observation("mcp.initialize", "http://h:1/mcp",
                                         {"auth_required": False})], [])
    changes = compare(a, b)["auth_posture_changes"]
    assert changes == [{"target": "http://h:1/mcp", "before": True, "after": False}]


def test_definition_change_detected_for_tools_and_skills(tmp_path):
    a = seed(tmp_path, "a", [Observation("mcp.inventory", "http://h:1/mcp",
                                         {"tools": [{"name": "run", "hash": "aaa"}],
                                          "resources": [], "prompts": []})], [])
    b = seed(tmp_path, "b", [Observation("mcp.inventory", "http://h:1/mcp",
                                         {"tools": [{"name": "run", "hash": "bbb"}],
                                          "resources": [], "prompts": []})], [])
    changes = compare(a, b)["definition_changes"]
    assert changes == [{"target": "http://h:1/mcp", "kind": "tools", "name": "run"}]


def test_definition_change_detected_for_a2a_card_fingerprint(tmp_path):
    # AM-A2A rug-pull detection: a2a.py already computes a `fingerprint` hash
    # of a card's skills on every a2a.card observation, but diff.py never
    # read it, so a changed skill/tool definition between two runs never
    # showed up in definition_changes the way an MCP tool-hash change does.
    a = seed(tmp_path, "a", [Observation("a2a.card", "http://h:1/agent", {"fingerprint": "aaa"})], [])
    b = seed(tmp_path, "b", [Observation("a2a.card", "http://h:1/agent", {"fingerprint": "bbb"})], [])
    changes = compare(a, b)["definition_changes"]
    assert changes == [{"target": "http://h:1/agent", "kind": "card", "name": "skills"}]


def test_auth_posture_change_flagged_a2a(tmp_path):
    a = seed(tmp_path, "a", [Observation("a2a.card", "http://h:1/agent",
                                         {"auth_declared": True})], [])
    b = seed(tmp_path, "b", [Observation("a2a.card", "http://h:1/agent",
                                         {"auth_declared": False})], [])
    changes = compare(a, b)["auth_posture_changes"]
    assert changes == [{"target": "http://h:1/agent", "before": True, "after": False}]


def test_no_changes_gives_empty_diff(tmp_path):
    obs = Observation("a2a.card", "http://h:1/x", {})
    a = seed(tmp_path, "a", [obs], [])
    b = seed(tmp_path, "b", [obs], [])
    d = compare(a, b)
    assert all(not v for v in d.values())
