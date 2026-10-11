from agentmap.protocols.base import Endpoint, Observation


def test_endpoint_urls():
    ep = Endpoint("https", "h.example", 8443, "/api")
    assert ep.origin == "https://h.example:8443"
    assert ep.base == "https://h.example:8443/api"
    assert ep.url("/mcp") == "https://h.example:8443/api/mcp"


def test_endpoint_ipv6_is_bracketed():
    assert Endpoint("http", "::1", 80).origin == "http://[::1]:80"


def test_observation_roundtrip():
    o = Observation("k", "http://h:1/", {"a": 1}, ["evidence/x"])
    assert Observation.from_dict(o.to_dict()) == o
