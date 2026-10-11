from agentmap.scope import Scope
from agentmap.targets import make_excluder


def test_hosts_urls_and_networks_in_scope():
    s = Scope.from_items(["a.example", "https://b.example:8443/x", "10.0.0.0/30", "[::1]:80"])
    assert s.allows_host("A.example") and s.allows_host("b.example")
    assert s.allows_host("10.0.0.2") and not s.allows_host("10.0.0.9")
    assert s.allows_host("::1")
    assert not s.allows_host("c.example")


def test_allows_url_uses_hostname_only():
    s = Scope.from_items(["a.example"])
    assert s.allows_url("http://a.example:9999/anything")
    assert not s.allows_url("http://evil.example/")
    assert not s.allows_url("not a url")


def test_excluded_host_inside_scope_network_is_refused():
    ex = make_excluder(["10.0.0.2"])
    s = Scope.from_items(["10.0.0.0/29"], excluder=ex)
    assert s.allows_host("10.0.0.3") and not s.allows_host("10.0.0.2")


def test_refuse_records_and_dedupes():
    s = Scope.from_items(["a.example"])
    s.refuse("http://x.example/", "out of scope", "redirect from http://a.example/")
    s.refuse("http://x.example/", "out of scope", "redirect from http://a.example/")
    assert len(s.refused) == 1
    assert s.refused[0]["url"] == "http://x.example/"


def test_ipv6_normalised():
    s = Scope.from_items(["0:0:0:0:0:0:0:1"])
    assert s.allows_host("::1")
