import pytest
from agentmap.targets import (
    LARGE_SCAN_THRESHOLD, MAX_HOSTS, Target, estimate_hosts, expand_item,
    iter_targets, make_excluder, parse_ports, read_target_file,
)


def test_parse_ports_mixed_and_deduped():
    assert parse_ports("80,443,8000-8002,80") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_preset():
    assert parse_ports("web,9000", {"web": [80, 443]}) == [80, 443, 9000]


@pytest.mark.parametrize("bad", ["", "abc", "0", "70000", "9-3", "80,,x"])
def test_parse_ports_rejects(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_host_and_host_port():
    assert list(expand_item("Example.COM")) == [Target("example.com")]
    assert list(expand_item("10.0.0.5:8080")) == [Target("10.0.0.5", 8080)]


def test_naabu_style_lines_work():
    assert list(iter_targets(["10.0.0.5:8000", "10.0.0.5:8001"])) == [
        Target("10.0.0.5", 8000), Target("10.0.0.5", 8001)]


def test_url_with_path_prefix():
    t = list(expand_item("https://h.example:8443/api/"))[0]
    assert t == Target("h.example", 8443, "https", "/api")
    t = list(expand_item("http://h.example/"))[0]
    assert t == Target("h.example", 80, "http", "")


def test_unsupported_scheme_rejected():
    with pytest.raises(ValueError):
        list(expand_item("ftp://h/x"))


def test_ipv6_forms():
    assert list(expand_item("[::1]:8000")) == [Target("::1", 8000)]
    assert list(expand_item("::1")) == [Target("::1")]
    assert list(expand_item("http://[::1]:9000/"))[0] == Target("::1", 9000, "http", "")
    assert Target("::1", 8000).netloc == "[::1]:8000"


def test_cidr_excludes_network_and_broadcast():
    got = [t.host for t in expand_item("10.0.0.0/30")]
    assert got == ["10.0.0.1", "10.0.0.2"]


def test_cidr_31_and_32_edge_sizes():
    assert [t.host for t in expand_item("10.0.0.0/31")] == ["10.0.0.0", "10.0.0.1"]
    assert [t.host for t in expand_item("10.0.0.7/32")] == ["10.0.0.7"]
    assert estimate_hosts(["10.0.0.0/31", "10.0.0.7/32"]) == 3


def test_estimate_and_thresholds():
    assert estimate_hosts(["10.0.0.0/24"]) == 254
    assert estimate_hosts(["10.0.0.0/21"]) > LARGE_SCAN_THRESHOLD
    assert estimate_hosts(["a.example", "b.example"]) == 2
    assert estimate_hosts(["10.0.0.0/8"]) > MAX_HOSTS


def test_dedupe_and_comments_and_blank():
    items = ["a.example", "A.example", "# note", "", "a.example:80", "b.example # tail"]
    assert [t.host for t in iter_targets(items)] == ["a.example", "a.example", "b.example"]


def test_excluder_hosts_and_networks():
    ex = make_excluder(["10.0.0.5", "192.168.1.0/24", "skip.example"])
    assert ex("10.0.0.5") and ex("192.168.1.77") and ex("SKIP.example")
    assert not ex("10.0.0.6") and not ex("other.example")


def test_excluder_invalid_cidr_raises_instead_of_silently_doing_nothing():
    # An invalid CIDR passed to make_excluder (e.g. via --exclude) must be a
    # clean error, not silently ignored -- a silently-ignored exclusion is
    # indistinguishable from "nothing was excluded."
    with pytest.raises(ValueError):
        make_excluder(["10.0.0.0/99"])


def test_excluder_normalizes_ipv6_long_form_like_scope_does():
    # An IPv6 long-form address must exclude its canonical short-form
    # equivalent, the same way Scope normalizes hosts.
    ex = make_excluder(["0000:0000:0000:0000:0000:0000:0000:0001"])
    assert ex("::1")
    assert ex("0:0:0:0:0:0:0:1")


def test_read_target_file(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# c\nhost-a.example\n\n10.0.0.0/30  # cidr\n")
    assert read_target_file(p) == ["host-a.example", "10.0.0.0/30"]


def test_host_port_out_of_range():
    """Port validation for host:port and [ipv6]:port forms."""
    with pytest.raises(ValueError, match="port out of range"):
        list(expand_item("host:99999"))
    with pytest.raises(ValueError, match="port out of range"):
        list(expand_item("[::1]:99999"))


def test_target_netloc_with_port_zero():
    """Target.netloc should render port=0 correctly."""
    assert Target("h", 0).netloc == "h:0"
    assert Target("::1", 0).netloc == "[::1]:0"


def test_estimate_hosts_ipv6_cidr():
    """estimate_hosts should count IPv6 CIDR hosts correctly."""
    ipv6_hosts = list(expand_item("fe80::/126"))
    estimated = estimate_hosts(["fe80::/126"])
    assert len(ipv6_hosts) == 3
    assert estimated == 3
