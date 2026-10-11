import json

from agentmap.ingest import from_httpx_jsonl, from_naabu, from_nmap_xml
from agentmap.targets import Target

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="8000"><state state="open"/></port>
    <port protocol="tcp" portid="8001"><state state="closed"/></port>
    <port protocol="tcp" portid="8443"><state state="filtered"/></port>
  </ports>
</host>
<host><address addr="10.0.0.6" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
</host>
</nmaprun>
"""


def test_from_nmap_xml_only_open_ports(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(NMAP_XML)
    assert sorted(from_nmap_xml(p), key=lambda t: (t.host, t.port)) == [
        Target("10.0.0.5", 8000), Target("10.0.0.6", 443)]


def test_from_nmap_xml_missing_file_returns_empty(tmp_path):
    assert from_nmap_xml(tmp_path / "nope.xml") == []


def test_from_nmap_xml_malformed_returns_empty(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("not xml")
    assert from_nmap_xml(p) == []


def test_from_httpx_jsonl_url_form(tmp_path):
    p = tmp_path / "h.jsonl"
    p.write_text("\n".join([
        json.dumps({"url": "https://10.0.0.5:8443/"}),
        json.dumps({"host": "10.0.0.6", "port": 8080, "scheme": "http"}),
        "not json",
        json.dumps({"no": "useful fields"}),
    ]))
    assert from_httpx_jsonl(p) == [
        Target("10.0.0.5", 8443, "https", ""), Target("10.0.0.6", 8080, "http", "")]


def test_from_naabu_plain_and_json_lines(tmp_path):
    p = tmp_path / "n.txt"
    p.write_text("10.0.0.5:8000\n" + json.dumps({"host": "10.0.0.6", "port": 8001}) + "\nbad line\n")
    assert from_naabu(p) == [Target("10.0.0.5", 8000), Target("10.0.0.6", 8001)]
