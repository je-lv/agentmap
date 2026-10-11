from fakeserver import Reply
from helpers import probe, run

from agentmap.protocols.mcp import MCPProtocol


def kinds(obs):
    return [o.kind for o in obs]


def ids(findings):
    return sorted(f.rule_id for f in findings)


def test_legacy_sse_transport_detected(fake, tmp_path):
    fake.route("GET", "/sse", Reply(200, sse=[("endpoint", "/messages?session=1")], sse_hold=0.3))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == ["mcp.endpoint"]
    assert obs[0].data["transport"] == "sse-legacy" and obs[0].data["confidence"] == "high"
    assert ids(MCPProtocol().analyze(obs)) == ["AM-MCP-001", "AM-MCP-008"]


def test_streamable_http_hint_from_405_with_jsonrpc_body(fake, tmp_path):
    fake.route("GET", "/mcp", Reply(405, {"jsonrpc": "2.0", "id": None,
                                          "error": {"code": -32000, "message": "use POST"}}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs[0].data["transport"] == "streamable-http" and obs[0].data["confidence"] == "medium"
    assert ids(MCPProtocol().analyze(obs)) == ["AM-MCP-001"]


def test_plain_405_is_not_mcp(fake, tmp_path):
    fake.route("GET", "/mcp", Reply(405, b"Method Not Allowed"))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_catch_all_html_and_json_give_no_match(fake, tmp_path):
    fake.default = Reply(200, "<html>spa</html>", {"Content-Type": "text/html"})
    assert run(probe(MCPProtocol(), fake, tmp_path))[0] == []
    fake.default = Reply(200, {"name": "x", "status": "ok"})
    assert run(probe(MCPProtocol(), fake, tmp_path))[0] == []


def test_401_with_resource_metadata_pulls_oauth_documents(fake, tmp_path):
    base = f"http://{fake.host}:{fake.port}"
    wa = f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'
    fake.route("GET", "/mcp", Reply(401, b"", {"WWW-Authenticate": wa}))
    fake.route("GET", "/.well-known/oauth-protected-resource",
               Reply(200, {"resource": f"{base}/mcp", "authorization_servers": [base]}))
    fake.route("GET", "/.well-known/oauth-authorization-server",
               Reply(200, {"issuer": base, "authorization_endpoint": f"{base}/authorize",
                           "token_endpoint": f"{base}/token"}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == ["mcp.endpoint", "mcp.oauth_resource", "mcp.oauth_as"]
    assert obs[0].data["confidence"] == "medium"
    got = ids(MCPProtocol().analyze(obs))
    assert got == ["AM-MCP-001", "AM-MCP-007"]          # no S256 advertised
    assert {r.method for r in fake.requests} == {"GET"}


def test_401_without_resource_metadata_is_low_confidence_and_flagged(fake, tmp_path):
    fake.route("GET", "/mcp", Reply(401, b"", {"WWW-Authenticate": "Bearer"}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs[0].data["confidence"] == "low"
    assert ids(MCPProtocol().analyze(obs)) == ["AM-MCP-001", "AM-MCP-006"]


def test_resource_metadata_url_outside_scope_is_never_requested(fake, tmp_path):
    wa = 'Bearer resource_metadata="http://203.0.113.9:9/.well-known/oauth-protected-resource"'
    fake.route("GET", "/mcp", Reply(401, b"", {"WWW-Authenticate": wa}))
    obs, ctx = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == ["mcp.endpoint"]
    assert any(r["url"].startswith("http://203.0.113.9:9/") for r in ctx.http.scope.refused)


def test_authorization_server_on_another_host_is_refused_not_fetched(fake, tmp_path):
    base = f"http://{fake.host}:{fake.port}"
    fake.route("GET", "/mcp", Reply(401, b"", {"WWW-Authenticate": "Bearer"}))
    fake.route("GET", "/.well-known/oauth-protected-resource",
               Reply(200, {"resource": base, "authorization_servers": ["https://auth.elsewhere.invalid"]}))
    obs, ctx = run(probe(MCPProtocol(), fake, tmp_path))
    assert "mcp.oauth_as" not in kinds(obs)
    assert any("auth.elsewhere.invalid" in r["url"] for r in ctx.http.scope.refused)


def test_inspector_ui_fingerprint(fake, tmp_path):
    fake.route("GET", "/", Reply(200, "<html><title>MCP Inspector</title></html>",
                                 {"Content-Type": "text/html"}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == ["mcp.devtool"]
    assert ids(MCPProtocol().analyze(obs)) == ["AM-MCP-012"]


def test_passive_probe_sends_only_get(fake, tmp_path):
    fake.route("GET", "/sse", Reply(200, sse=[("endpoint", "/m")], sse_hold=0.2))
    run(probe(MCPProtocol(), fake, tmp_path, level="passive"))
    assert {r.method for r in fake.requests} == {"GET"}


# -- Adversarial non-MCP-server probes beyond the brief's test list --------
# These exist to catch the specific failure mode a reviewer found in the A2A
# plugin (Task 10): a classifier that "looks like" it rejects ordinary web
# servers but actually produces a false-positive mcp.endpoint observation for
# some plausible non-MCP shape.

def test_plain_404_is_not_mcp(fake, tmp_path):
    fake.route("GET", "/mcp", Reply(404, b"Not Found"))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_plain_500_error_page_is_not_mcp(fake, tmp_path):
    fake.default = Reply(500, "<html><body>Internal Server Error</body></html>",
                         {"Content-Type": "text/html"})
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_redirect_is_not_mcp(fake, tmp_path):
    # sse_first_event does not follow redirects; a 3xx must never be
    # misclassified as an MCP endpoint just because some path "responded".
    fake.route("GET", "/mcp", Reply(302, b"", {"Location": "/login"}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_200_json_with_incidental_jsonrpc_substring_is_not_mcp(fake, tmp_path):
    # A 200 response is only ever classified via the SSE branch; a generic
    # 200 JSON body that happens to mention "jsonrpc" (e.g. a tool/service
    # description, not an actual JSON-RPC error) must not trigger a match.
    fake.default = Reply(200, {"name": "jsonrpc-cli", "description": "a jsonrpc helper tool"})
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_generic_json_api_404_with_jsonrpc_mention_is_not_mcp(fake, tmp_path):
    # A 404 (not one of the 400/405/406 "endpoint exists but rejects GET"
    # statuses) must never match even if the body mentions a hint string.
    fake.route("GET", "/mcp", Reply(404, {"error": "no such jsonrpc route"}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert obs == []


def test_401_on_unrelated_path_without_pointer_is_not_flagged(fake, tmp_path):
    # A bare 401 on a path that is neither a configured MCP path nor carries
    # a resource_metadata pointer still only matches on /mcp or /sse; here we
    # confirm "/" alone (no /mcp, /sse routes) with a 401 and no pointer does
    # not falsely report high/medium confidence -- it's low or absent.
    fake.route("GET", "/", Reply(401, b"", {"WWW-Authenticate": "Basic realm=\"x\""}))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == []


def test_sse_stream_without_endpoint_event_is_low_confidence_not_high(fake, tmp_path):
    # A generic SSE feed unrelated to MCP (no legacy "endpoint" event) must
    # not be classified as the high-confidence legacy transport.
    fake.route("GET", "/sse", Reply(200, sse=[("tick", "1")], sse_hold=0.2))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path))
    assert kinds(obs) == ["mcp.endpoint"]
    assert obs[0].data["transport"] == "streamable-http"
    assert obs[0].data["confidence"] == "low"
