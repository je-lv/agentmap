from fakeserver import Reply
from helpers import probe, run
from mcpfake import JSONRPC_HINT, serve_mcp

from agentmap.protocols import mcp as mcpmod
from agentmap.protocols.mcp import MCPProtocol


def ids(findings):
    return sorted({f.rule_id for f in findings})


def kinds(obs):
    return [o.kind for o in obs]


def test_bearer_check_excludes_an_auth_file_api_key_header(fake, tmp_path):
    # A server authenticated by a non-Authorization header (e.g. an
    # --auth-file configured as {"X-API-Key": "..."}) must not let that
    # real, valid credential ride along on the forged-bearer-token probe --
    # otherwise the server accepts the request because of the real header
    # it never even inspects the fake Authorization header, and agentmap
    # wrongly reports AM-MCP-010 ("invalid bearer token accepted").
    def post(req):
        msg = req.json if isinstance(req.json, dict) else {}
        if req.headers.get("x-api-key") != "valid-key":
            return Reply(401, b"", {"WWW-Authenticate": "Bearer"})
        if msg.get("method") == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "demo-mcp", "version": "1.0.0"}}
            return Reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": result},
                         {"Mcp-Session-Id": "sess-1"})
        return Reply(202, b"")

    fake.route("GET", "/mcp", Reply(405, JSONRPC_HINT))
    fake.route("POST", "/mcp", post)
    fake.route("DELETE", "/mcp", Reply(200, b""))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active",
                       headers={"X-API-Key": "valid-key"}))
    bearer = [o for o in obs if o.kind == "mcp.bearer_check"][0].data
    assert bearer["accepted"] is False
    assert "AM-MCP-010" not in ids(MCPProtocol().analyze(obs))


def test_bearer_check_excludes_a_lowercase_authorization_default_header(fake, tmp_path):
    # httpx does not deduplicate header dicts that differ only by key case:
    # a default {"authorization": "Bearer good"} and an explicit
    # {"Authorization": "Bearer bad"} would otherwise both go out on the
    # wire, and a server reading either one would accept the request on the
    # real token -- again a false AM-MCP-010.
    def post(req):
        msg = req.json if isinstance(req.json, dict) else {}
        if req.headers.get("authorization") != "Bearer good":
            return Reply(401, b"", {"WWW-Authenticate": "Bearer"})
        if msg.get("method") == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "demo-mcp", "version": "1.0.0"}}
            return Reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": result},
                         {"Mcp-Session-Id": "sess-1"})
        return Reply(202, b"")

    fake.route("GET", "/mcp", Reply(405, JSONRPC_HINT))
    fake.route("POST", "/mcp", post)
    fake.route("DELETE", "/mcp", Reply(200, b""))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active",
                       headers={"authorization": "Bearer good"}))
    bearer = [o for o in obs if o.kind == "mcp.bearer_check"][0].data
    assert bearer["accepted"] is False
    assert "AM-MCP-010" not in ids(MCPProtocol().analyze(obs))


def test_probe_level_sends_no_active_probes(fake, tmp_path):
    serve_mcp(fake)
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="probe"))
    assert not {"mcp.origin_check", "mcp.version_check", "mcp.bearer_check"} & set(kinds(obs))
    assert all("origin" not in r.headers for r in fake.requests)
    assert all(not r.headers.get("authorization", "").startswith("Bearer agentmap")
               for r in fake.requests)


def test_origin_not_validated_is_flagged(fake, tmp_path):
    serve_mcp(fake, check_origin=False)
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    check = [o for o in obs if o.kind == "mcp.origin_check"][0].data
    assert check["accepted"] is True
    assert "AM-MCP-009" in ids(MCPProtocol().analyze(obs))


def test_origin_validated_is_clean(fake, tmp_path):
    serve_mcp(fake, check_origin=True)
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    check = [o for o in obs if o.kind == "mcp.origin_check"][0].data
    assert check["accepted"] is False and check["status"] == 403
    assert "AM-MCP-009" not in ids(MCPProtocol().analyze(obs))


def test_broken_bearer_validation_is_flagged(fake, tmp_path):
    serve_mcp(fake, auth="broken")
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    assert [o for o in obs if o.kind == "mcp.bearer_check"][0].data["accepted"] is True
    assert "AM-MCP-010" in ids(MCPProtocol().analyze(obs))


def test_strict_bearer_validation_is_clean(fake, tmp_path):
    serve_mcp(fake, auth="strict")
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    assert [o for o in obs if o.kind == "mcp.bearer_check"][0].data["accepted"] is False
    assert "AM-MCP-010" not in ids(MCPProtocol().analyze(obs))


def test_bearer_check_not_applicable_when_server_is_open(fake, tmp_path):
    serve_mcp(fake)
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    assert "mcp.bearer_check" not in kinds(obs)


def test_version_header_check_records_status_only(fake, tmp_path):
    serve_mcp(fake)
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    check = [o for o in obs if o.kind == "mcp.version_check"][0]
    assert check.data["status"] == 200
    assert not any(f.rule_id.endswith("-VERSION") for f in MCPProtocol().analyze(obs))


def test_active_only_uses_allowed_methods_and_closes_every_session(fake, tmp_path):
    serve_mcp(fake)
    run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    assert set(fake.methods_seen()) <= mcpmod.ALLOWED_METHODS
    initializes = fake.methods_seen().count("initialize")
    deletes = [r for r in fake.requests if r.method == "DELETE"]
    assert initializes == 3 and len(deletes) == 3     # baseline, origin check, version check


def test_bad_session_id_from_active_check_is_not_echoed_back(fake, tmp_path):
    """A hostile server can return a session id containing a character outside the
    MCP spec's visible-ASCII range (0x21-0x7E). _try_initialize must validate it
    the same way _handshake does (via _valid_session), and must simply skip the
    DELETE rather than echo the raw value back into a later request header."""
    bad_session = "sess-évil"  # contains a non-ASCII character

    def post(req):
        msg = req.json if isinstance(req.json, dict) else {}
        if msg.get("method") == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "demo-mcp", "version": "1.0.0"}}
            return Reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": result},
                         {"Mcp-Session-Id": bad_session})
        return Reply(202, b"")

    fake.route("GET", "/mcp", Reply(405, JSONRPC_HINT))
    fake.route("POST", "/mcp", post)
    fake.route("DELETE", "/mcp", Reply(200, b""))
    obs, _ = run(probe(MCPProtocol(), fake, tmp_path, level="active"))
    assert [o for o in obs if o.kind == "mcp.origin_check"][0].data["accepted"] is True
    deletes = [r for r in fake.requests if r.method == "DELETE"]
    assert not deletes
    assert all(bad_session not in str(r.headers) for r in fake.requests)
