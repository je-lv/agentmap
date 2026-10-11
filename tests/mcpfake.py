import json

from fakeserver import Reply

JSONRPC_HINT = {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32000, "message": "Method not allowed, use POST"}}


def _ok(msg, result, headers=None, sse=False):
    body = {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}
    if sse:
        return Reply(200, sse=[("message", json.dumps(body))], headers=headers)
    return Reply(200, body, headers)


def serve_mcp(fake, *, tools=(), resources=(), prompts=(), caps=None,
              server=("demo-mcp", "1.0.0"), instructions=None, session="sess-1",
              auth=None, check_origin=False, endless_cursor=False,
              sse_responses=False, path="/mcp"):
    capabilities = caps if caps is not None else {"tools": {}, "resources": {}, "prompts": {}}

    def post(req):
        msg = req.json if isinstance(req.json, dict) else {}
        method = msg.get("method")
        header = req.headers.get("authorization", "")
        if auth == "strict" and header != "Bearer good-token":
            return Reply(401, b"", {"WWW-Authenticate": "Bearer"})
        if auth == "broken" and not header.startswith("Bearer "):
            return Reply(401, b"", {"WWW-Authenticate": "Bearer"})
        if check_origin and "origin" in req.headers:
            return Reply(403, {"error": "bad origin"})
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": capabilities,
                      "serverInfo": {"name": server[0], "version": server[1]}}
            if instructions:
                result["instructions"] = instructions
            return _ok(msg, result, {"Mcp-Session-Id": session}, sse_responses)
        if method == "notifications/initialized":
            return Reply(202, b"")
        if method == "tools/list":
            result = {"tools": list(tools)}
            if endless_cursor:
                result["nextCursor"] = "c"
            return _ok(msg, result, sse=sse_responses)
        if method == "resources/list":
            return _ok(msg, {"resources": list(resources)}, sse=sse_responses)
        if method == "prompts/list":
            return _ok(msg, {"prompts": list(prompts)}, sse=sse_responses)
        return Reply(400, {"jsonrpc": "2.0", "id": msg.get("id"),
                           "error": {"code": -32601, "message": "unsupported"}})

    fake.route("GET", path, Reply(405, JSONRPC_HINT))
    fake.route("POST", path, post)
    fake.route("DELETE", path, Reply(200, b""))
    return fake
