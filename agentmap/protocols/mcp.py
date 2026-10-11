"""MCP endpoint discovery, handshake, inventory, auth posture and analysis."""
from __future__ import annotations

import hashlib
import itertools
import json
import re

from .. import __version__, datafiles, jsonsafe
from ..advisories import match_advisories
from ..analysis.authposture import as_metadata_url, assess_oauth_as, parse_www_authenticate
from ..analysis.poisoning import scan_text
from ..analysis.secrets import redact_text, scan_json
from ..analysis.toolrisk import HIGH_RISK, classify_tool
from ..findings import make_finding
from ..http import SseResult
from ..levels import allows
from ..sse import parse_events
from .base import Endpoint, Observation, ProbeContext, Protocol

SSE_WAIT = 2.0
PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 5
MAX_ITEMS = 500
BODY_HINTS = ("jsonrpc", "text/event-stream", "mcp-session-id",
              "mcp-protocol-version", "modelcontextprotocol")

# The complete set of JSON-RPC methods agentmap can ever construct. This is a
# passive/read-only discovery scanner: it must be architecturally impossible
# for it to invoke a tool, read a resource, fetch a prompt or send a message
# on a target system. rpc() below is the only place a JSON-RPC message body
# is built, and it enforces this allowlist on every call.
ALLOWED_METHODS = frozenset({
    "initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list"})


class ForbiddenMethod(Exception):
    """Raised when code tries to build a JSON-RPC method outside the allowlist."""


def rpc(method: str, *, id: int | None = None, params: dict | None = None) -> bytes:
    if method not in ALLOWED_METHODS:
        raise ForbiddenMethod(method)
    message: dict = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        message["id"] = id
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode()


def rpc_result(resp) -> dict | None:
    """The JSON-RPC response object in a JSON body or the first matching SSE event."""
    if resp.status != 200:
        return None
    content_type = resp.headers.get("content-type", "")
    text = resp.text()
    if "text/event-stream" in content_type or text.lstrip().startswith(("event:", "data:", ":")):
        for _event, data in parse_events(text):
            obj = jsonsafe.loads(data)
            if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                return obj
        return None
    obj = jsonsafe.loads(resp.body)
    return obj if isinstance(obj, dict) else None


def _post_headers(session: str | None = None, version: str | None = None) -> dict:
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if session:
        headers["Mcp-Session-Id"] = session
    if version:
        headers["MCP-Protocol-Version"] = version
    return headers


def _init_body(request_id: int = 1) -> bytes:
    return rpc("initialize", id=request_id, params={
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "agentmap", "version": __version__}})


_VERSION_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _valid_protocol_version(value: object) -> str:
    """The server's negotiated protocolVersion if it matches the spec's YYYY-MM-DD
    wire format, else our own constant. This value is echoed back verbatim into the
    MCP-Protocol-Version request header on every later request, so an unvalidated
    server-supplied string here is a header-injection / non-ASCII-header crash vector."""
    if isinstance(value, str) and _VERSION_RE.fullmatch(value):
        return value
    return PROTOCOL_VERSION


def _valid_session(value: object) -> str | None:
    """The server's Mcp-Session-Id if every character is in the visible-ASCII range
    the MCP spec requires (0x21-0x7E), else None (treated as if no session was
    issued: no Mcp-Session-Id header is sent later, and no DELETE is attempted).
    Same rationale as _valid_protocol_version: this value is echoed into a header."""
    if isinstance(value, str) and value and all(0x21 <= ord(c) <= 0x7E for c in value):
        return value
    return None


def _strings(obj, depth=0):
    if depth > 32:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _strings(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            yield from _strings(value, depth + 1)


def _scan_item(where: str, item) -> tuple[list[dict], list[dict]]:
    kinds: set[str] = set()
    for text in _strings(item):
        kinds.update(scan_text(text))
    indicators = [{"where": where, "kinds": sorted(kinds)}] if kinds else []
    return indicators, scan_json(item, where)


def _hash(item) -> str:
    return hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _text(value, limit=500) -> str:
    return redact_text(value)[:limit] if isinstance(value, str) else ""


def _classify_get(url: str, path: str, res: SseResult) -> Observation | None:
    content_type = res.headers.get("content-type", "")
    www = parse_www_authenticate(res.headers.get("www-authenticate", ""))
    base = {"path": path, "status": res.status, "www_authenticate": www}
    if res.status == 200 and "text/event-stream" in content_type:
        if res.event == "endpoint":
            return Observation("mcp.endpoint", url, {
                **base, "transport": "sse-legacy", "confidence": "high",
                "message_endpoint": res.data[:256]})
        return Observation("mcp.endpoint", url, {
            **base, "transport": "streamable-http", "confidence": "low"})
    head = res.body_head.decode("utf-8", errors="replace").lower()
    if res.status in (400, 405, 406) and any(h in head for h in BODY_HINTS):
        return Observation("mcp.endpoint", url, {
            **base, "transport": "streamable-http", "confidence": "medium"})
    if res.status == 401:
        if www.get("params", {}).get("resource_metadata"):
            return Observation("mcp.endpoint", url, {
                **base, "transport": "streamable-http", "confidence": "medium"})
        if path in ("/mcp", "/sse"):
            return Observation("mcp.endpoint", url, {
                **base, "transport": "streamable-http", "confidence": "low"})
    return None


class MCPProtocol(Protocol):
    name = "mcp"
    min_level = "passive"

    async def probe(self, ep: Endpoint, ctx: ProbeContext) -> list[Observation]:
        cfg = datafiles.load("paths")["mcp"]
        found: list[Observation] = []
        for path in cfg["endpoint_paths"]:
            url = ep.url(path)
            res = await ctx.http.sse_first_event(url, wait=SSE_WAIT)
            obs = _classify_get(url, path, res)
            if obs:
                found.append(obs)
        out = list(found)
        out += await self._fingerprints(ep, ctx, cfg)
        if found:
            out += await self._oauth(ep, ctx, found, cfg)
        if found and allows(ctx.level, "probe"):
            for endpoint_obs in found:
                if endpoint_obs.data["transport"] == "streamable-http":
                    out += await self._handshake(ep, ctx, endpoint_obs)
        if found and allows(ctx.level, "active"):
            for endpoint_obs in found:
                if endpoint_obs.data["transport"] == "streamable-http":
                    out += await self._active(ctx, endpoint_obs, out)
        return out

    # -- passive helpers (see Task 11) ----------------------------------
    async def _fingerprints(self, ep, ctx, cfg) -> list[Observation]:
        out = []
        for fp in cfg.get("fingerprints", []):
            url = ep.url(fp["path"])
            resp = await ctx.http.request("GET", url, headers={"Accept": "text/html"})
            if resp.ok and resp.status == 200 and fp["body_contains"].lower() in resp.text().lower():
                out.append(Observation("mcp.devtool", url, {"product": fp["product"]}))
        return out

    async def _oauth(self, ep, ctx, found, cfg) -> list[Observation]:
        resource_path = cfg["oauth_resource_path"]
        urls: list[str] = []
        for o in found:
            pointer = o.data["www_authenticate"].get("params", {}).get("resource_metadata")
            if pointer:
                urls.append(pointer)
        urls.append(ep.origin + resource_path)
        for o in found:
            if o.data["path"] not in ("", "/"):
                urls.append(ep.origin + resource_path + o.data["path"])
        out: list[Observation] = []
        issuers: list[str] = []
        for url in dict.fromkeys(urls):
            resp = await ctx.http.request("GET", url, headers={"Accept": "application/json"})
            meta = resp.json() if resp.ok and resp.status == 200 else None
            if not isinstance(meta, dict) or not ("authorization_servers" in meta or "resource" in meta):
                continue
            ref = ctx.evidence(f"mcp-oauth-resource-{ep.host}-{ep.port}.json", resp.body)
            servers = [s for s in meta.get("authorization_servers", []) if isinstance(s, str)][:5]
            out.append(Observation("mcp.oauth_resource", url, {
                "resource": meta.get("resource") if isinstance(meta.get("resource"), str) else None,
                "authorization_servers": servers}, [ref]))
            issuers.extend(servers)
        for issuer in dict.fromkeys(issuers):
            meta_url = as_metadata_url(issuer)
            resp = await ctx.http.request("GET", meta_url, headers={"Accept": "application/json"})
            meta = resp.json() if resp.ok and resp.status == 200 else None
            if not isinstance(meta, dict):
                continue
            ref = ctx.evidence(f"mcp-oauth-as-{ep.host}-{ep.port}.json", resp.body)
            methods = meta.get("code_challenge_methods_supported")
            out.append(Observation("mcp.oauth_as", meta_url, {
                "issuer": meta.get("issuer") if isinstance(meta.get("issuer"), str) else None,
                "weaknesses": assess_oauth_as(meta),
                "methods": methods if isinstance(methods, list) else None,
            }, [ref]))
        return out

    # -- probe level ----------------------------------------------------
    async def _unauthenticated_requires_auth(self, ctx, url: str) -> bool:
        """A credential-free initialize, used only to recheck whether an
        endpoint truly requires auth after the real handshake succeeded while
        default headers (--auth-file / --header) were configured. Sent with
        exclude_default_headers so it reflects the endpoint's real,
        unauthenticated posture rather than whatever the scan's configured
        credentials happen to unlock."""
        resp = await ctx.http.request(
            "POST", url, headers=_post_headers(), content=_init_body(request_id=0),
            exclude_default_headers=True)
        session = _valid_session(resp.headers.get("mcp-session-id"))
        if session:
            await ctx.http.request("DELETE", url, headers={
                "Mcp-Session-Id": session, "MCP-Protocol-Version": PROTOCOL_VERSION},
                exclude_default_headers=True)
        return resp.status in (401, 403)

    async def _handshake(self, ep, ctx, endpoint_obs) -> list[Observation]:
        url = endpoint_obs.target
        ids = itertools.count(1)
        resp = await ctx.http.request(
            "POST", url, headers=_post_headers(),
            content=rpc("initialize", id=next(ids), params={
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "agentmap", "version": __version__}}))
        ref = ctx.evidence(f"mcp-initialize-{ep.host}-{ep.port}.json", resp.body)
        # Validate anything the server hands us before it is ever echoed back
        # into a request header: an unvalidated session id or protocol
        # version string can make a later header-building call raise (a
        # non-ASCII value) or can wedge every later request on this
        # connection (a CRLF-shaped value), either of which would otherwise
        # abort the whole probe and/or leak the session server-side.
        session = _valid_session(resp.headers.get("mcp-session-id"))
        negotiated = PROTOCOL_VERSION
        auth_required = resp.status in (401, 403)
        if not auth_required and ctx.http.has_default_headers:
            # The call above may have carried --auth-file (or --header)
            # credentials, so a successful (non-401/403) status here only
            # proves "the configured credentials work," never "this endpoint
            # is open." Re-check with a credential-free initialize before
            # ever reporting AM-MCP-002 ("completes initialize without
            # credentials") -- otherwise a valid --auth-file turns every
            # properly-authenticated server into a false high-severity
            # finding.
            auth_required = await self._unauthenticated_requires_auth(ctx, url)
        data = {
            "status": resp.status, "error": resp.error,
            "www_authenticate": parse_www_authenticate(resp.headers.get("www-authenticate", "")),
            "auth_required": auth_required, "initialized": False,
            "server_name": "", "server_version": "", "protocol_version": "",
            "capabilities": [], "session": False, "instructions": "",
            "tools_count": 0, "resources_count": 0, "prompts_count": 0,
            "truncated": False, "indicators": [], "secrets": [],
        }
        try:
            message = rpc_result(resp)
            result = message.get("result") if message else None
            if not isinstance(result, dict):
                return [Observation("mcp.initialize", url, data, [ref])]
            info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
            caps = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
            negotiated = _valid_protocol_version(result.get("protocolVersion"))
            instructions = result.get("instructions") if isinstance(result.get("instructions"), str) else ""
            meta = {"serverInfo": info, "instructions": instructions}
            indicators, secrets = _scan_item("server", meta)
            headers = _post_headers(session, negotiated)
            await ctx.http.request("POST", url, headers=headers,
                                   content=rpc("notifications/initialized"))
            inventory = {"tools": [], "resources": [], "prompts": []}
            truncated = {"tools": False, "resources": False, "prompts": False}
            raw: dict[str, list[dict]] = {}
            list_refs: list[str] = []
            for method, key in (("tools/list", "tools"), ("resources/list", "resources"),
                                ("prompts/list", "prompts")):
                if key in caps:
                    raw[key], truncated[key], refs = await self._list(
                        ctx, ep, url, headers, method, key, ids)
                    list_refs += refs
            for tool in raw.get("tools", []):
                name = tool.get("name") if isinstance(tool.get("name"), str) else ""
                schema = tool.get("inputSchema")
                inventory["tools"].append({
                    "name": name[:200], "description": _text(tool.get("description")),
                    "classes": classify_tool(name, tool.get("description") or "",
                                             schema if isinstance(schema, dict) else None),
                    "hash": _hash(tool)})
                ind, sec = _scan_item(f"tool:{name[:80]}", tool)
                indicators += ind
                secrets += sec
            for res in raw.get("resources", []):
                name = res.get("name") if isinstance(res.get("name"), str) else ""
                inventory["resources"].append({
                    "name": name[:200], "uri": _text(res.get("uri"), 300),
                    "description": _text(res.get("description")), "hash": _hash(res)})
                ind, sec = _scan_item(f"resource:{name[:80]}", res)
                indicators += ind
                secrets += sec
            for prompt in raw.get("prompts", []):
                name = prompt.get("name") if isinstance(prompt.get("name"), str) else ""
                inventory["prompts"].append({
                    "name": name[:200], "description": _text(prompt.get("description")),
                    "hash": _hash(prompt)})
                ind, sec = _scan_item(f"prompt:{name[:80]}", prompt)
                indicators += ind
                secrets += sec
            data.update(
                initialized=True,
                server_name=_text(info.get("name"), 200), server_version=_text(info.get("version"), 100),
                protocol_version=negotiated, capabilities=sorted(caps), session=bool(session),
                instructions=_text(instructions, 4096),
                tools_count=len(inventory["tools"]), resources_count=len(inventory["resources"]),
                prompts_count=len(inventory["prompts"]), truncated=any(truncated.values()),
                indicators=indicators, secrets=secrets)
            # AM-MCP-004/005 findings cite whichever observation's evidence
            # list they were raised from, and a secret/indicator can live in
            # a tool/resource/prompt description, not just the initialize
            # result -- so both observations get every list-page ref, not
            # just the initialize ref, or the raw value for such a finding
            # would never actually be recoverable from evidence.
            evidence_all = [ref, *list_refs]
            return [Observation("mcp.initialize", url, data, evidence_all),
                    Observation("mcp.inventory", url, {**inventory, "truncated": truncated}, evidence_all)]
        finally:
            # Always close a session we were validly handed, from an early
            # return, a normal finish, or an unexpected exception partway
            # through -- never both the early-return and end-of-function
            # paths (they used to duplicate each other and still had a gap
            # an exception could fall through unclosed). Use the constant,
            # not `negotiated`, for this header: cleanup must stay safe even
            # if a future change to _valid_protocol_version ever let an
            # unsafe value through.
            if session:
                await ctx.http.request("DELETE", url, headers={
                    "Mcp-Session-Id": session, "MCP-Protocol-Version": PROTOCOL_VERSION})

    # -- active level -----------------------------------------------------
    async def _try_initialize(self, ctx, url: str, extra_headers: dict, *,
                              exclude_default_headers: bool = False) -> tuple[int, bool]:
        """POST initialize with extra headers. Returns (status, accepted). Closes any session.

        exclude_default_headers drops any --auth-file/--header credentials
        for this call. The origin and protocol-version checks want them kept
        (they're testing Origin/version validation on an otherwise-normal,
        properly-authenticated request). The bearer check must NOT keep
        them: it sends a deliberately invalid Authorization header to test
        whether an invalid token gets accepted, and a real credential
        riding alongside it -- whether a differently-named header the
        server actually authenticates on, or even an `authorization` key
        that only differs from `Authorization` by case, which httpx will
        happily send as two separate wire headers -- would let the server
        accept on the real credential while agentmap wrongly concludes the
        fake one was accepted.
        """
        headers = {**_post_headers(), **extra_headers}
        resp = await ctx.http.request("POST", url, headers=headers, content=_init_body(),
                                      exclude_default_headers=exclude_default_headers)
        message = rpc_result(resp)
        accepted = bool(message and isinstance(message.get("result"), dict))
        # Same rationale as _handshake: validate the session id before it is
        # ever echoed back into a request header, so a hostile server can't
        # crash this call (non-ASCII value) or wedge the DELETE (CRLF-shaped
        # value) by handing back an unvalidated Mcp-Session-Id.
        session = _valid_session(resp.headers.get("mcp-session-id"))
        if accepted and session:
            await ctx.http.request("DELETE", url, headers={
                "Mcp-Session-Id": session, "MCP-Protocol-Version": PROTOCOL_VERSION},
                exclude_default_headers=exclude_default_headers)
        return resp.status, accepted

    async def _active(self, ctx, endpoint_obs, so_far) -> list[Observation]:
        url = endpoint_obs.target
        baseline = next((o for o in so_far
                         if o.kind == "mcp.initialize" and o.target == url), None)
        auth_required = bool(baseline and baseline.data["auth_required"])
        out: list[Observation] = []
        status, accepted = await self._try_initialize(ctx, url, {"Origin": "https://agentmap.invalid"})
        out.append(Observation("mcp.origin_check", url, {"status": status, "accepted": accepted}))
        status, _accepted = await self._try_initialize(ctx, url, {"MCP-Protocol-Version": "1999-01-01"})
        out.append(Observation("mcp.version_check", url, {"status": status}))
        if auth_required:
            status, accepted = await self._try_initialize(
                ctx, url, {"Authorization": "Bearer agentmap-invalid-token"},
                exclude_default_headers=True)
            out.append(Observation("mcp.bearer_check", url, {"status": status, "accepted": accepted}))
        return out

    async def _list(self, ctx, ep, url, headers, method, key, ids) -> tuple[list[dict], bool, list[str]]:
        items: list[dict] = []
        seen: set[str] = set()
        pages = 0
        truncated = False
        cursor = None
        # Every page's raw response is written to evidence, not just kept in
        # memory: AM-MCP-004/005 findings can be raised from a secret or
        # indicator found inside one of these list responses, and the only
        # place the unmasked raw value is ever recoverable from is evidence.
        refs: list[str] = []
        while True:
            params = {"cursor": cursor} if cursor else None
            resp = await ctx.http.request("POST", url, headers=headers,
                                          content=rpc(method, id=next(ids), params=params))
            refs.append(ctx.evidence(f"mcp-{key}-{ep.host}-{ep.port}-p{pages + 1}.json", resp.body))
            message = rpc_result(resp)
            result = message.get("result") if message else None
            chunk = result.get(key) if isinstance(result, dict) else None
            if not isinstance(chunk, list):
                break
            items.extend(x for x in chunk if isinstance(x, dict))
            pages += 1
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor:
                break
            if cursor in seen or pages >= MAX_PAGES or len(items) >= MAX_ITEMS:
                truncated = True
                break
            seen.add(cursor)
        if len(items) > MAX_ITEMS:
            items, truncated = items[:MAX_ITEMS], True
        return items, truncated, refs

    # -- analysis -------------------------------------------------------
    def analyze(self, observations: list[Observation]) -> list:
        findings = []
        for o in observations:
            d = o.data
            if o.kind == "mcp.endpoint":
                findings.append(make_finding("AM-MCP-001", o.target, d["confidence"],
                                             detail=f"transport={d['transport']}", evidence=o.evidence))
                if d["transport"] == "sse-legacy":
                    findings.append(make_finding("AM-MCP-008", o.target, "high"))
                has_pointer = bool(d["www_authenticate"].get("params", {}).get("resource_metadata"))
                if d["status"] == 401 and not has_pointer:
                    findings.append(make_finding("AM-MCP-006", o.target, "medium"))
            elif o.kind == "mcp.oauth_as" and d["weaknesses"]:
                findings.append(make_finding("AM-MCP-007", o.target, "high",
                                             detail="; ".join(d["weaknesses"]), evidence=o.evidence))
            elif o.kind == "mcp.devtool":
                findings.append(make_finding("AM-MCP-012", o.target, "medium", detail=d["product"]))
            elif o.kind == "mcp.initialize" and d["initialized"]:
                findings += self._analyze_initialize(o)
            elif o.kind == "mcp.inventory":
                findings += self._analyze_inventory(o)
            elif o.kind == "mcp.origin_check" and d["accepted"]:
                findings.append(make_finding(
                    "AM-MCP-009", o.target, "medium",
                    detail=f"foreign Origin accepted (HTTP {d['status']})"))
            elif o.kind == "mcp.bearer_check" and d["accepted"]:
                findings.append(make_finding(
                    "AM-MCP-010", o.target, "high",
                    detail=f"invalid bearer token accepted (HTTP {d['status']})"))
        return findings

    def _analyze_initialize(self, o: Observation) -> list:
        d = o.data
        out = []
        if not d["auth_required"]:
            detail = (f"server={d['server_name']} {d['server_version']}; tools={d['tools_count']}; "
                      f"resources={d['resources_count']}; prompts={d['prompts_count']}")
            if d["truncated"]:
                detail += " [inventory truncated]"
            out.append(make_finding("AM-MCP-002", o.target, "high",
                                    detail=detail, evidence=o.evidence,
                                    severity="high" if d["tools_count"] else "medium"))
        for adv in match_advisories(d["server_name"], d["server_version"]):
            out.append(make_finding(
                "AM-MCP-011", o.target, "medium",
                detail=f"{adv['id']}: {adv['summary']} ({adv['reference']})", evidence=o.evidence))
        if d["indicators"]:
            out.append(self._indicator_finding(o, d["indicators"]))
        if d["secrets"]:
            detail = "; ".join(f"{s['path']}: {s['kind']}" for s in d["secrets"][:5])
            out.append(make_finding("AM-MCP-005", o.target, "high", detail=detail, evidence=o.evidence))
        return out

    def _analyze_inventory(self, o: Observation) -> list:
        out = []
        by_class: dict[str, list[tuple[str, str]]] = {}
        for tool in o.data["tools"]:
            for cls, source in tool["classes"].items():
                if cls in HIGH_RISK:
                    by_class.setdefault(cls, []).append((tool["name"], source))
        for cls, entries in sorted(by_class.items()):
            strong = any(source in ("name", "schema") for _, source in entries)
            out.append(make_finding(
                "AM-MCP-003", o.target, "medium" if strong else "low",
                detail=f"{cls}: " + ", ".join(name for name, _ in entries[:8]),
                evidence=o.evidence, severity="critical" if cls == "exec" else "high"))
        return out

    @staticmethod
    def _indicator_finding(o: Observation, indicators: list[dict]):
        strong = any({"instruction_phrase", "hidden_unicode"} & set(i["kinds"]) for i in indicators)
        detail = "; ".join(f"{i['where']}: {','.join(i['kinds'])}" for i in indicators[:5])
        return make_finding("AM-MCP-004", o.target, "medium" if strong else "low",
                            detail=detail, evidence=o.evidence)
