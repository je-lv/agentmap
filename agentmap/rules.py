"""The rule catalog. IDs are stable once released."""
from __future__ import annotations

from .findings import REGISTRY, Rule

A2A_SPEC = "https://a2a-protocol.org/latest/specification/"
MCP_TRANSPORTS = "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports"
MCP_AUTH = "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization"
RFC9728 = "https://datatracker.ietf.org/doc/html/rfc9728"
RFC8414 = "https://datatracker.ietf.org/doc/html/rfc8414"

RULES = (
    Rule(
        "AM-A2A-001", "A2A agent card is publicly reachable", "info", "passive", "a2a",
        "An A2A Agent Card was served without credentials. Cards are designed to be discoverable, so this is an inventory record rather than a flaw.",
        "Confirm the agent is meant to be reachable from this network position.",
        "Info: discovery documents are public by design.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-002", "Agent card declares no authentication", "medium", "passive", "a2a",
        "The card has no securitySchemes or security entries (and no legacy authentication block), telling clients the agent accepts anonymous requests.",
        "Declare securitySchemes on the card and enforce them on every interface the agent exposes.",
        "Medium: an anonymous agent can act on behalf of its operator; exploitability is not confirmed at this level.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-003", "Agent interface is served over plain HTTP", "medium", "passive", "a2a",
        "The card advertises at least one interface URL using http://, so task content and credentials cross the network unprotected.",
        "Serve every interface over TLS and publish https:// URLs.",
        "Medium: passive network attackers can read or alter agent traffic.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-004", "Agent card advertises an internal address", "low", "passive", "a2a",
        "The card lists an interface URL on a private, loopback or internal-only name that differs from the host that served the card. This leaks topology and breaks external clients.",
        "Publish the externally reachable URL in the card, not the internal one.",
        "Low: information disclosure about internal naming and addressing.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-005", "Injection-style text in agent card", "medium", "passive", "a2a",
        "Card or skill text contains phrases or hidden characters typical of prompt injection aimed at orchestrating LLMs. This is a heuristic indicator, not proof of malicious intent.",
        "Review the card text; treat card content from untrusted agents as untrusted input and strip hidden characters.",
        "Medium: a poisoned card can steer a client agent that places card text in its prompt.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-006", "Secret-like value in agent card", "high", "passive", "a2a",
        "A value in the public card matches a known credential format (API key, token, private key header).",
        "Remove the secret from the card, rotate it, and review what else was published with it.",
        "High: credentials in a public document are assumed compromised.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-007", "Agent card is not signed or signature not verifiable", "info", "passive", "a2a",
        "The card carries no signatures, or carries signatures that agentmap 0.1.0 does not verify. Clients cannot rely on agentmap to establish card authenticity.",
        "Sign cards (JWS) where trust in card contents matters and verify them in clients.",
        "Info: card authenticity cannot be established from this scan.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-008", "Push notifications enabled with no declared authentication", "medium", "passive", "a2a",
        "The card advertises pushNotifications while declaring no authentication. Webhook-style callbacks to caller-supplied URLs are a request-forgery and abuse vector when unauthenticated.",
        "Require authentication before accepting push notification configuration and restrict callback destinations.",
        "Medium: unauthenticated callers may direct the agent to make outbound requests.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-A2A-009", "Authenticated extended card reachable without credentials", "high", "active", "a2a",
        "The card says an authenticated extended card exists, but requesting it with no credentials succeeded.",
        "Enforce authentication on the extended card endpoint.",
        "High: content intended only for authenticated clients was served anonymously.",
        (A2A_SPEC,),
    ),
    Rule(
        "AM-MCP-001", "MCP endpoint detected", "info", "passive", "mcp",
        "An endpoint behaves like an MCP server (Streamable HTTP or legacy HTTP+SSE).",
        "Confirm the server is meant to be reachable from this network position.",
        "Info: inventory record.",
        (MCP_TRANSPORTS,),
    ),
    Rule(
        "AM-MCP-002", "MCP server completes initialize without credentials", "high", "probe", "mcp",
        "The server accepted an unauthenticated initialize handshake and answered capability and list requests. Anyone who can reach it can enumerate what it exposes.",
        "Require authentication (OAuth 2.1 per the MCP authorization spec) or restrict network reachability.",
        "High when tools are listed, medium otherwise: the exposed surface is enumerable anonymously.",
        (MCP_AUTH,),
    ),
    Rule(
        "AM-MCP-003", "High-risk tool class exposed", "high", "probe", "mcp",
        "A listed tool looks like command execution, file modification, outbound HTTP fetch, SQL, secret access or cloud administration, based on its name, description and schema. Classification is heuristic.",
        "Remove or tightly scope the tool, require authentication, and apply least privilege to the server process.",
        "High (critical for command execution): these classes turn tool access into code execution, data access or SSRF.",
        (MCP_AUTH,),
    ),
    Rule(
        "AM-MCP-004", "Injection-style text in MCP server or tool metadata", "medium", "probe", "mcp",
        "Server instructions or tool, resource or prompt text contains phrases or hidden characters typical of tool poisoning. This is a heuristic indicator, not proof of malicious intent.",
        "Review the text and pin or sign tool definitions; treat definitions from untrusted servers as untrusted input.",
        "Medium: poisoned metadata can steer a client model without the user seeing it.",
    ),
    Rule(
        "AM-MCP-005", "Secret-like value in MCP metadata", "high", "probe", "mcp",
        "Server, tool, resource or prompt metadata contains a value matching a known credential format.",
        "Remove the secret from published metadata and rotate it.",
        "High: credentials exposed by an enumerable endpoint are assumed compromised.",
    ),
    Rule(
        "AM-MCP-006", "401 without resource metadata pointer", "low", "passive", "mcp",
        "The endpoint answers 401 but its WWW-Authenticate header does not point to OAuth protected resource metadata, which the MCP authorization spec requires, so clients cannot discover how to authenticate.",
        "Return WWW-Authenticate with a resource_metadata parameter and serve RFC 9728 metadata.",
        "Low: interoperability and discoverability weakness rather than direct exposure.",
        (MCP_AUTH, RFC9728),
    ),
    Rule(
        "AM-MCP-007", "OAuth metadata weakness", "medium", "passive", "mcp",
        "Published OAuth metadata advertises non-HTTPS endpoints or does not advertise PKCE S256 support.",
        "Serve all authorization endpoints over HTTPS and support PKCE with S256.",
        "Medium: weakens the authorization flow protecting the server.",
        (MCP_AUTH, RFC8414),
    ),
    Rule(
        "AM-MCP-008", "Legacy HTTP+SSE transport in use", "info", "passive", "mcp",
        "The server uses the deprecated 2024-11-05 HTTP+SSE transport. agentmap detects it but does not perform the handshake on this transport.",
        "Migrate to Streamable HTTP.",
        "Info: deprecated transport, may lack newer protections.",
        (MCP_TRANSPORTS,),
    ),
    Rule(
        "AM-MCP-009", "MCP server does not validate Origin", "medium", "active", "mcp",
        "A request carrying a foreign Origin header was accepted. The MCP spec requires servers to validate Origin to prevent DNS rebinding.",
        "Validate Origin (and Host) on every request and bind local servers to loopback only.",
        "Medium: enables DNS rebinding against servers on internal networks.",
        (MCP_TRANSPORTS,),
    ),
    Rule(
        "AM-MCP-010", "Invalid bearer token accepted", "high", "active", "mcp",
        "The server demands authentication (it rejected an anonymous request) but accepted a request carrying a bogus bearer token.",
        "Validate access tokens, including audience, on every request.",
        "High: authentication is not actually enforced.",
        (MCP_AUTH,),
    ),
    Rule(
        "AM-MCP-011", "Server version matches a known advisory", "high", "passive", "mcp",
        "The server's reported name and version match an entry in agentmap's curated advisory list.",
        "Upgrade to a fixed version; see the advisory reference in the finding detail.",
        "High: a published vulnerability affects the reported version.",
    ),
    Rule(
        "AM-MCP-012", "MCP developer tooling exposed", "high", "passive", "mcp",
        "A web UI or proxy for MCP development tooling (for example an MCP inspector) is reachable on the network. Such tools can execute commands on the host they run on.",
        "Do not expose developer tooling beyond loopback; require authentication and keep it patched.",
        "High: developer tooling commonly grants command execution to anyone who can reach it.",
    ),
)

for _rule in RULES:
    REGISTRY[_rule.id] = _rule
