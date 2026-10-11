# agentmap rules

Generated from `agentmap/rules.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

| ID | Severity | Level | Protocol | Title |
|---|---|---|---|---|
| AM-A2A-001 | info | passive | a2a | A2A agent card is publicly reachable |
| AM-A2A-002 | medium | passive | a2a | Agent card declares no authentication |
| AM-A2A-003 | medium | passive | a2a | Agent interface is served over plain HTTP |
| AM-A2A-004 | low | passive | a2a | Agent card advertises an internal address |
| AM-A2A-005 | medium | passive | a2a | Injection-style text in agent card |
| AM-A2A-006 | high | passive | a2a | Secret-like value in agent card |
| AM-A2A-007 | info | passive | a2a | Agent card is not signed or signature not verifiable |
| AM-A2A-008 | medium | passive | a2a | Push notifications enabled with no declared authentication |
| AM-A2A-009 | high | active | a2a | Authenticated extended card reachable without credentials |
| AM-MCP-001 | info | passive | mcp | MCP endpoint detected |
| AM-MCP-002 | high | probe | mcp | MCP server completes initialize without credentials |
| AM-MCP-003 | high | probe | mcp | High-risk tool class exposed |
| AM-MCP-004 | medium | probe | mcp | Injection-style text in MCP server or tool metadata |
| AM-MCP-005 | high | probe | mcp | Secret-like value in MCP metadata |
| AM-MCP-006 | low | passive | mcp | 401 without resource metadata pointer |
| AM-MCP-007 | medium | passive | mcp | OAuth metadata weakness |
| AM-MCP-008 | info | passive | mcp | Legacy HTTP+SSE transport in use |
| AM-MCP-009 | medium | active | mcp | MCP server does not validate Origin |
| AM-MCP-010 | high | active | mcp | Invalid bearer token accepted |
| AM-MCP-011 | high | passive | mcp | Server version matches a known advisory |
| AM-MCP-012 | high | passive | mcp | MCP developer tooling exposed |

## AM-A2A-001: A2A agent card is publicly reachable

An A2A Agent Card was served without credentials. Cards are designed to be discoverable, so this is an inventory record rather than a flaw.

**Remediation:** Confirm the agent is meant to be reachable from this network position.

**Rationale:** Info: discovery documents are public by design.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-002: Agent card declares no authentication

The card has no securitySchemes or security entries (and no legacy authentication block), telling clients the agent accepts anonymous requests.

**Remediation:** Declare securitySchemes on the card and enforce them on every interface the agent exposes.

**Rationale:** Medium: an anonymous agent can act on behalf of its operator; exploitability is not confirmed at this level.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-003: Agent interface is served over plain HTTP

The card advertises at least one interface URL using http://, so task content and credentials cross the network unprotected.

**Remediation:** Serve every interface over TLS and publish https:// URLs.

**Rationale:** Medium: passive network attackers can read or alter agent traffic.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-004: Agent card advertises an internal address

The card lists an interface URL on a private, loopback or internal-only name that differs from the host that served the card. This leaks topology and breaks external clients.

**Remediation:** Publish the externally reachable URL in the card, not the internal one.

**Rationale:** Low: information disclosure about internal naming and addressing.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-005: Injection-style text in agent card

Card or skill text contains phrases or hidden characters typical of prompt injection aimed at orchestrating LLMs. This is a heuristic indicator, not proof of malicious intent.

**Remediation:** Review the card text; treat card content from untrusted agents as untrusted input and strip hidden characters.

**Rationale:** Medium: a poisoned card can steer a client agent that places card text in its prompt.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-006: Secret-like value in agent card

A value in the public card matches a known credential format (API key, token, private key header).

**Remediation:** Remove the secret from the card, rotate it, and review what else was published with it.

**Rationale:** High: credentials in a public document are assumed compromised.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-007: Agent card is not signed or signature not verifiable

The card carries no signatures, or carries signatures that agentmap 0.1.0 does not verify. Clients cannot rely on agentmap to establish card authenticity.

**Remediation:** Sign cards (JWS) where trust in card contents matters and verify them in clients.

**Rationale:** Info: card authenticity cannot be established from this scan.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-008: Push notifications enabled with no declared authentication

The card advertises pushNotifications while declaring no authentication. Webhook-style callbacks to caller-supplied URLs are a request-forgery and abuse vector when unauthenticated.

**Remediation:** Require authentication before accepting push notification configuration and restrict callback destinations.

**Rationale:** Medium: unauthenticated callers may direct the agent to make outbound requests.

- https://a2a-protocol.org/latest/specification/

## AM-A2A-009: Authenticated extended card reachable without credentials

The card says an authenticated extended card exists, but requesting it with no credentials succeeded.

**Remediation:** Enforce authentication on the extended card endpoint.

**Rationale:** High: content intended only for authenticated clients was served anonymously.

- https://a2a-protocol.org/latest/specification/

## AM-MCP-001: MCP endpoint detected

An endpoint behaves like an MCP server (Streamable HTTP or legacy HTTP+SSE).

**Remediation:** Confirm the server is meant to be reachable from this network position.

**Rationale:** Info: inventory record.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## AM-MCP-002: MCP server completes initialize without credentials

The server accepted an unauthenticated initialize handshake and answered capability and list requests. Anyone who can reach it can enumerate what it exposes.

**Remediation:** Require authentication (OAuth 2.1 per the MCP authorization spec) or restrict network reachability.

**Rationale:** High when tools are listed, medium otherwise: the exposed surface is enumerable anonymously.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization

## AM-MCP-003: High-risk tool class exposed

A listed tool looks like command execution, file modification, outbound HTTP fetch, SQL, secret access or cloud administration, based on its name, description and schema. Classification is heuristic.

**Remediation:** Remove or tightly scope the tool, require authentication, and apply least privilege to the server process.

**Rationale:** High (critical for command execution): these classes turn tool access into code execution, data access or SSRF.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization

## AM-MCP-004: Injection-style text in MCP server or tool metadata

Server instructions or tool, resource or prompt text contains phrases or hidden characters typical of tool poisoning. This is a heuristic indicator, not proof of malicious intent.

**Remediation:** Review the text and pin or sign tool definitions; treat definitions from untrusted servers as untrusted input.

**Rationale:** Medium: poisoned metadata can steer a client model without the user seeing it.


## AM-MCP-005: Secret-like value in MCP metadata

Server, tool, resource or prompt metadata contains a value matching a known credential format.

**Remediation:** Remove the secret from published metadata and rotate it.

**Rationale:** High: credentials exposed by an enumerable endpoint are assumed compromised.


## AM-MCP-006: 401 without resource metadata pointer

The endpoint answers 401 but its WWW-Authenticate header does not point to OAuth protected resource metadata, which the MCP authorization spec requires, so clients cannot discover how to authenticate.

**Remediation:** Return WWW-Authenticate with a resource_metadata parameter and serve RFC 9728 metadata.

**Rationale:** Low: interoperability and discoverability weakness rather than direct exposure.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- https://datatracker.ietf.org/doc/html/rfc9728

## AM-MCP-007: OAuth metadata weakness

Published OAuth metadata advertises non-HTTPS endpoints or does not advertise PKCE S256 support.

**Remediation:** Serve all authorization endpoints over HTTPS and support PKCE with S256.

**Rationale:** Medium: weakens the authorization flow protecting the server.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- https://datatracker.ietf.org/doc/html/rfc8414

## AM-MCP-008: Legacy HTTP+SSE transport in use

The server uses the deprecated 2024-11-05 HTTP+SSE transport. agentmap detects it but does not perform the handshake on this transport.

**Remediation:** Migrate to Streamable HTTP.

**Rationale:** Info: deprecated transport, may lack newer protections.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## AM-MCP-009: MCP server does not validate Origin

A request carrying a foreign Origin header was accepted. The MCP spec requires servers to validate Origin to prevent DNS rebinding.

**Remediation:** Validate Origin (and Host) on every request and bind local servers to loopback only.

**Rationale:** Medium: enables DNS rebinding against servers on internal networks.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

## AM-MCP-010: Invalid bearer token accepted

The server demands authentication (it rejected an anonymous request) but accepted a request carrying a bogus bearer token.

**Remediation:** Validate access tokens, including audience, on every request.

**Rationale:** High: authentication is not actually enforced.

- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization

## AM-MCP-011: Server version matches a known advisory

The server's reported name and version match an entry in agentmap's curated advisory list.

**Remediation:** Upgrade to a fixed version; see the advisory reference in the finding detail.

**Rationale:** High: a published vulnerability affects the reported version.


## AM-MCP-012: MCP developer tooling exposed

A web UI or proxy for MCP development tooling (for example an MCP inspector) is reachable on the network. Such tools can execute commands on the host they run on.

**Remediation:** Do not expose developer tooling beyond loopback; require authentication and keep it patched.

**Rationale:** High: developer tooling commonly grants command execution to anyone who can reach it.


