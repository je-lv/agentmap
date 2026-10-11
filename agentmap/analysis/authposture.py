"""Reading MCP/OAuth authentication posture signals."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_PARAM = re.compile(r'([A-Za-z_][A-Za-z0-9_\-]*)="([^"]*)"')
_LOCAL = {"localhost", "127.0.0.1", "::1"}


def parse_www_authenticate(value: str) -> dict:
    value = (value or "").strip()
    if not value:
        return {}
    scheme = value.split(None, 1)[0]
    return {"scheme": scheme, "params": dict(_PARAM.findall(value))}


def _insecure(url: object) -> bool:
    if not isinstance(url, str):
        return False
    parts = urlsplit(url)
    return parts.scheme == "http" and (parts.hostname or "") not in _LOCAL


def assess_oauth_as(meta: dict) -> list[str]:
    weaknesses: list[str] = []
    insecure = [k for k in ("issuer", "authorization_endpoint", "token_endpoint",
                            "registration_endpoint") if _insecure(meta.get(k))]
    if insecure:
        weaknesses.append("non-HTTPS endpoints advertised: " + ", ".join(insecure))
    methods = meta.get("code_challenge_methods_supported")
    has_s256 = isinstance(methods, list) and "S256" in methods
    if not has_s256:
        weaknesses.append("PKCE S256 not advertised in code_challenge_methods_supported")
    auth_methods = meta.get("token_endpoint_auth_methods_supported")
    if isinstance(auth_methods, list) and "none" in auth_methods and not has_s256:
        weaknesses.append("public client authentication 'none' advertised without PKCE S256")
    return weaknesses


def as_metadata_url(issuer: str) -> str:
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    base = f"{parts.scheme}://{parts.netloc}"
    return f"{base}/.well-known/oauth-authorization-server{path}"
