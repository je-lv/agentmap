from agentmap.analysis.authposture import (
    as_metadata_url, assess_oauth_as, parse_www_authenticate,
)


def test_parse_www_authenticate_with_resource_metadata():
    v = 'Bearer realm="mcp", resource_metadata="https://h/.well-known/oauth-protected-resource", error="invalid_token"'
    got = parse_www_authenticate(v)
    assert got["scheme"] == "Bearer"
    assert got["params"]["resource_metadata"] == "https://h/.well-known/oauth-protected-resource"
    assert got["params"]["error"] == "invalid_token"


def test_parse_empty_and_garbage():
    assert parse_www_authenticate("") == {}
    assert parse_www_authenticate("Basic") == {"scheme": "Basic", "params": {}}


def test_assess_clean_metadata():
    meta = {
        "issuer": "https://auth.example",
        "authorization_endpoint": "https://auth.example/authorize",
        "token_endpoint": "https://auth.example/token",
        "code_challenge_methods_supported": ["S256"],
    }
    assert assess_oauth_as(meta) == []


def test_assess_flags_http_endpoints_and_missing_pkce():
    meta = {
        "issuer": "http://auth.example",
        "token_endpoint": "http://auth.example/token",
        "token_endpoint_auth_methods_supported": ["none"],
    }
    got = assess_oauth_as(meta)
    assert any("non-HTTPS" in g for g in got)
    assert any("S256" in g for g in got)
    assert any("none" in g for g in got)


def test_http_localhost_is_not_flagged():
    meta = {"issuer": "http://localhost:9000", "code_challenge_methods_supported": ["S256"]}
    assert assess_oauth_as(meta) == []


def test_as_metadata_url_path_insertion():
    assert as_metadata_url("https://a.example") == "https://a.example/.well-known/oauth-authorization-server"
    assert as_metadata_url("https://a.example/tenant1") == "https://a.example/.well-known/oauth-authorization-server/tenant1"
