from agentmap.analysis.secrets import (
    find_secrets, mask, mask_json, redact_text, scan_json,
)

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"          # 20 chars, assembled so this file carries no literal key
GH = "ghp_" + "a" * 36
JWT = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
# Same rationale as AWS/GH/JWT above: assembled so the file's own text never
# carries the full dashed PEM private-key header as one contiguous run,
# which would otherwise make the leak scanner flag this very test file when
# it scans a copy of the test suite (see scripts/leakscan.py / export-release.sh).
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY" + "-----"


def kinds(text):
    return [h.kind for h in find_secrets(text)]


def test_known_formats_detected():
    assert kinds(f"key {AWS} end") == ["aws_access_key"]
    assert kinds(GH) == ["github_token"]
    assert kinds(JWT) == ["jwt"]
    assert kinds(PRIVATE_KEY_HEADER) == ["private_key"]
    assert kinds("AIza" + "x" * 35) == ["google_api_key"]


def test_generic_secret_needs_random_looking_value():
    # The random-looking value is built via concatenation and interpolated
    # (not written as one literal `api_key = "..."` run) for the same
    # self-matching reason as PRIVATE_KEY_HEADER above: a contiguous
    # "api_key = \"<value>\"" of this shape is exactly what the generic-secret
    # pattern this test exercises looks for, and this file ships in the
    # public export too.
    random_value = "Zk93jd8sL2pQ7vXm41Ab" + "T"
    assert kinds(f'api_key = "{random_value}"') == ["generic_secret"]
    assert kinds("token: authentication-required-header") == []
    assert kinds("password: placeholderplaceholder") == []


def test_plain_prose_has_no_hits():
    assert find_secrets("A helpful agent that books flights and hotels.") == []


def test_mask_and_redact():
    assert mask("short") == "****"
    assert mask(AWS) == "AKIA…[20]"
    out = redact_text(f"id={AWS};")
    assert AWS not in out and "<aws_access_key:AKIA…[20]>" in out


def test_redaction_is_idempotent():
    once = redact_text(f"a {AWS} b {GH}")
    assert redact_text(once) == once


def test_scan_json_reports_paths_not_values():
    obj = {"skills": [{"description": f"use {GH}"}], "n": 1}
    assert scan_json(obj) == [{"path": "skills[0].description", "kind": "github_token"}]


def test_mask_json_deep_copy():
    obj = {"a": [f"x {AWS}"], "b": {"c": 5}}
    masked = mask_json(obj)
    assert AWS not in str(masked) and masked["b"] == {"c": 5}
    assert AWS in str(obj)
