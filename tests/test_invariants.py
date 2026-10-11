from pathlib import Path

from agentmap.protocols.mcp import ALLOWED_METHODS

FORBIDDEN = ["tools/" + "call", "resources/" + "read", "prompts/" + "get",
             "message/" + "send", "Send" + "Message", "tasks" + "/"]


def test_allowlist_is_exactly_the_five_read_only_methods():
    assert ALLOWED_METHODS == frozenset({
        "initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list"})


def test_package_source_never_names_a_mutating_method():
    root = Path(__file__).resolve().parent.parent / "agentmap"
    offenders = []
    for path in root.rglob("*"):
        if path.suffix in (".py", ".yaml", ".j2"):
            text = path.read_text(encoding="utf-8")
            offenders += [(path.name, bad) for bad in FORBIDDEN if bad in text]
    assert not offenders, offenders
