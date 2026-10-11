"""Heuristic capability classification of MCP tools."""
from __future__ import annotations

import re

HIGH_RISK = frozenset({"exec", "filesystem_write", "http_fetch", "sql", "secrets", "cloud_admin"})

_WORDS = {
    "exec": r"(?:exec|execute|shell|bash|zsh|powershell|eval|spawn|subprocess|terminal|run command|run script|run code)",
    "filesystem_write": r"(?:write file|delete file|remove file|create file|edit file|move file|save file|append file|mkdir|chmod|rm)",
    "http_fetch": r"(?:fetch|http request|curl|download|browse|scrape|web request|get url|open url)",
    "sql": r"(?:sql|run query|execute query|query database)",
    "secrets": r"(?:get secret|read secret|credential|credentials|api key|api keys|vault|keychain|password)",
    "cloud_admin": r"(?:kubectl|aws|iam|terraform|azure|gcloud|kubernetes|docker)",
}
_PATTERNS = {k: re.compile(rf"\b{v}\b") for k, v in _WORDS.items()}
_PARAMS = {
    "exec": {"command", "cmd", "script", "shell", "code"},
    "sql": {"sql", "query_sql"},
    "http_fetch": {"url", "uri"},
}
_RANK = {"name": 3, "schema": 2, "description": 1}


def _normalise(text: object) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.sub(r"[_\-./]+", " ", text).lower()


def classify_tool(name: str, description: str = "", schema: dict | None = None) -> dict[str, str]:
    found: dict[str, str] = {}

    def note(cls: str, source: str) -> None:
        if _RANK[source] > _RANK.get(found.get(cls, ""), 0):
            found[cls] = source

    n, d = _normalise(name), _normalise(description)
    for cls, pattern in _PATTERNS.items():
        if pattern.search(n):
            note(cls, "name")
        elif pattern.search(d):
            note(cls, "description")
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        for param in props:
            for cls, names in _PARAMS.items():
                if isinstance(param, str) and param.lower() in names:
                    note(cls, "schema")
    return found
