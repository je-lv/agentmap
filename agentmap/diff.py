"""Compare two runs: new/removed endpoints, findings, auth posture, definitions."""
from __future__ import annotations

from urllib.parse import urlsplit


def _netloc(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.hostname}:{port}"


def _endpoints(store) -> set[str]:
    return {_netloc(o["target"]) for o in store.observations()}


def _finding_key(f: dict) -> tuple:
    return (f["rule_id"], f["target"])


def _auth_signal(data: dict) -> bool | None:
    if "auth_required" in data:
        return bool(data["auth_required"])
    if "auth_declared" in data:
        return bool(data["auth_declared"])
    return None


def compare(a, b) -> dict:
    endpoints_a, endpoints_b = _endpoints(a), _endpoints(b)
    findings_a = {_finding_key(f.to_dict()): f.to_dict() for f in a.findings()}
    findings_b = {_finding_key(f.to_dict()): f.to_dict() for f in b.findings()}

    auth_a: dict[str, bool] = {}
    auth_b: dict[str, bool] = {}
    defs_a: dict[tuple[str, str, str], str] = {}
    defs_b: dict[tuple[str, str, str], str] = {}
    for store, auth_map, defs_map in ((a, auth_a, defs_a), (b, auth_b, defs_b)):
        for o in store.observations():
            signal = _auth_signal(o["data"])
            if signal is not None and o["kind"] in ("mcp.initialize", "a2a.card"):
                auth_map[o["target"]] = signal
            if o["kind"] == "mcp.inventory":
                for key in ("tools", "resources", "prompts"):
                    for item in o["data"].get(key, []):
                        defs_map[(o["target"], key, item.get("name", ""))] = item.get("hash", "")
            elif o["kind"] == "a2a.card":
                fingerprint = o["data"].get("fingerprint")
                if fingerprint:
                    defs_map[(o["target"], "card", "skills")] = fingerprint

    auth_changes = [
        {"target": target, "before": auth_a[target], "after": auth_b[target]}
        for target in sorted(set(auth_a) & set(auth_b)) if auth_a[target] != auth_b[target]
    ]
    def_changes = [
        {"target": target, "kind": kind, "name": name}
        for (target, kind, name) in sorted(set(defs_a) & set(defs_b))
        if defs_a[(target, kind, name)] != defs_b[(target, kind, name)]
    ]
    return {
        "new_endpoints": sorted(endpoints_b - endpoints_a),
        "removed_endpoints": sorted(endpoints_a - endpoints_b),
        "new_findings": [findings_b[k] for k in sorted(findings_b) if k not in findings_a],
        "resolved_findings": [findings_a[k] for k in sorted(findings_a) if k not in findings_b],
        "auth_posture_changes": auth_changes,
        "definition_changes": def_changes,
    }
