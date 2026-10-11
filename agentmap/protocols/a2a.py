"""A2A agent card discovery, strict validation and analysis."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import datafiles
from ..analysis.poisoning import scan_text
from ..analysis.secrets import mask_json, scan_json
from ..findings import make_finding
from ..levels import allows
from .base import Endpoint, Observation, ProbeContext, Protocol

A2A_KEYS = {"skills", "supportedInterfaces", "capabilities", "securitySchemes",
            "protocolVersion", "preferredTransport", "defaultInputModes", "defaultOutputModes"}
TEXT_KEYS = {"name", "description", "examples", "tags", "instructions", "title"}
INTERNAL_SUFFIXES = (".internal", ".local", ".lan", ".svc", ".cluster.local", ".corp", ".intranet")


@dataclass
class CardInfo:
    name: str
    version: str
    description: str
    interface_urls: list[str]
    skills: list[dict]
    auth_declared: bool
    push: bool
    extended: bool
    signed: bool
    family: str
    fingerprint: str


def _is_http_url(value: object) -> bool:
    return isinstance(value, str) and value.startswith(("http://", "https://"))


def parse_card(obj: object) -> CardInfo | None:
    """Strict: a bare {"name": ...} document is not an agent card."""
    if not isinstance(obj, dict):
        return None
    name = obj.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    if not (A2A_KEYS & obj.keys()):
        return None
    interfaces = obj.get("supportedInterfaces")
    skills = obj.get("skills")
    urls: list[str] = []
    for key in ("supportedInterfaces", "additionalInterfaces"):
        for item in obj.get(key) or []:
            if isinstance(item, dict) and _is_http_url(item.get("url")):
                urls.append(item["url"])
    if _is_http_url(obj.get("url")):
        urls.append(obj["url"])
    skill_list = [s for s in skills if isinstance(s, dict)] if isinstance(skills, list) else []
    # A supportedInterfaces/additionalInterfaces entry only counts as a real endpoint when it
    # actually carries a usable url -- that is already what `urls` accumulates above. A separate
    # "interfaces is a non-empty list of dicts" fallback would match entries like
    # {"protocolBinding": "JSONRPC"} that declare no endpoint at all, so it is deliberately not
    # part of this check.
    has_endpoint = bool(urls) or bool(skill_list)
    if not has_endpoint:
        return None
    caps = obj.get("capabilities") if isinstance(obj.get("capabilities"), dict) else {}
    auth_block = obj.get("authentication")
    legacy_auth = isinstance(auth_block, dict) and bool(
        auth_block.get("schemes") or auth_block.get("credentials"))
    fingerprint = hashlib.sha256(json.dumps(
        [{"id": s.get("id"), "name": s.get("name"), "description": s.get("description")}
         for s in skill_list], sort_keys=True).encode()).hexdigest()[:16]
    return CardInfo(
        name=name,
        version=str(obj.get("version", "")),
        description=str(obj.get("description", "")),
        interface_urls=urls,
        skills=skill_list,
        auth_declared=bool(obj.get("securitySchemes")) or bool(obj.get("security")) or legacy_auth,
        push=caps.get("pushNotifications") is True,
        extended=caps.get("extendedAgentCard") is True
        or obj.get("supportsAuthenticatedExtendedCard") is True,
        signed=bool(obj.get("signatures")),
        family="v1" if isinstance(interfaces, list) and interfaces else "legacy",
        fingerprint=fingerprint,
    )


def _leaf_strings(value, path):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _leaf_strings(item, f"{path}[{i}]")
    elif isinstance(value, dict):
        yield from _texts(value, path)


def _texts(obj, path=""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            sub = f"{path}.{key}" if path else str(key)
            if key in TEXT_KEYS:
                yield from _leaf_strings(value, sub)
            else:
                yield from _texts(value, sub)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _texts(item, f"{path}[{i}]")


def _internal_host(host: str) -> bool:
    host = host.lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or "." not in host or host.endswith(INTERNAL_SUFFIXES)


class A2AProtocol(Protocol):
    name = "a2a"
    min_level = "passive"

    async def probe(self, ep: Endpoint, ctx: ProbeContext) -> list[Observation]:
        out: list[Observation] = []
        for path in datafiles.load("paths")["a2a"]["card_paths"]:
            url = ep.url(path)
            resp = await ctx.http.request("GET", url, headers={"Accept": "application/json"})
            if not resp.ok or resp.status != 200:
                continue
            raw = resp.json()
            card = parse_card(raw)
            if card is None:
                continue
            ref = ctx.evidence(f"a2a-card-{ep.host}-{ep.port}.json", resp.body)
            indicators = []
            for where, text in _texts(raw):
                kinds = scan_text(text)
                if kinds:
                    indicators.append({"where": where, "kinds": kinds})
            out.append(Observation("a2a.card", url, {
                "path": path,
                "legacy_path": path.endswith("/agent.json"),
                "status": resp.status,
                "server": resp.headers.get("server"),
                "name": card.name,
                "version": card.version,
                "interfaces": card.interface_urls,
                "auth_declared": card.auth_declared,
                "push": card.push,
                "extended": card.extended,
                "signed": card.signed,
                "family": card.family,
                "secrets": scan_json(raw),
                "indicators": indicators,
                "fingerprint": card.fingerprint,
                "card": mask_json(raw),
            }, [ref]))
            if card.extended and allows(ctx.level, "active"):
                ext_url = ep.url("/extendedAgentCard")
                # AM-A2A-009 means "reachable without credentials": this
                # check must never carry --auth-file/--header defaults, or a
                # properly-authenticated extended card looks identical to an
                # exposed one just because the scan happened to have valid
                # credentials configured.
                ext = await ctx.http.request("GET", ext_url, headers={"Accept": "application/json"},
                                             exclude_default_headers=True)
                out.append(Observation("a2a.extended", ext_url,
                                       {"status": ext.status, "error": ext.error}))
            break
        return out

    def analyze(self, observations: list[Observation]) -> list:
        findings = []
        for o in observations:
            d = o.data
            if o.kind == "a2a.extended":
                if d.get("status") == 200:
                    findings.append(make_finding("AM-A2A-009", o.target, "high"))
                continue
            if o.kind != "a2a.card":
                continue
            ev = o.evidence
            host = urlsplit(o.target).hostname or ""
            findings.append(make_finding("AM-A2A-001", o.target, "high", detail=d["path"], evidence=ev))
            if not d["auth_declared"]:
                findings.append(make_finding("AM-A2A-002", o.target, "high", evidence=ev))
            plain = [u for u in d["interfaces"] if u.startswith("http://")]
            if plain:
                findings.append(make_finding("AM-A2A-003", o.target, "high",
                                             detail=", ".join(plain[:3]), evidence=ev))
            internal = [u for u in d["interfaces"]
                        if (urlsplit(u).hostname or "") != host and _internal_host(urlsplit(u).hostname or "")]
            if internal:
                findings.append(make_finding("AM-A2A-004", o.target, "medium",
                                             detail=", ".join(internal[:3]), evidence=ev))
            if d["indicators"]:
                strong = any({"instruction_phrase", "hidden_unicode"} & set(i["kinds"])
                             for i in d["indicators"])
                detail = "; ".join(f"{i['where']}: {','.join(i['kinds'])}" for i in d["indicators"][:5])
                findings.append(make_finding("AM-A2A-005", o.target, "medium" if strong else "low",
                                             detail=detail, evidence=ev))
            if d["secrets"]:
                detail = "; ".join(f"{s['path']}: {s['kind']}" for s in d["secrets"][:5])
                findings.append(make_finding("AM-A2A-006", o.target, "high", detail=detail, evidence=ev))
            findings.append(make_finding(
                "AM-A2A-007", o.target, "high",
                detail="signatures present, not verified" if d["signed"] else "no signatures",
                evidence=ev))
            if d["push"] and not d["auth_declared"]:
                findings.append(make_finding("AM-A2A-008", o.target, "high", evidence=ev))
        return findings
