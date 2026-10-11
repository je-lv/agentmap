"""Target parsing: hosts, host:port, URLs, IPv6, CIDR (lazy), exclusions."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator
from urllib.parse import urlsplit

LARGE_SCAN_THRESHOLD = 1024
MAX_HOSTS = 1 << 20


@dataclass(frozen=True)
class Target:
    host: str
    port: int | None = None
    scheme: str | None = None
    path: str = ""

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port is not None else host


def parse_ports(spec: str, presets: dict[str, list[int]] | None = None) -> list[int]:
    presets = presets or {}
    out: list[int] = []
    seen: set[int] = set()
    for part in (p.strip() for p in spec.split(",")):
        if part in presets:
            values: Iterable[int] = presets[part]
        elif re.fullmatch(r"\d+-\d+", part):
            lo, hi = (int(x) for x in part.split("-"))
            if lo > hi:
                raise ValueError(f"invalid port range: {part!r}")
            values = range(lo, hi + 1)
        elif part.isdigit():
            values = [int(part)]
        else:
            raise ValueError(f"invalid port spec: {part!r}")
        for value in values:
            if not 1 <= value <= 65535:
                raise ValueError(f"port out of range: {value}")
            if value not in seen:
                seen.add(value)
                out.append(value)
    if not out:
        raise ValueError("no ports")
    return out


def _network(item: str):
    try:
        return ipaddress.ip_network(item, strict=False)
    except ValueError:
        return None


def _network_hosts(net) -> Iterator[str]:
    if net.num_addresses <= 2:
        yield from (str(ip) for ip in net)
    else:
        yield from (str(ip) for ip in net.hosts())


def _strip(item: str) -> str:
    return item.split(" #", 1)[0].strip()


def expand_item(item: str) -> Iterator[Target]:
    item = _strip(item)
    if not item or item.startswith("#"):
        return
    if "://" in item:
        parts = urlsplit(item)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"unsupported target: {item!r}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = "" if parts.path in ("", "/") else parts.path.rstrip("/")
        yield Target(parts.hostname.lower(), port, parts.scheme, path)
        return
    if "/" in item:
        net = _network(item)
        if net is None:
            raise ValueError(f"invalid network: {item!r}")
        for host in _network_hosts(net):
            yield Target(host)
        return
    bracketed = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::(\d+))?", item)
    if bracketed:
        port = int(bracketed.group(2)) if bracketed.group(2) else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        yield Target(bracketed.group(1).lower(), port)
        return
    if item.count(":") == 1:
        host, _, port = item.partition(":")
        if not port.isdigit():
            raise ValueError(f"invalid target: {item!r}")
        port_int = int(port)
        if not 1 <= port_int <= 65535:
            raise ValueError(f"port out of range: {port_int}")
        yield Target(host.lower(), port_int)
        return
    yield Target(item.lower())


def iter_targets(items: Iterable[str]) -> Iterator[Target]:
    seen: set[Target] = set()
    for item in items:
        for target in expand_item(item):
            if target not in seen:
                seen.add(target)
                yield target


def estimate_hosts(items: Iterable[str]) -> int:
    total = 0
    for item in items:
        item = _strip(item)
        if not item or item.startswith("#"):
            continue
        net = _network(item) if "/" in item and "://" not in item else None
        if net is not None:
            n = net.num_addresses
            if n > 2:
                # IPv4 excludes network and broadcast; IPv6 excludes only network
                total += n - 2 if net.version == 4 else n - 1
            else:
                total += n
        else:
            total += 1
    return total


def normalize_host(host: str) -> str:
    """Lowercase, and canonicalize an IP address to its compressed form (so
    an IPv6 long-form address like 0:0:0:0:0:0:0:1 compares equal to ::1).
    Shared with Scope, which must normalize scope/exclusion hosts the same
    way or the two could silently disagree about what a host "is"."""
    host = host.strip().lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def make_excluder(patterns: Iterable[str]) -> Callable[[str], bool]:
    hosts: set[str] = set()
    nets = []
    for raw in patterns:
        raw = _strip(raw)
        if not raw:
            continue
        if "/" in raw:
            net = _network(raw)
            if net is None:
                raise ValueError(f"invalid network in --exclude: {raw!r}")
            nets.append(net)
        else:
            hosts.add(normalize_host(raw))

    def excluded(host: str) -> bool:
        host = normalize_host(host)
        if host in hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in nets)

    return excluded


def read_target_file(path: str | Path) -> list[str]:
    lines = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = _strip(line)
        if line and not line.startswith("#"):
            lines.append(line)
    return lines
