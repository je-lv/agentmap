"""Default-deny scope. Every URL is checked here before any socket opens."""
from __future__ import annotations

import ipaddress
from typing import Callable, Iterable
from urllib.parse import urlsplit

from .targets import expand_item
from .targets import normalize_host as _norm


class Scope:
    def __init__(self, hosts: Iterable[str] = (), networks: Iterable = (),
                 excluder: Callable[[str], bool] | None = None) -> None:
        self._hosts = {_norm(h) for h in hosts}
        self._nets = list(networks)
        self._excluder = excluder
        self.refused: list[dict] = []
        self._refused_keys: set[tuple[str, str]] = set()

    @classmethod
    def from_items(cls, items: Iterable[str], excluder=None) -> "Scope":
        hosts: set[str] = set()
        nets = []
        for raw in items:
            raw = raw.split(" #", 1)[0].strip()
            if not raw or raw.startswith("#"):
                continue
            if "/" in raw and "://" not in raw:
                nets.append(ipaddress.ip_network(raw, strict=False))
                continue
            for target in expand_item(raw):
                hosts.add(target.host)
        return cls(hosts, nets, excluder)

    def allows_host(self, host: str) -> bool:
        host = _norm(host)
        if self._excluder and self._excluder(host):
            return False
        if host in self._hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self._nets)

    def allows_url(self, url: str) -> bool:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            return False
        return bool(host) and self.allows_host(host)

    def refuse(self, url: str, reason: str, source: str = "") -> None:
        key = (url, reason)
        if key in self._refused_keys:
            return
        self._refused_keys.add(key)
        self.refused.append({"url": url, "reason": reason, "source": source})
