"""Async scan engine."""
from __future__ import annotations

import asyncio
import ssl
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .levels import allows
from .protocols.base import Endpoint, ProbeContext
from .targets import Target


@dataclass
class ScanConfig:
    ports: list[int]
    level: str = "passive"
    concurrency: int = 64
    per_host: int = 8
    connect_timeout: float = 1.5
    time_limit: float | None = None
    resolve: dict = field(default_factory=dict)


@dataclass
class Coverage:
    endpoints_total: int = 0
    tcp_open: int = 0
    tcp_closed: int = 0
    skipped_resumed: int = 0
    skipped_scope: int = 0
    errors: int = 0
    matched: dict = field(default_factory=dict)
    stopped: str | None = None

    def to_dict(self) -> dict:
        return {
            "endpoints_total": self.endpoints_total, "tcp_open": self.tcp_open,
            "tcp_closed": self.tcp_closed, "skipped_resumed": self.skipped_resumed,
            "skipped_scope": self.skipped_scope, "errors": self.errors,
            "matched": dict(self.matched), "stopped": self.stopped,
        }


async def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - peer reset on close is irrelevant
        pass
    return True


async def detect_scheme(host: str, port: int, timeout: float,
                        server_name: str | None = None) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context,
                                    server_hostname=server_name or host), timeout)
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return "http"
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return "https"


class Engine:
    def __init__(self, cfg: ScanConfig, scope, http, store, plugins: list,
                 on_event: Callable[[str, object], None] | None = None) -> None:
        self.cfg = cfg
        self.scope = scope
        self.http = http
        self.store = store
        self.plugins = plugins
        self.on_event = on_event
        self.cov = Coverage()

    def _emit(self, kind: str, payload: object) -> None:
        if self.on_event:
            self.on_event(kind, payload)

    async def run(self, targets: Iterable[Target]) -> Coverage:
        queue: asyncio.Queue = asyncio.Queue(maxsize=max(2, self.cfg.concurrency * 2))
        host_sems: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.cfg.per_host))
        workers = [asyncio.create_task(self._worker(queue, host_sems))
                   for _ in range(self.cfg.concurrency)]
        producer = asyncio.create_task(self._produce(targets, queue, len(workers)))
        everything = [producer, *workers]
        try:
            await asyncio.wait_for(asyncio.gather(*everything), timeout=self.cfg.time_limit)
        except asyncio.TimeoutError:
            self.cov.stopped = f"time limit {self.cfg.time_limit:g}s reached"
            for task in everything:
                task.cancel()
            await asyncio.gather(*everything, return_exceptions=True)
        except BaseException:
            for task in everything:
                task.cancel()
            await asyncio.gather(*everything, return_exceptions=True)
            raise
        return self.cov

    async def _produce(self, targets: Iterable[Target], queue: asyncio.Queue, n_workers: int) -> None:
        for target in targets:
            if not self.scope.allows_host(target.host):
                self.cov.skipped_scope += 1
                self.scope.refuse(target.netloc, "target not in scope", "target list")
                self._emit("skipped_scope", target)
                continue
            for port in ([target.port] if target.port else self.cfg.ports):
                await queue.put((target, port))
        for _ in range(n_workers):
            await queue.put(None)

    async def _worker(self, queue: asyncio.Queue, host_sems) -> None:
        while True:
            item = await queue.get()
            if item is None:
                return
            target, port = item
            try:
                await self._one(target, port, host_sems[target.host])
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - last-resort net; _one handles plugin
                                       # errors itself (with an accurate elapsed time); this
                                       # only catches something unexpected outside that path.
                self.cov.errors += 1
                message = f"{type(exc).__name__}: {exc}"
                self._emit("error", (target.host, port, message))
                self._emit("done", {"host": target.host, "port": port, "state": "error",
                                   "matched": [], "findings": 0, "elapsed": 0.0,
                                   "message": message})

    async def _one(self, target: Target, port: int, host_sem: asyncio.Semaphore) -> None:
        key = (target.host, port)
        if key in self.store.completed:
            self.cov.skipped_resumed += 1
            self._emit("skipped_resumed", key)
            return
        async with host_sem:
            start = time.monotonic()
            self.cov.endpoints_total += 1
            connect_host = self.cfg.resolve.get(key, target.host)
            # --rate must bound every socket agentmap opens, not just the
            # HTTP requests a protocol plugin later makes on top of an
            # already-open port: the TCP pre-filter and the TLS/plaintext
            # scheme probe below are each a real connection attempt too.
            await self.http.limiter.acquire()
            if not await tcp_open(connect_host, port, self.cfg.connect_timeout):
                self.cov.tcp_closed += 1
                self.store.mark_done(*key)
                self._emit("closed", key)
                self._emit("done", {"host": target.host, "port": port, "state": "closed",
                                   "matched": [], "findings": 0,
                                   "elapsed": time.monotonic() - start})
                return
            self.cov.tcp_open += 1
            if target.scheme:
                scheme = target.scheme
            else:
                await self.http.limiter.acquire()
                scheme = await detect_scheme(
                    connect_host, port, self.cfg.connect_timeout, server_name=target.host)
            endpoint = Endpoint(scheme, target.host, port, target.path)
            self._emit("open", endpoint)
            ctx = ProbeContext(http=self.http, level=self.cfg.level, store=self.store)
            matched: list[str] = []
            findings_count = 0
            try:
                for plugin in self.plugins:
                    if not allows(self.cfg.level, plugin.min_level):
                        continue
                    observations = await plugin.probe(endpoint, ctx)
                    if not observations:
                        continue
                    self.cov.matched[plugin.name] = self.cov.matched.get(plugin.name, 0) + 1
                    matched.append(plugin.name)
                    for obs in observations:
                        self.store.add_observation(obs)
                    for finding in plugin.analyze(observations):
                        self.store.add_finding(finding)
                        findings_count += 1
                        self._emit("finding", finding)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - one plugin's bug must not sink the scan
                self.cov.errors += 1
                message = f"{type(exc).__name__}: {exc}"
                self._emit("error", (target.host, port, message))
                self._emit("done", {"host": target.host, "port": port, "state": "error",
                                   "matched": matched, "findings": findings_count,
                                   "elapsed": time.monotonic() - start,
                                   "message": message})
                return
            self.store.mark_done(*key)
            self._emit("done", {"host": target.host, "port": port, "state": "open",
                               "matched": matched, "findings": findings_count,
                               "elapsed": time.monotonic() - start})
