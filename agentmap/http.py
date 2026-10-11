"""Scope-enforcing async HTTP layer."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from . import __version__, jsonsafe
from .sse import first_event

DEFAULT_UA = f"agentmap/{__version__}"
MAX_REDIRECTS = 3
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class RateLimiter:
    """Spaces acquisitions 1/rate seconds apart. rate <= 0 disables limiting."""

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval


@dataclass
class Response:
    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    elapsed: float = 0.0
    error: str | None = None
    tls: dict | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return jsonsafe.loads(self.body)


@dataclass
class SseResult:
    status: int = 0
    headers: dict = field(default_factory=dict)
    event: str | None = None
    data: str = ""
    error: str | None = None
    body_head: bytes = b""


class HttpClient:
    def __init__(self, scope, limiter: RateLimiter, *, timeout: float = 5.0,
                 connect_timeout: float = 3.0, max_bytes: int = 1_048_576,
                 headers: dict | None = None, user_agent: str = DEFAULT_UA,
                 proxy: str | None = None, resolve: dict | None = None,
                 on_request=None) -> None:
        self.scope = scope
        self.limiter = limiter
        self.max_bytes = max_bytes
        self.resolve = resolve or {}
        self.on_request = on_request
        self.requests_sent = 0
        # Whether this client has any configured default headers beyond the
        # (always-present) User-Agent -- i.e. whether --header or --auth-file
        # credentials are in play. Protocol plugins use this to decide whether
        # an "is this endpoint open" baseline check needs a credential-free
        # recheck: see request(..., exclude_default_headers=True).
        self.has_default_headers = bool(headers)
        self._headers = {"User-Agent": user_agent, **(headers or {})}
        self._client = httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            proxy=proxy,
            timeout=httpx.Timeout(timeout, connect=connect_timeout),
            limits=httpx.Limits(max_connections=256, max_keepalive_connections=0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- internals ---------------------------------------------------------
    def _pin(self, url: str, headers: dict):
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = self.resolve.get((host, port))
        extensions: dict = {}
        if ip:
            netloc_ip = f"[{ip}]" if ":" in ip else ip
            headers.setdefault("Host", parts.netloc)
            extensions["sni_hostname"] = host
            url = parts._replace(netloc=f"{netloc_ip}:{port}").geturl()
        return url, extensions

    async def _send(self, method: str, url: str, headers: dict | None,
                    content: bytes | None, *, exclude_default_headers: bool = False) -> Response:
        await self.limiter.acquire()
        base = {} if exclude_default_headers else self._headers
        hdrs = {**base, **(headers or {})}
        send_url, extensions = self._pin(url, hdrs)
        self.requests_sent += 1
        if self.on_request:
            self.on_request(method, url)
        resp = Response(url=url)
        start = time.monotonic()
        try:
            async with self._client.stream(
                method, send_url, headers=hdrs, content=content, extensions=extensions
            ) as r:
                resp.status = r.status_code
                resp.headers = {k.lower(): v for k, v in r.headers.items()}
                resp.tls = self._tls_facts(r)
                body = bytearray()
                try:
                    async for chunk in r.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= self.max_bytes:
                            resp.truncated = True
                            del body[self.max_bytes:]
                            break
                except httpx.TimeoutException:
                    resp.error = "timeout"
                resp.body = bytes(body)
        except httpx.TimeoutException:
            resp.error = "timeout"
        except httpx.HTTPError as exc:
            resp.error = f"{type(exc).__name__}: {exc}"[:200]
        resp.elapsed = time.monotonic() - start
        return resp

    @staticmethod
    def _tls_facts(response) -> dict | None:
        try:
            stream = response.extensions.get("network_stream")
            ssl_obj = stream.get_extra_info("ssl_object") if stream else None
            if ssl_obj is None:
                return None
            return {"version": ssl_obj.version(), "cipher": (ssl_obj.cipher() or [None])[0]}
        except Exception:  # noqa: BLE001 - facts are best effort
            return None

    # -- public ------------------------------------------------------------
    async def request(self, method: str, url: str, *, headers: dict | None = None,
                      content: bytes | None = None,
                      exclude_default_headers: bool = False) -> Response:
        current = url
        hops = 0
        while True:
            if not self.scope.allows_url(current):
                self.scope.refuse(current, "out of scope", source=url)
                return Response(url=current, error="out of scope")
            resp = await self._send(method, current, headers, content,
                                    exclude_default_headers=exclude_default_headers)
            if resp.error or resp.status not in REDIRECT_STATUSES:
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            hops += 1
            if hops > MAX_REDIRECTS:
                resp.error = "too many redirects"
                return resp
            current = urljoin(current, location)
            if resp.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                method, content = "GET", None

    async def sse_first_event(self, url: str, headers: dict | None = None,
                              wait: float = 4.0) -> SseResult:
        result = SseResult()
        if not self.scope.allows_url(url):
            self.scope.refuse(url, "out of scope", source=url)
            result.error = "out of scope"
            return result
        await self.limiter.acquire()
        hdrs = {**self._headers, "Accept": "text/event-stream", **(headers or {})}
        send_url, extensions = self._pin(url, hdrs)
        self.requests_sent += 1
        if self.on_request:
            self.on_request("GET", url)

        async def read() -> None:
            async with self._client.stream("GET", send_url, headers=hdrs,
                                           extensions=extensions) as r:
                result.status = r.status_code
                result.headers = {k.lower(): v for k, v in r.headers.items()}
                is_sse = "text/event-stream" in result.headers.get("content-type", "")
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf.extend(chunk)
                    result.body_head = bytes(buf[:65536])
                    if is_sse:
                        event = first_event(bytes(buf))
                        if event:
                            result.event, result.data = event
                            return
                    if len(buf) >= 65536:
                        return

        try:
            await asyncio.wait_for(read(), timeout=wait)
        except asyncio.TimeoutError:
            result.error = "timeout"
        except httpx.HTTPError as exc:
            result.error = f"{type(exc).__name__}: {exc}"[:200]
        return result
