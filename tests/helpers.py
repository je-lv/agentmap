import asyncio

from agentmap.http import HttpClient, RateLimiter
from agentmap.protocols.base import Endpoint, ProbeContext
from agentmap.scope import Scope
from agentmap.store import RunStore


def run(coro):
    return asyncio.run(coro)


async def probe(plugin, fake, tmp_path, level="passive", **client_kw):
    scope = Scope.from_items([fake.host])
    http = HttpClient(scope, RateLimiter(0), timeout=3.0, **client_kw)
    ctx = ProbeContext(http=http, level=level, store=RunStore.new(tmp_path))
    ep = Endpoint("http", fake.host, fake.port)
    try:
        return await plugin.probe(ep, ctx), ctx
    finally:
        await http.aclose()
