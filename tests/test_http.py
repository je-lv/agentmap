import asyncio
import time

from fakeserver import FakeServer, Reply

from agentmap.http import HttpClient, RateLimiter
from agentmap.scope import Scope


def run(coro):
    return asyncio.run(coro)


def client_for(fake, **kw):
    scope = Scope.from_items([fake.host, "agentmap.test"])
    return HttpClient(scope, RateLimiter(0), timeout=2.0, **kw)


def test_rate_limiter_spaces_requests():
    async def go():
        limiter = RateLimiter(50)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        return time.monotonic() - start
    assert run(go()) >= 0.07


def test_rate_limiter_serializes_concurrent_callers():
    # Concurrent acquirers must still be spaced 1/rate apart, not race past
    # the limit by reading `_next` before anyone has updated it.
    async def go():
        limiter = RateLimiter(50)  # interval = 0.02s
        start = time.monotonic()
        await asyncio.gather(*(limiter.acquire() for _ in range(5)))
        return time.monotonic() - start
    assert run(go()) >= 0.07


def test_get_returns_status_headers_body(fake):
    fake.route("GET", "/x", Reply(200, {"a": 1}, {"X-Test": "yes"}))

    async def go():
        c = client_for(fake)
        try:
            return await c.request("GET", f"http://{fake.host}:{fake.port}/x")
        finally:
            await c.aclose()
    r = run(go())
    assert r.ok and r.status == 200 and r.headers["x-test"] == "yes"
    assert r.json() == {"a": 1} and not r.truncated


def test_body_is_capped(fake):
    fake.route("GET", "/big", Reply(200, b"A" * 5000))

    async def go():
        c = client_for(fake, max_bytes=1000)
        try:
            return await c.request("GET", f"http://{fake.host}:{fake.port}/big")
        finally:
            await c.aclose()
    r = run(go())
    assert len(r.body) == 1000 and r.truncated


def test_out_of_scope_url_is_refused_without_a_request(fake):
    async def go():
        c = client_for(fake)
        try:
            r = await c.request("GET", "http://203.0.113.9:9/")
            return r, c
        finally:
            await c.aclose()
    r, c = run(go())
    assert r.error == "out of scope" and c.requests_sent == 0
    assert c.scope.refused[0]["url"] == "http://203.0.113.9:9/"


def test_redirect_in_scope_followed_out_of_scope_refused(fake):
    fake.route("GET", "/in", Reply(302, b"", {"Location": "/landed"}))
    fake.route("GET", "/landed", Reply(200, b"ok"))
    fake.route("GET", "/out", Reply(302, b"", {"Location": "http://203.0.113.9:9/"}))

    async def go():
        c = client_for(fake)
        try:
            a = await c.request("GET", f"http://{fake.host}:{fake.port}/in")
            b = await c.request("GET", f"http://{fake.host}:{fake.port}/out")
            return a, b, c
        finally:
            await c.aclose()
    a, b, c = run(go())
    assert a.status == 200 and a.body == b"ok"
    assert b.error == "out of scope"
    assert any(r["url"] == "http://203.0.113.9:9/" for r in c.scope.refused)


def test_redirect_loop_stops(fake):
    fake.route("GET", "/loop", Reply(302, b"", {"Location": "/loop"}))

    async def go():
        c = client_for(fake)
        try:
            return await c.request("GET", f"http://{fake.host}:{fake.port}/loop")
        finally:
            await c.aclose()
    assert run(go()).error == "too many redirects"


def test_stall_times_out_with_error(fake):
    fake.route("GET", "/slow", Reply(200, b"x", stall=1.5))

    async def go():
        scope = Scope.from_items([fake.host])
        c = HttpClient(scope, RateLimiter(0), timeout=0.3)
        try:
            return await c.request("GET", f"http://{fake.host}:{fake.port}/slow")
        finally:
            await c.aclose()
    r = run(go())
    assert r.error and not r.ok


def test_connect_error_is_reported_not_raised():
    async def go():
        scope = Scope.from_items(["127.0.0.1"])
        c = HttpClient(scope, RateLimiter(0), timeout=1.0, connect_timeout=0.5)
        try:
            return await c.request("GET", "http://127.0.0.1:1/")
        finally:
            await c.aclose()
    assert run(go()).error


def test_sse_first_event(fake):
    fake.route("GET", "/sse", Reply(200, sse=[("endpoint", "/messages?s=1")], sse_hold=0.5))

    async def go():
        c = client_for(fake)
        try:
            return await c.sse_first_event(f"http://{fake.host}:{fake.port}/sse")
        finally:
            await c.aclose()
    r = run(go())
    assert r.status == 200 and r.event == "endpoint" and r.data == "/messages?s=1"


def test_sse_first_event_non_sse_keeps_body_head(fake):
    fake.route("GET", "/mcp", Reply(405, {"error": "jsonrpc: use POST"}))

    async def go():
        c = client_for(fake)
        try:
            return await c.sse_first_event(f"http://{fake.host}:{fake.port}/mcp")
        finally:
            await c.aclose()
    r = run(go())
    assert r.status == 405 and b"jsonrpc" in r.body_head and r.event is None


def test_resolve_pin_sets_host_header(fake):
    fake.route("GET", "/who", Reply(200, b"hi"))

    async def go():
        c = client_for(fake, resolve={("agentmap.test", fake.port): fake.host})
        try:
            return await c.request("GET", f"http://agentmap.test:{fake.port}/who")
        finally:
            await c.aclose()
    r = run(go())
    assert r.status == 200
    assert fake.requests[-1].headers["host"] == f"agentmap.test:{fake.port}"


def test_headers_and_user_agent_sent(fake):
    fake.route("GET", "/h", Reply(200, b"ok"))

    async def go():
        c = client_for(fake, headers={"X-Engagement": "abc"}, user_agent="agentmap-test")
        try:
            return await c.request("GET", f"http://{fake.host}:{fake.port}/h")
        finally:
            await c.aclose()
    run(go())
    h = fake.requests[-1].headers
    assert h["x-engagement"] == "abc" and h["user-agent"] == "agentmap-test"
