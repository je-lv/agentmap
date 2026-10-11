import asyncio
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest
from fakeserver import Reply
from cards import MODERN_CARD
from helpers import run

from agentmap.engine import Engine, ScanConfig, detect_scheme, tcp_open
from agentmap.http import HttpClient, RateLimiter
from agentmap.protocols.a2a import A2AProtocol
from agentmap.protocols.base import Protocol
from agentmap.protocols.mcp import MCPProtocol
from agentmap.scope import Scope
from agentmap.store import RunStore
from agentmap.targets import Target


def closed_port(avoid=()):
    while True:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port not in avoid:
            return port


def build(fake, tmp_path, plugins, ports=None, **cfg):
    scope = Scope.from_items([fake.host])
    http = HttpClient(scope, RateLimiter(0), timeout=3.0)
    store = RunStore.new(tmp_path)
    events = []
    config = ScanConfig(ports=ports or [fake.port], connect_timeout=0.5, **cfg)
    engine = Engine(config, scope, http, store, plugins, on_event=lambda k, p: events.append((k, p)))
    return engine, store, http, events


async def scan(engine, http, targets):
    try:
        return await engine.run(targets)
    finally:
        await http.aclose()


def test_tcp_open_and_closed(fake):
    assert run(tcp_open(fake.host, fake.port, 0.5)) is True
    assert run(tcp_open("127.0.0.1", closed_port(), 0.5)) is False


def test_detect_scheme_plain_http(fake):
    assert run(detect_scheme(fake.host, fake.port, 0.5)) == "http"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_detect_scheme_https(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        assert run(detect_scheme("127.0.0.1", sock.getsockname()[1], 2.0)) == "https"
    finally:
        stop.set()
        t.join(1)
        sock.close()


def test_engine_finds_a2a_and_records_everything(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol(), MCPProtocol()])
    cov = run(scan(engine, http, [Target(fake.host, scheme="http")]))
    assert cov.tcp_open == 1 and cov.matched == {"a2a": 1}
    assert any(f.rule_id == "AM-A2A-001" for f in store.findings())
    kinds = [k for k, _ in events]
    assert "open" in kinds and "finding" in kinds
    assert (fake.host, fake.port) in store.completed


def test_closed_ports_are_counted_and_cheap(fake, tmp_path):
    first = closed_port()
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol()],
                                        ports=[first, closed_port(avoid=(first,))])
    cov = run(scan(engine, http, [Target(fake.host)]))
    assert cov.tcp_closed == 2 and cov.tcp_open == 0 and http.requests_sent == 0


def test_rate_limit_applies_to_tcp_connect_attempts(tmp_path):
    # --rate must bound the TCP pre-filter too, not just HTTP requests made
    # once a port is already known to be open: previously tcp_open() was
    # called without ever going through the shared limiter.
    ports = []
    for _ in range(5):
        ports.append(closed_port(avoid=tuple(ports)))
    scope = Scope.from_items(["127.0.0.1"])
    http = HttpClient(scope, RateLimiter(10), timeout=3.0)  # interval = 0.1s
    store = RunStore.new(tmp_path)
    config = ScanConfig(ports=ports, connect_timeout=0.5, concurrency=8)
    engine = Engine(config, scope, http, store, [A2AProtocol()])
    start = time.monotonic()
    cov = run(scan(engine, http, [Target("127.0.0.1")]))
    elapsed = time.monotonic() - start
    assert cov.tcp_closed == 5
    # 5 rate-limited acquisitions at 10/s space out to roughly 0.4s; allow
    # slack but it must be nowhere near the near-instant unlimited case.
    assert elapsed >= 0.35


def test_out_of_scope_target_is_refused_not_contacted(fake, tmp_path):
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol()])
    cov = run(scan(engine, http, [Target("203.0.113.9", 80)]))
    assert cov.skipped_scope == 1 and cov.endpoints_total == 0
    assert engine.scope.refused[0]["url"].startswith("203.0.113.9")
    skipped = [p for k, p in events if k == "skipped_scope"]
    assert skipped == [Target("203.0.113.9", 80)]
    assert "done" not in [k for k, _ in events]


def test_resume_skips_completed_endpoints(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    engine, store, http, _ = build(fake, tmp_path, [A2AProtocol()])
    run(scan(engine, http, [Target(fake.host, scheme="http")]))
    scope = Scope.from_items([fake.host])
    http2 = HttpClient(scope, RateLimiter(0), timeout=3.0)
    events2 = []
    again = Engine(ScanConfig(ports=[fake.port], connect_timeout=0.5), scope, http2,
                   RunStore(store.run_dir), [A2AProtocol()],
                   on_event=lambda k, p: events2.append((k, p)))
    cov = run(scan(again, http2, [Target(fake.host, scheme="http")]))
    assert cov.skipped_resumed == 1 and http2.requests_sent == 0
    assert [p for k, p in events2 if k == "skipped_resumed"] == [(fake.host, fake.port)]
    assert "done" not in [k for k, _ in events2]


class Sleepy(Protocol):
    name = "sleepy"

    async def probe(self, ep, ctx):
        await asyncio.sleep(5)
        return []

    def analyze(self, observations):
        return []


class Boom(Protocol):
    name = "boom"

    async def probe(self, ep, ctx):
        if ep.port == BOOM_PORT[0]:
            raise RuntimeError("kaboom")
        return []

    def analyze(self, observations):
        return []


class SlowBoom(Protocol):
    """Takes real, measurable time before raising -- used to catch an engine
    that hardcodes elapsed=0.0 for the error path instead of timing it."""

    name = "slowboom"

    async def probe(self, ep, ctx):
        await asyncio.sleep(0.25)
        raise RuntimeError("kaboom-after-sleep")

    def analyze(self, observations):
        return []


BOOM_PORT = [0]


def test_time_limit_stops_and_does_not_mark_done(fake, tmp_path):
    engine, store, http, _ = build(fake, tmp_path, [Sleepy()], time_limit=0.4)
    cov = run(scan(engine, http, [Target(fake.host, scheme="http")]))
    assert cov.stopped and "time limit" in cov.stopped
    assert (fake.host, fake.port) not in store.completed


def test_plugin_exception_is_isolated(fake, tmp_path):
    BOOM_PORT[0] = fake.port
    engine, store, http, events = build(fake, tmp_path, [Boom()])
    cov = run(scan(engine, http, [Target(fake.host, scheme="http")]))
    assert cov.errors == 1
    assert ("error" in [k for k, _ in events])
    assert (fake.host, fake.port) not in store.completed


def test_done_event_fires_exactly_once_per_endpoint_with_full_payload(fake, tmp_path):
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol()])
    run(scan(engine, http, [Target(fake.host, scheme="http")]))
    done = [p for k, p in events if k == "done"]
    assert len(done) == 1
    assert done[0]["host"] == fake.host and done[0]["port"] == fake.port
    assert done[0]["state"] == "open" and done[0]["matched"] == ["a2a"]
    assert done[0]["findings"] >= 1 and done[0]["elapsed"] >= 0


def test_done_event_fires_for_closed_and_error_endpoints(fake, tmp_path):
    first = closed_port()
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol()], ports=[first])
    run(scan(engine, http, [Target(fake.host)]))
    done = [p for k, p in events if k == "done"]
    assert done == [{"host": fake.host, "port": first, "state": "closed",
                     "matched": [], "findings": 0, "elapsed": done[0]["elapsed"]}]

    BOOM_PORT[0] = fake.port
    engine2, store2, http2, events2 = build(fake, tmp_path, [Boom()])
    run(scan(engine2, http2, [Target(fake.host, scheme="http")]))
    done2 = [p for k, p in events2 if k == "done"]
    assert len(done2) == 1 and done2[0]["state"] == "error" and "kaboom" in done2[0]["message"]


def test_error_done_event_reports_real_elapsed_time_not_zero(fake, tmp_path):
    """Regression test: an earlier draft of the engine hardcoded elapsed=0.0
    in the worker's exception handler because `start` was only captured
    inside `_one`, out of scope for that handler. A plugin that spends real
    time before raising must still be reflected in the "done" event's
    elapsed field -- the live terminal UI (Task 16/19) renders this per row,
    and a flat 0.0 for every error would hide where time was actually
    spent."""
    engine, store, http, events = build(fake, tmp_path, [SlowBoom()])
    cov = run(scan(engine, http, [Target(fake.host, scheme="http")]))
    assert cov.errors == 1
    done = [p for k, p in events if k == "done"]
    assert len(done) == 1
    assert done[0]["state"] == "error"
    assert done[0]["elapsed"] >= 0.2


def test_partial_plugin_results_survive_a_later_plugin_crashing(fake, tmp_path):
    """When one plugin at an endpoint succeeds and a later one raises, the
    successful plugin's findings/observations must not be discarded -- they
    were already durably written to the store, and the "done" event should
    reflect that partial progress rather than reporting matched=[] /
    findings=0 as if nothing had happened."""
    fake.route("GET", "/.well-known/agent-card.json", Reply(200, MODERN_CARD))
    BOOM_PORT[0] = fake.port
    engine, store, http, events = build(fake, tmp_path, [A2AProtocol(), Boom()])
    cov = run(scan(engine, http, [Target(fake.host, scheme="http")]))
    assert cov.errors == 1
    done = [p for k, p in events if k == "done"]
    assert len(done) == 1
    assert done[0]["state"] == "error"
    assert done[0]["matched"] == ["a2a"]
    assert done[0]["findings"] >= 1
    assert any(f.rule_id == "AM-A2A-001" for f in store.findings())
