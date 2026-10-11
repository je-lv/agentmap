"""Threaded stdlib fake servers: real sockets, no network, no extra deps."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace


@dataclass
class Reply:
    status: int = 200
    body: object = b""
    headers: dict | None = None
    sse: list | None = None      # [(event, data), ...] sent as an event stream
    sse_hold: float = 0.0        # keep the stream open this long afterwards
    stall: float = 0.0           # sleep before replying


class FakeServer:
    host = "127.0.0.1"

    def __init__(self) -> None:
        self.routes: dict = {}
        self.default = None          # Reply or callable used when no route matches
        self.requests: list = []
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def route(self, method: str, path: str, reply) -> "FakeServer":
        self.routes[(method.upper(), path)] = reply
        return self

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def methods_seen(self) -> list:
        return [r.json.get("method") for r in self.requests
                if isinstance(r.json, dict) and "method" in r.json]

    def start(self) -> "FakeServer":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                req = SimpleNamespace(
                    method=self.command,
                    path=self.path.split("?")[0],
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=raw,
                )
                try:
                    req.json = json.loads(raw) if raw else None
                except ValueError:
                    req.json = None
                outer.requests.append(req)
                reply = outer.routes.get((self.command, req.path), outer.default)
                if callable(reply):
                    reply = reply(req)
                if reply is None:
                    reply = Reply(404, b"not found")
                if reply.stall:
                    time.sleep(reply.stall)
                if reply.sse is not None:
                    return self._sse(reply)
                body = reply.body
                headers = dict(reply.headers or {})
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                    headers.setdefault("Content-Type", "application/json")
                elif isinstance(body, str):
                    body = body.encode()
                self.send_response(reply.status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _sse(self, reply):
                self.send_response(reply.status)
                self.send_header("Content-Type", "text/event-stream")
                for key, value in (reply.headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    for event, data in reply.sse:
                        self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode())
                        self.wfile.flush()
                    if reply.sse_hold:
                        time.sleep(reply.sse_hold)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_GET = do_POST = do_DELETE = do_HEAD = do_PUT = _handle

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
