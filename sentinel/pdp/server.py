"""Localhost-only HTTP surface for the PDP.

stdlib ThreadingHTTPServer - no web-framework supply-chain on the
security-critical path. Endpoints:

    POST /v1/evaluate   {"kind": ..., ...probe fields, "trace_id"?}
    GET  /v1/health
    GET  /v1/bundle     (metadata only; never secrets)

Fail-closed: malformed requests and unknown routes produce DENY-style
responses, never exceptions leaking to the client.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

DEFAULT_PORT = 7433


def make_handler(engine, auth_token: Optional[str] = None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelPDP/0.2"
        protocol_version = "HTTP/1.1"

        # ------------------------------------------------------------ util
        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not auth_token:
                return True
            return self.headers.get("X-Sentinel-Token", "") == auth_token

        def log_message(self, fmt, *args):  # quiet by default
            pass

        # ----------------------------------------------------------- GET
        def do_GET(self):
            if not self._authorized():
                return self._send(403, {"error": "unauthorized"})
            path = self.path.split("?")[0]
            if path == "/v1/health":
                return self._send(200, engine.health())
            if path == "/v1/bundle":
                return self._send(200, engine.bundle_metadata())
            if path == "/metrics":
                body = engine.metrics_text().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return None
            return self._send(404, {"error": "not found",
                                    "hint": "GET /v1/health | /v1/bundle | /metrics"})

        # ---------------------------------------------------------- POST
        def do_POST(self):
            if not self._authorized():
                return self._send(403, {"error": "unauthorized"})
            path = self.path.split("?")[0]
            if path != "/v1/evaluate":
                return self._send(404, {"error": "not found",
                                        "hint": "POST /v1/evaluate"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
                probe = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception as e:  # noqa: BLE001 - fail closed
                return self._send(400, {
                    "decision": {"allowed": False,
                                 "reason": f"unreadable request: {e}",
                                 "rule": "bad-request"}})
            trace_id = probe.pop("trace_id", None)
            try:
                result = engine.evaluate(probe, trace_id=trace_id)
            except Exception as e:  # noqa: BLE001 - fail closed
                result = {"decision": {"allowed": False,
                                       "reason": f"engine error: {e}",
                                       "rule": "engine-error"}}
            return self._send(200, result)

    return Handler


class PDPServer:
    def __init__(self, engine, host: str = "127.0.0.1",
                 port: int = DEFAULT_PORT, auth_token: Optional[str] = None):
        handler = make_handler(engine, auth_token=auth_token)
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.host, self.port = self.httpd.server_address
        self.engine = engine

    def serve_forever(self) -> None:
        print(f"[sentinel-pdp] listening on http://{self.host}:{self.port} "
              f"(mode={self.engine.mode})")
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown_report()

    def shutdown_report(self) -> None:
        st = self.engine.status
        lats = sorted(st.latencies_ms)
        p99 = lats[int(len(lats) * 0.99)] if lats else 0.0
        print(f"\n[sentinel-pdp] session: {st.decisions} decisions "
              f"({st.allowed} allow / {st.denied} deny), p99 {p99}ms")

    def start_background(self):
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        return t
