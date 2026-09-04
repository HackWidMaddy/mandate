"""MCP gateway proxy prototype - tool-level PEP for ANY agent.

Sits between an agent and an MCP HTTP server. Every JSON-RPC call is judged:

  tools/list  -> response FILTERED to tools the manifest authorizes
                 (each tool evaluated as action mcp.<server>.<tool>)
  tools/call  -> evaluated BEFORE forwarding; denial returns a JSON-RPC
                 error (-32003) and writes a signed receipt
  others      -> forwarded untouched

stdlib ThreadingHTTPServer: this is enforcement-path adjacent, so the same
zero-web-framework discipline as the PDP applies.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

JSONRPC_ERR_AUTHORITY = -32003


class MCPProxy:
    def __init__(self, upstream: str, server_name: str,
                 pdp_client=None, fallback_manifest: Optional[str] = None,
                 evidence_path: Optional[str] = None):
        self.upstream = upstream.rstrip("/")
        self.server_name = server_name
        self.pdp_client = pdp_client
        self.fallback_manifest = fallback_manifest
        self.evidence_path = evidence_path
        self.counters = {"allowed": 0, "denied": 0, "filtered": 0,
                         "forwarded": 0}

    # ------------------------------------------------------------ evaluate
    def _decide(self, probe: dict):
        from ..pdp.client import PDPClient

        client = self.pdp_client or PDPClient()
        return client.evaluate(probe)

    def _record(self, tool: str, allowed: bool, rule: str, reason: str) -> None:
        try:
            if not self.evidence_path:
                return
            from ..core.schema import Manifest
            from ..evidence import EvidenceLedger
            from ..manifest_io import load as _manifest_load

            m = (_manifest_load(self.fallback_manifest)
                 if self.fallback_manifest else Manifest.from_dict({}))
            led = EvidenceLedger(self.evidence_path)
            led.record(bundle_id="mcp-proxy", policy_sha256="-",
                       manifest_dict=m.to_dict(),
                       action={"type": "action",
                               "target": f"mcp.{self.server_name}.{tool}",
                               "detail": f"mcp {tool}"},
                       allowed=allowed, reason=reason, rule=rule)
        except Exception:  # noqa: BLE001 - evidence must never break serving
            pass

    def _probe_for(self, tool: str, params: Optional[dict]) -> dict:
        p = {"kind": "action", "action":
             f"mcp.{self.server_name}.{tool}".lower()}
        if isinstance(params, dict):
            scalar = {k: v for k, v in params.items()
                      if isinstance(v, (str, int, bool))}
            if scalar:
                p["params"] = scalar
        return p

    # ------------------------------------------------------------- upstream
    def _forward_raw(self, body: bytes) -> tuple:
        req = urllib.request.Request(
            self.upstream, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()

    # ---------------------------------------------------------------- logic
    def handle_rpc(self, payload: Dict[str, Any]) -> tuple:
        method = str(payload.get("method", ""))
        rid = payload.get("id")
        params = payload.get("params") or {}

        if method == "tools/list":
            status, raw = self._forward_raw(json.dumps(payload).encode())
            try:
                resp = json.loads(raw.decode())
                tools = resp.get("result", {}).get("tools", [])
            except Exception:  # noqa: BLE001 - pass through on parse issues
                return status, raw
            kept = []
            for t in tools:
                name = t.get("name", "")
                dec = self._decide(self._probe_for(name, None))
                if dec["decision"]["allowed"]:
                    kept.append(t)
                else:
                    self.counters["filtered"] += 1
                    self._record(name, False, dec["decision"]["rule"],
                                 dec["decision"]["reason"])
            resp.setdefault("result", {})["tools"] = kept
            self.counters["forwarded"] += 1
            return 200, json.dumps(resp).encode()

        if method == "tools/call":
            name = str((params or {}).get("name", ""))
            args = (params or {}).get("arguments")
            dec = self._decide(self._probe_for(name, args))
            d = dec["decision"]
            if not d["allowed"]:
                self.counters["denied"] += 1
                self._record(name, False, d["rule"], d["reason"])
                return 200, json.dumps({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {
                        "code": JSONRPC_ERR_AUTHORITY,
                        "message": "Sentinel: tool call outside task authority",
                        "data": {"tool": name, "rule": d["rule"],
                                 "reason": d["reason"]},
                    }}).encode()
            self.counters["allowed"] += 1
            self._record(name, True, d["rule"], d["reason"])

        status, raw = self._forward_raw(json.dumps(payload).encode())
        self.counters["forwarded"] += 1
        return status, raw


def make_handler(proxy: MCPProxy):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelMCPProxy/0.4"

        def log_message(self, fmt, *args):  # quiet
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode())
            except Exception:  # noqa: BLE001
                return self._send(200, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700,
                                                  "message": "parse error"}})
            try:
                status, body = proxy.handle_rpc(payload)
            except Exception as e:  # noqa: BLE001 - fail closed
                return self._send(200, {
                    "jsonrpc": "2.0", "id": payload.get("id"),
                    "error": {"code": JSONRPC_ERR_AUTHORITY,
                              "message": f"Sentinel proxy error: {e}"}})
            self._send(status, json.loads(body.decode()))

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(upstream: str, server_name: str, port: int = 7601,
          **kwargs) -> None:
    proxy = MCPProxy(upstream, server_name, **kwargs)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(proxy))
    print(f"[sentinel-mcp] proxying '{server_name}' "
          f"{httpd.server_address} -> {upstream}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[sentinel-mcp] session: {proxy.counters}")


def main(argv=None) -> int:
    argv = list(argv or [])
    def arg(name, default=None, cast=str):
        if name in argv:
            i = argv.index(name)
            return cast(argv[i + 1])
        return default
    upstream = arg("--upstream")
    if not upstream:
        print("usage: python -m sentinel.adapters.mcp_proxy --upstream URL "
              "--server-name NAME [--port N]", file=sys.stderr)
        return 2
    serve(upstream, arg("--server-name", "mcp"), port=int(arg("--port", 7601)),
          fallback_manifest=arg("--manifest"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
