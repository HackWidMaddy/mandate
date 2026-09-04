"""Tiny urllib client for adapters talking to the local PDP.

Offline-safe by design: callers must treat ConnectionError as a signal to
use their local fallback, never as an implicit allow.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

DEFAULT_URL = f"http://127.0.0.1:{7433}/v1/evaluate"


class PDPConnectionError(ConnectionError):
    """PDP unreachable - caller must apply its own fail-closed policy."""


class PDPClient:
    def __init__(self, url: str = DEFAULT_URL,
                 token: Optional[str] = None, timeout_s: float = 2.0):
        env_url = os.environ.get("SENTINEL_PDP_URL")
        self.url = env_url or url
        self.token = token or os.environ.get("SENTINEL_PDP_TOKEN")
        self.timeout_s = timeout_s

    def evaluate(self, probe: Dict[str, Any],
                 trace_id: Optional[str] = None) -> Dict[str, Any]:
        body = dict(probe)
        if trace_id:
            body["trace_id"] = trace_id
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Sentinel-Token"] = self.token
        req = urllib.request.Request(self.url, data=data, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError:
            raise  # PDP answered (deny payloads still carry decisions)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise PDPConnectionError(f"PDP unreachable at {self.url}: {e}")

    def health(self) -> Dict[str, Any]:
        url = self.url.rsplit("/", 1)[0] + "/health"
        req = urllib.request.Request(url)
        if self.token:
            req.add_header("X-Sentinel-Token", self.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise PDPConnectionError(f"PDP health failed: {e}")
