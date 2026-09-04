"""Stable adapter interface: one deterministic boundary, every coding agent.

An adapter maps a platform's tool-call event onto a neutral Sentinel probe
and runs the shared decision flow:

    platform event ──classify──▶ neutral probe dict
                                        │
                        PDP-first (trace_id = agent session id)
                                        │  on PDPConnectionError:
                        logged local-manifest fallback (same evaluator)
                                        ▼
                     AdapterResult -> platform-native response

Contract guarantees (tested in tests/test_phase3_adapters.py):
  * semantically-equal events from different platforms produce IDENTICAL
    probe dicts, hence identical decisions and correlated receipts
  * fallback is explicit and logged, never silent
  * adapters never mutate host configuration
"""
from __future__ import annotations

import json
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.evaluator import Evaluator
from ..manifest_io import load as _manifest_load
from ..pdp.client import PDPClient, PDPConnectionError

DEFAULT_MANIFEST = "./authority.yaml"


def new_trace_id() -> str:
    return "trc_" + uuid.uuid4().hex[:12]


@dataclass
class AdapterResult:
    allowed: bool
    reason: str
    rule: str = ""
    via: str = "pdp"                    # pdp | local-fallback | error-fail-closed
    enforcement: str = "enforcing"      # enforcing | advisory
    probe: Dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""
    raw: Optional[dict] = None

    def blocked(self) -> bool:
        return not self.allowed


@dataclass
class Response:
    exit_code: int                      # 0 allow; 2 block (uniform convention)
    stdout_payload: Optional[dict]      # structured JSON where supported
    stderr_text: str


class AdapterSpec(ABC):
    """Subclass per platform; classify() is the ONLY platform-specific code."""

    name: str = "adapter"
    session_key: str = "session_id"
    supports_json_output: bool = False

    # ------------------------------------------------------- classification
    @abstractmethod
    def classify(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Platform event -> neutral probe dict {kind: action/path/host/spawn/...}."""

    # -------------------------------------------------------------- decide
    def decide(self, event: Dict[str, Any], *,
               pdp_client: Optional[PDPClient] = None,
               manifest_path: Optional[str] = None) -> AdapterResult:
        probe = self.classify(event or {})
        trace_id = (event or {}).get(self.session_key) or new_trace_id()

        client = pdp_client
        if client is None:
            client = PDPClient()  # honors SENTINEL_PDP_URL env

        try:
            raw = client.evaluate(dict(probe), trace_id=trace_id)
            dec = raw.get("decision", {})
            return AdapterResult(
                allowed=bool(dec.get("allowed")),
                reason=dec.get("reason", ""),
                rule=f"{dec.get('rule', '')} [via:pdp]",
                via="pdp",
                enforcement=raw.get("enforcement", "enforcing"),
                probe=probe, trace_id=trace_id, raw=raw)
        except PDPConnectionError as e:
            print(f"[Sentinel/{self.name}] PDP unavailable ({e}); "
                  "falling back to local manifest evaluation", file=sys.stderr)
            try:
                m = _manifest_load(manifest_path or DEFAULT_MANIFEST)
            except FileNotFoundError:
                return AdapterResult(
                    allowed=False,
                    reason="PDP unreachable and no fallback manifest found; "
                           "fail closed",
                    rule="no-bundle", via="error-fail-closed",
                    probe=probe, trace_id=trace_id)
            dec = self._evaluate_locally(m, probe)
            return AdapterResult(
                allowed=dec.allowed, reason=str(dec), rule=dec.rule,
                via="local-fallback", probe=probe, trace_id=trace_id)

    @staticmethod
    def _evaluate_locally(manifest, probe: Dict[str, Any]):
        ev = Evaluator(manifest)
        kind = probe.get("kind")
        if kind == "path":
            return ev.check_path(probe["path"], probe.get("mode", "r"))
        if kind == "host":
            return ev.check_host(probe["host"], probe.get("port", 443))
        if kind == "spawn":
            return ev.check_spawn(probe["executable"])
        if kind == "environment":
            return ev.check_environment(probe["name"])
        if kind == "delegation":
            return ev.check_delegation(int(probe["depth"]))
        if kind == "constraint":
            return ev.check_constraints(probe["action"],
                                        probe.get("params") or {})
        return ev.check_action(probe.get("action", ""))

    # ------------------------------------------------------------- respond
    def respond(self, result: AdapterResult,
                style: str = "auto",
                event: Optional[Dict[str, Any]] = None) -> Response:
        """style: 'json' (structured payload, exit 0) or 'code' (exit codes)."""
        use_json = (style == "json") or (style == "auto"
                                         and self.supports_json_output)
        if result.blocked():
            stderr = f"[Sentinel/{self.name}] BLOCKED: {result.reason}"
            if use_json and self.supports_json_output:
                payload = self.json_block_payload(result, event or {})
                return Response(exit_code=0, stdout_payload=payload,
                                stderr_text="")
            return Response(exit_code=2, stdout_payload=None,
                            stderr_text=stderr)
        if use_json and self.supports_json_output:
            return Response(exit_code=0,
                            stdout_payload=self.json_allow_payload(result),
                            stderr_text="")
        return Response(exit_code=0, stdout_payload=None, stderr_text="")

    # default JSON shapes; claude_code overrides to official schema
    def json_allow_payload(self, result: AdapterResult) -> dict:
        return {"permission": "allow", "sentinel": self._sentinel_meta(result)}

    def json_block_payload(self, result: AdapterResult,
                           event: Dict[str, Any]) -> dict:
        return {"permission": "deny",
                "reason": result.reason,
                "sentinel": self._sentinel_meta(result)}

    def _sentinel_meta(self, r: AdapterResult) -> dict:
        return {"adapter": self.name, "rule": r.rule, "via": r.via,
                "trace_id": r.trace_id, "enforcement": r.enforcement}


# --------------------------------------------------------------------- io
def read_event(stdin=sys.stdin) -> Dict[str, Any]:
    raw = stdin.read().strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"event is not valid JSON: {e}")
    if isinstance(obj, dict):
        return obj
    raise ValueError("event must be a JSON object")


def run_adapter(spec: AdapterSpec, argv: Optional[list] = None,
                stdin=sys.stdin) -> int:
    """Shared entrypoint: python -m sentinel.adapters.<platform> [--style X]."""
    argv = list(argv or [])
    style = "auto"
    if "--style" in argv:
        i = argv.index("--style")
        style = argv[i + 1] if len(argv) > i + 1 else "auto"
    try:
        event = read_event(stdin)
    except ValueError as e:
        # malformed event: fail closed but do not crash the host session
        print(f"[Sentinel/{spec.name}] malformed event: {e}", file=sys.stderr)
        return 2
    result = spec.decide(event)
    resp = spec.respond(result, style=style, event=event)
    if resp.stdout_payload is not None:
        print(json.dumps(resp.stdout_payload))
    if resp.stderr_text:
        print(resp.stderr_text, file=sys.stderr)
    return resp.exit_code


# --------------------------------------------------------- shared classifiers
def first_token(command: str) -> str:
    return (command or "").strip().split()[0] if (command or "").strip() else ""


def host_from_url(url: str) -> str:
    u = str(url or "")
    if "://" in u:
        return u.split("://", 1)[1].split("/", 1)[0]
    return u.split("/", 1)[0]
