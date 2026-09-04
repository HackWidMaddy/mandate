"""Local Policy Decision Point engine.

Verify-then-serve: the engine refuses to evaluate anything until a bundle
verifies under pinned trust anchors and is neither expired nor revoked.
With no valid bundle it denies EVERYTHING (fail closed).

The enforcement path has zero network dependencies - a control-plane outage
(or its absence) can never disable local deterministic enforcement.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..bundle.bundle import PolicyBundle
from ..bundle.revocation import RevocationList
from ..bundle.signing import AnchorVerifier
from ..core.evaluator import Evaluator
from ..evidence import EvidenceLedger

PROBE_KINDS = ("action", "path", "host", "spawn", "environment",
               "delegation", "constraint")


@dataclass
class PDPStatus:
    started_at: float = field(default_factory=time.monotonic)
    decisions: int = 0
    allowed: int = 0
    denied: int = 0
    latencies_ms: list = field(default_factory=list)


class PDPEngine:
    def __init__(self,
                 deploy_path: str | Path,
                 keys_dir: str | Path,
                 revocations_path: Optional[str | Path] = None,
                 evidence_path: Optional[str | Path] = None,
                 mode: str = "enforcing",   # enforcing | advisory
                 signer=None):
        self.deploy_path = Path(deploy_path)
        self.keys_dir = Path(keys_dir)
        self.verifier = AnchorVerifier(self.keys_dir)
        self.revocations_path = Path(revocations_path) if revocations_path else \
            self.deploy_path.parent.parent / "revocations.jsonl"
        self.mode = mode if mode in ("enforcing", "advisory") else "enforcing"
        self.signer = signer
        self._lock = threading.RLock()
        self.status = PDPStatus()
        self._deploy_mtime: Optional[float] = None
        self.bundle: Optional[PolicyBundle] = None
        self.load_error: Optional[str] = None
        self.ledger = (EvidenceLedger(evidence_path, signer=signer)
                       if evidence_path else None)
        self.reload_bundle(force=True)

    # ------------------------------------------------------------- bundle
    def reload_bundle(self, force: bool = False) -> None:
        with self._lock:
            mtime = (self.deploy_path.stat().st_mtime
                     if self.deploy_path.exists() else None)
            if not force and mtime == self._deploy_mtime:
                return
            self._deploy_mtime = mtime
            self.bundle = None
            self.load_error = None
            if mtime is None:
                self.load_error = f"no deployed bundle at {self.deploy_path}"
                return
            try:
                raw = PolicyBundle.from_file(self.deploy_path)
                raw.verify_signature(self.verifier)
                self.bundle = raw
                # temporal + revocation checked live per-evaluate; signature
                # checked now so tampering is reported immediately.
            except Exception as e:  # noqa: BLE001 - any failure = no authority
                self.bundle = None
                self.load_error = f"bundle rejected: {e}"

    def _revocation_list(self) -> RevocationList:
        return RevocationList(self.revocations_path)

    # ------------------------------------------------------------ probe
    @staticmethod
    def _validate_probe(probe: Dict[str, Any]) -> Optional[str]:
        if not isinstance(probe, dict):
            return "probe must be an object"
        kind = probe.get("kind")
        if kind not in PROBE_KINDS:
            return f"unknown probe kind {kind!r}; expected one of {PROBE_KINDS}"
        required = {
            "action": ("action",), "path": ("path",), "host": ("host",),
            "spawn": ("executable",), "environment": ("name",),
            "delegation": ("depth",), "constraint": ("action",),
        }[kind]
        missing = [k for k in required if k not in probe]
        if missing:
            return f"missing probe fields: {', '.join(missing)}"
        return None

    def _evaluate_core(self, probe: Dict[str, Any]):
        manifest = self.bundle.manifest
        ev = Evaluator(manifest, base_dir=str(Path.cwd()))
        kind = probe["kind"]
        if kind == "action":
            return ev.check_action(probe["action"], params=probe.get("params"))
        if kind == "constraint":
            return ev.check_constraints(probe["action"], probe.get("params") or {})
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
        raise AssertionError("unreachable")

    # ---------------------------------------------------------- evaluate
    def evaluate(self, probe: Dict[str, Any],
                 trace_id: Optional[str] = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        with self._lock:
            self.reload_bundle()
            action_desc: Dict[str, Any] = {}
            decision = None
            blocked_reason = None

            err = self._validate_probe(probe)
            if err:
                allowed, reason, rule = False, err, "bad-request"
            else:
                if self.bundle is None:
                    allowed = False
                    reason = (self.load_error or
                              "no valid deployed authority; fail closed")
                    rule = "no-bundle"
                else:
                    # live temporal check (window may have passed since load)
                    try:
                        self.bundle.check_temporal(
                            now=datetime.now(timezone.utc))
                    except Exception as e:  # noqa: BLE001
                        allowed, reason, rule = False, str(e), "temporal"
                        self.bundle = None  # refuse until redeployed/rotated
                    else:
                        rl = self._revocation_list()
                        try:
                            revoked = rl.is_revoked(
                                self.bundle.bundle_id,
                                verifier=self.verifier, strict=True)
                        except Exception as e:  # noqa: BLE001
                            allowed = False
                            reason = f"revocation list unusable: {e}; fail closed"
                            rule = "revocation-integrity"
                            revoked = None
                        if revoked is True:
                            allowed = False
                            reason = (f"bundle {self.bundle.bundle_id} "
                                      "has been revoked")
                            rule = "revoked"
                        elif revoked is None:
                            pass  # already denied above
                        else:
                            decision = self._evaluate_core(probe)
                            allowed, reason, rule = (decision.allowed,
                                                     decision.reason,
                                                     decision.rule)

            latency_ms = round((time.perf_counter() - t0) * 1000, 3)

            # describe the action for humans + receipts
            kind = probe.get("kind", "?")
            target = (probe.get("action") or probe.get("path")
                      or probe.get("host") or probe.get("executable")
                      or probe.get("name") or "")
            action_desc = {"type": kind, "target": str(target)[:512]}
            detail_bits = []
            if kind == "path":
                detail_bits.append(probe.get("mode", "r"))
            if probe.get("params"):
                detail_bits.append(f"params:{len(probe['params'])}")
            action_desc["detail"] = " ".join([str(target)] + detail_bits)[:512]

            result = {
                "decision": {"allowed": bool(allowed),
                             "reason": reason,
                             "rule": rule},
                "enforcement": self.mode,
                "latency_ms": latency_ms,
            }
            if decision is not None:
                result["decision"]["detail"] = str(decision)

            # evidence receipt for every consequential decision
            if self.ledger is not None:
                if self.bundle is not None:
                    md = self.bundle.manifest.to_dict()
                    bid, sha = self.bundle.bundle_id, self.bundle.digest
                else:
                    md, bid, sha = {}, "-", "-"
                try:
                    line = self.ledger.record(
                        bundle_id=bid, policy_sha256=sha,
                        manifest_dict=md, action=action_desc,
                        allowed=bool(allowed), reason=reason, rule=rule,
                        enforcement=self.mode, trace_id=trace_id)
                    result["receipt"] = {"sequence": line["sequence"],
                                         "receipt_hash": line["receipt_hash"],
                                         "trace_id": line["trace_id"],
                                         "signed": bool(line.get("signature"))}
                except Exception as e:  # noqa: BLE001
                    result["receipt_error"] = str(e)

            st = self.status
            st.decisions += 1
            st.allowed += 1 if allowed else 0
            st.denied += 0 if allowed else 1
            st.latencies_ms.append(latency_ms)
            return result

    # ------------------------------------------------------------- status
    def health(self) -> Dict[str, Any]:
        with self._lock:
            self.reload_bundle()
            b = self.bundle
            st = self.status
            lats = sorted(st.latencies_ms[-500:])
            p99 = lats[int(len(lats) * 0.99)] if lats else 0.0
            return {
                "status": "ready" if b else "fail-closed",
                "mode": self.mode,
                "bundle_id": b.bundle_id if b else None,
                "policy_sha256": b.digest if b else None,
                "expires_at": b.manifest.expires_at if b else None,
                "not_before": b.manifest.not_before if b else None,
                "mandate_id": b.manifest.mandate_id if b else None,
                "load_error": self.load_error,
                "decisions": st.decisions,
                "allowed": st.allowed,
                "denied": st.denied,
                "p99_latency_ms": p99,
                "uptime_s": round(time.monotonic() - st.started_at, 1),
            }

    def bundle_metadata(self) -> Dict[str, Any]:
        with self._lock:
            if self.bundle is None:
                return {"loaded": False, "error": self.load_error}
            b = self.bundle
            return {"loaded": True,
                    "bundle_id": b.bundle_id,
                    "policy_sha256": b.digest,
                    "meta": b.meta,
                    "manifest_summary": {
                        "agent": b.manifest.principal.get("agent"),
                        "objective": b.manifest.task.get("objective"),
                        "expires_at": b.manifest.expires_at,
                        "not_before": b.manifest.not_before,
                    }}

    # ------------------------------------------------------------- metrics
    def metrics_text(self) -> str:
        h = self.health()
        lines = [
            "# HELP sentinel_pdp_decisions_total Total authorization decisions.",
            "# TYPE sentinel_pdp_decisions_total counter",
            f'sentinel_pdp_decisions_total{{decision="allow"}} {h["allowed"]}',
            f'sentinel_pdp_decisions_total{{decision="deny"}} {h["denied"]}',
            "# HELP sentinel_pdp_decision_latency_ms p99 decision latency.",
            "# TYPE sentinel_pdp_decision_latency_ms gauge",
            f"sentinel_pdp_decision_latency_ms {h['p99_latency_ms']}",
            "# HELP sentinel_pdp_bundle_loaded Whether a valid bundle is loaded.",
            "# TYPE sentinel_pdp_bundle_loaded gauge",
            f"sentinel_pdp_bundle_loaded {1 if h['status'] == 'ready' else 0}",
        ]
        return "\n".join(lines) + "\n"
