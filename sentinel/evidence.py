"""Append-only, signed, hash-chained decision receipts.

Every consequential authorization decision becomes a receipt:

    receipt = {receipt_version, ts, sequence, previous_receipt_hash,
               principal{...}, task_id?, mandate_id?,
               policy{bundle_id, sha256}, delegation{...},
               action{...}, decision, reason, rule,
               trace_id, enforcement}
    receipt_hash = sha256(canonical_json(receipt))
    line         = receipt + {"receipt_hash", "key_id", "signature"}

Properties:
  * individually signed  - a stolen database is not enough to forge one
  * hash chained         - deletion/reordering/modification is detectable
  * append-only JSONL    - the file is the source of truth; searchable
                           projections come later with the control plane

Verify with `sentinel evidence verify [FILE]`.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bundle.signing import AnchorVerifier, Signer, b64e, canonical_json, \
    sha256_hex

RECEIPT_VERSION = "1.0"
GENESIS_HASH = "0" * 64
SIGNED_EXCLUDED = ("key_id", "signature")


class EvidenceError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_trace_id() -> str:
    return "trc_" + uuid.uuid4().hex[:12]


class EvidenceLedger:
    def __init__(self, path: str | Path, signer: Optional[Signer] = None):
        self.path = Path(path)
        self.signer = signer
        self._lock_held = False  # engine-level lock owns concurrency
        self.sequence = -1
        self.prev_hash = GENESIS_HASH
        self._prime_from_existing_file()

    # ------------------------------------------------------------- prime
    def _prime_from_existing_file(self) -> None:
        if not self.path.exists():
            return
        last = None
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return
        rec = json.loads(last)
        self.sequence = int(rec.get("sequence", -1))
        self.prev_hash = rec.get("receipt_hash") or rec.get(
            "previous_receipt_hash", GENESIS_HASH)

    # ------------------------------------------------------------ append
    def build_receipt(self, *, bundle_id: str, policy_sha256: str,
                      manifest_dict: Dict[str, Any], action: Dict[str, Any],
                      allowed: bool, reason: str, rule: str,
                      enforcement: str = "enforcing",
                      trace_id: Optional[str] = None) -> Dict[str, Any]:
        delegation = manifest_dict.get("delegation", {})
        receipt = {
            "receipt_version": RECEIPT_VERSION,
            "ts": _now_iso(),
            "sequence": self.sequence + 1,
            "previous_receipt_hash": self.prev_hash,
            "principal": {
                "human_subject": manifest_dict.get("human_subject"),
                "agent": manifest_dict.get("principal", {}).get("agent"),
            },
            "mandate_id": manifest_dict.get("mandate_id"),
            "policy": {"bundle_id": bundle_id, "sha256": policy_sha256},
            "delegation": {
                "parent_mandate": delegation.get("parent_mandate"),
                "depth": delegation.get("depth", 0),
            },
            "action": action,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
            "rule": rule,
            "trace_id": trace_id or new_trace_id(),
            "enforcement": enforcement,
        }
        return receipt

    def append(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        """Finalize (hash + sign) and persist a receipt; returns the full line."""
        core = canonical_json(receipt)
        line: Dict[str, Any] = dict(receipt)
        line["receipt_hash"] = sha256_hex(core)
        if self.signer is not None:
            line["key_id"] = self.signer.key_id
            line["signature"] = b64e(self.signer.sign(core))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(line) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.sequence += 1
        self.prev_hash = line["receipt_hash"]
        return line

    def record(self, **kwargs) -> Dict[str, Any]:
        return self.append(self.build_receipt(**kwargs))

    # ------------------------------------------------------------ verify
    @staticmethod
    def verify(path: str | Path, verifier: Optional[AnchorVerifier] = None
               ) -> Dict[str, Any]:
        """Replay the whole chain. Returns summary; raises EvidenceError on the
        first broken entry, naming its line number."""
        p = Path(path)
        checked = 0
        prev = GENESIS_HASH
        if not p.exists():
            raise EvidenceError(f"evidence file not found: {p}")
        with p.open(encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    line = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise EvidenceError(f"line {lineno}: not valid JSON ({e})")

                expected_prev = line.get("previous_receipt_hash")
                if expected_prev != prev:
                    raise EvidenceError(
                        f"line {lineno}: chain break - previous_receipt_hash "
                        f"does not match predecessor "
                        f"(expected {prev[:16]}..., got {str(expected_prev)[:16]}...)")

                core_fields = {k: v for k, v in line.items()
                               if k not in SIGNED_EXCLUDED
                               and k != "receipt_hash"}
                h = sha256_hex(canonical_json(core_fields))
                if line.get("receipt_hash") != h:
                    raise EvidenceError(
                        f"line {lineno}: receipt content tampered "
                        "(hash mismatch)")

                if verifier is not None:
                    key_id = line.get("key_id", "")
                    sig = line.get("signature", "")
                    if not key_id or not sig or not verifier.verify(
                            canonical_json(core_fields), sig, key_id):
                        raise EvidenceError(
                            f"line {lineno}: signature invalid or unknown key")

                prev = line["receipt_hash"]
                checked += 1
        return {"lines_checked": checked, "head_hash": prev,
                "verdict": "INTACT" if checked else "EMPTY"}


def summarize_line(line: Dict[str, Any]) -> str:
    a = line.get("action", {})
    what = a.get("detail") or a.get("target") or a.get("name", "?")
    return (f"[{line.get('ts', '?')}] {line.get('decision')} "
            f"{what} [{line.get('rule', '')}]")
