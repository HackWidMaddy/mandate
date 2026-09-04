"""Append-only, signed revocation list.

Each entry revokes one bundle_id. Entries are individually signed and
hash-chained so deletion or reordering is detectable:

    core  = {"bundle_id","reason","revoked_at","prev_hash"}
    hash  = sha256(canonical_json(core))
    line  = core + {"entry_hash", "key_id", "sig"(over canonical_json(core))}

The list is small; the PDP reloads it whenever its file mtime changes and
refuses to serve a revoked bundle even if its signature is valid.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .signing import AnchorVerifier, FileEd25519Signer, Signer, b64e, \
    canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


class RevocationError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RevocationList:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._entries: List[dict] = []
        self._mtime: Optional[float] = None
        self.reload_if_changed(force=True)

    # -------------------------------------------------------------- io
    def _read(self) -> List[dict]:
        if not self.path.exists():
            return []
        entries = []
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RevocationError(f"corrupt revocation entry at line {i+1}: {e}")
        return entries

    def reload_if_changed(self, force: bool = False) -> None:
        mtime = self.path.stat().st_mtime if self.path.exists() else None
        if force or mtime != self._mtime:
            self._entries = self._read()
            self._mtime = mtime

    # ----------------------------------------------------------- write
    def revoke(self, bundle_id: str, reason: str, signer: Signer,
               now: Optional[datetime] = None) -> dict:
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else GENESIS_HASH
        core = {
            "bundle_id": bundle_id,
            "reason": reason,
            "prev_hash": prev_hash,
            "revoked_at": (now or datetime.now(timezone.utc)).isoformat(),
        }
        entry = dict(core)
        entry["entry_hash"] = sha256_hex(canonical_json(core))
        entry["key_id"] = signer.key_id
        entry["sig"] = b64e(signer.sign(canonical_json(core)))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.reload_if_changed(force=True)
        return entry

    # ---------------------------------------------------------- query
    def is_revoked(self, bundle_id: str, verifier: Optional[AnchorVerifier] = None,
                   strict: bool = False) -> bool:
        """True if any VALID entry revokes bundle_id.

        strict=True additionally fails closed on any invalid/tampered entry.
        """
        self.reload_if_changed()
        prev = GENESIS_HASH
        hit = False
        for i, e in enumerate(self._entries):
            core = {"bundle_id": e.get("bundle_id"), "reason": e.get("reason"),
                    "prev_hash": e.get("prev_hash"),
                    "revoked_at": e.get("revoked_at")}
            h = sha256_hex(canonical_json(core))
            valid = (
                e.get("prev_hash") == prev
                and e.get("entry_hash") == h
                and (verifier is None or verifier.verify(
                    canonical_json(core), e.get("sig", ""), e.get("key_id", "")))
            )
            if not valid:
                if strict:
                    raise RevocationError(
                        f"revocation list integrity failure at entry {i+1}")
                prev = e.get("entry_hash", prev)
                continue
            prev = h
            if e.get("bundle_id") == bundle_id:
                hit = True
        return hit

    def entries(self) -> List[dict]:
        self.reload_if_changed()
        return list(self._entries)
