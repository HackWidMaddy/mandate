"""Signed, versioned, expiring Authority bundles.

A bundle is the ONLY artifact a PDP will enforce. It wraps an Authority
Manifest with metadata and an ed25519 signature over the canonical bytes of
{manifest, meta}:

    digest = sha256(canonical_json({"manifest": m, "meta": meta}))
    bundle = {"bundle_version": "1",
              "manifest": {...}, "meta": {...},
              "signature": {"alg": "ed25519", "key_id": ..., "sig": b64}}

Verification requires: structural validity, known trust anchor for key_id,
valid signature, and (optionally enforced at evaluate-time) temporal window.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.schema import Manifest
from .signing import ALGORITHM, AnchorVerifier, FileEd25519Signer, Signer, \
    b64e, canonical_json, digest_of

BUNDLE_VERSION = "1"


class BundleError(Exception):
    pass


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PolicyBundle:
    manifest: Manifest
    meta: Dict[str, Any] = field(default_factory=dict)
    signature: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------ build
    @classmethod
    def build(cls, manifest: Manifest, epoch: int = 1,
              issued_for: Optional[str] = None,
              planner_source: str = "rules") -> "PolicyBundle":
        meta_core = {
            "created_at": _utcnow_iso(),
            "epoch": int(epoch),
            "issued_for": issued_for or manifest.principal.get("agent", "agent"),
            "planner_source": planner_source,
        }
        # identity derives ONLY from content fields, never from itself
        content_digest = digest_of({"manifest": manifest.to_dict(),
                                    "meta": meta_core})
        meta = dict(meta_core)
        meta["content_sha256"] = content_digest
        meta["bundle_id"] = "bdl_" + content_digest[:12]
        return cls(manifest=manifest, meta=meta)

    # ------------------------------------------------------------- sign
    def to_signable(self) -> Dict[str, Any]:
        return {"manifest": self.manifest.to_dict(), "meta": self.meta}

    @property
    def digest(self) -> str:
        return digest_of(self.to_signable())

    @property
    def bundle_id(self) -> str:
        return self.meta.get("bundle_id", "")

    def sign(self, signer: Signer) -> None:
        sig = signer.sign(canonical_json(self.to_signable()))
        self.signature = {"alg": ALGORITHM, "key_id": signer.key_id,
                          "sig": b64e(sig)}

    # --------------------------------------------------------------- IO
    def to_dict(self) -> Dict[str, Any]:
        if not self.signature:
            raise BundleError("refusing to serialize unsigned bundle")
        return {
            "bundle_version": BUNDLE_VERSION,
            "manifest": self.manifest.to_dict(),
            "meta": self.meta,
            "signature": dict(self.signature),
        }

    def to_file(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return p

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyBundle":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "PolicyBundle":
        if not isinstance(raw, dict):
            raise BundleError("bundle root must be an object")
        version = str(raw.get("bundle_version", ""))
        if version != BUNDLE_VERSION:
            raise BundleError(f"unsupported bundle_version {version!r}")
        manifest = Manifest.from_dict(raw.get("manifest"))
        meta = dict(raw.get("meta") or {})
        signature = dict(raw.get("signature") or {})
        if signature.get("alg") != ALGORITHM:
            raise BundleError("missing/unsupported signature algorithm")
        return cls(manifest=manifest, meta=meta, signature=signature)

    # --------------------------------------------------------- verify
    def verify_signature(self, verifier: AnchorVerifier) -> None:
        """Raise BundleError unless identity + signature both verify under
        pinned trust anchors."""
        meta_core = {k: v for k, v in self.meta.items()
                     if k not in ("bundle_id", "content_sha256")}
        expected_digest = digest_of({"manifest": self.manifest.to_dict(),
                                     "meta": meta_core})
        if self.meta.get("content_sha256") != expected_digest:
            raise BundleError(
                "content hash mismatch - manifest or metadata tampered")
        expected_id = "bdl_" + expected_digest[:12]
        if self.meta.get("bundle_id") != expected_id:
            raise BundleError(
                f"identity mismatch: bundle_id says "
                f"{self.meta.get('bundle_id')} but content hashes to {expected_id}")
        key_id = self.signature.get("key_id", "")
        sig = self.signature.get("sig", "")
        if not key_id or not sig:
            raise BundleError("incomplete signature block")
        if not verifier.verify(canonical_json(self.to_signable()), sig, key_id):
            raise BundleError(
                f"signature invalid for key_id={key_id!r} "
                "(not signed by a trusted anchor)")

    def check_temporal(self, now: Optional[datetime] = None) -> None:
        m = self.manifest
        if m.not_yet_active(now=now):
            raise BundleError(f"bundle authority not yet active "
                              f"(not_before {m.not_before})")
        if m.expired(now=now):
            raise BundleError(f"bundle expired at {m.expires_at}")

    def load_and_verify(self, keys_dir: str | Path,
                        now: Optional[datetime] = None) -> "PolicyBundle":
        self.verify_signature(AnchorVerifier(keys_dir))
        return self


def default_deploy_path() -> Path:
    home = Path(os.environ.get("SENTINEL_HOME_DATA",
                               str(Path.home() / ".sentinel")))
    return home / "deployed" / "current.bundle.json"


def atomic_write_bundle(bundle: PolicyBundle, path: str | Path) -> Path:
    """Deploy atomically: write temp, fsync, replace."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp-" + uuid.uuid4().hex[:8])
    tmp.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
    with open(tmp, "ab") as f:  # flush + fsync before replace
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    return p
