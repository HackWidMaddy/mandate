"""Signing primitives for policy bundles and evidence receipts.

Design rules (from the enterprise blueprint):

* Signatures are computed over CANONICAL JSON bytes - identical logical
  content must always produce identical bytes, across languages.
* Trust anchors are pinned PUBLIC KEYS on disk. A signature is valid only if
  it verifies under the anchor matching its key_id. A compromised registry
  or database must never be sufficient to forge policy.
* The signing abstraction (Signer/Verifier protocols) exists so a cloud
  KMS/HSM-backed implementation can replace file keys without touching any
  caller.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional, Protocol

ALGORITHM = "ed25519"


# --------------------------------------------------------------------------
# canonical serialization
# --------------------------------------------------------------------------
def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding: sorted keys, compact separators, UTF-8.

    Data written by Sentinel manifests/bundles/receipts contains no floats,
    so this encoding is stable across Python versions and languages.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(obj) -> str:
    return sha256_hex(canonical_json(obj))


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# --------------------------------------------------------------------------
# key material
# --------------------------------------------------------------------------
def _require_crypto():
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: F401
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        return serialization, Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "sentinel bundle signing requires the 'cryptography' package "
            "(pip install cryptography)") from e


def new_key_id(public_pem: bytes) -> str:
    return "ed25519_" + hashlib.sha256(public_pem).hexdigest()[:12]


def generate_keypair(keys_dir: str | Path) -> Dict[str, str]:
    """Create an ed25519 keypair on disk; returns {key_id, private, public}."""
    serialization, Ed25519PrivateKey, _ = _require_crypto()
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = new_key_id(pub_pem)
    priv_path = keys_dir / f"{key_id}.pem"
    pub_path = keys_dir / f"{key_id}.pub"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    for p in (priv_path,):
        try:
            os.chmod(p, 0o600)  # best-effort on Windows
        except OSError:
            pass
    return {"key_id": key_id, "private": str(priv_path), "public": str(pub_path)}


def load_private_pem(path: str | Path):
    serialization, _, _ = _require_crypto()
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_pem(path: str | Path):
    serialization, _, _ = _require_crypto()
    return serialization.load_pem_public_key(Path(path).read_bytes())


# --------------------------------------------------------------------------
# signer / verifier
# --------------------------------------------------------------------------
class Signer(Protocol):
    key_id: str

    def sign(self, data: bytes) -> bytes: ...


class FileEd25519Signer:
    """Signs with a PEM private key file. Swap for a KMS signer later."""

    def __init__(self, private_pem_path: str | Path, key_id: Optional[str] = None):
        from cryptography.hazmat.primitives import serialization

        self._key = load_private_pem(private_pem_path)
        pub_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = key_id or new_key_id(pub_pem)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class AnchorVerifier:
    """Verifies signatures against pinned public-key anchors in a directory.

    Directory layout: <keys_dir>/<key_id>.pub
    """

    def __init__(self, keys_dir: str | Path):
        self.keys_dir = Path(keys_dir)

    def verify(self, data: bytes, signature_b64: str, key_id: str) -> bool:
        anchor = self.keys_dir / f"{key_id}.pub"
        if not anchor.exists():
            return False
        try:
            pub = load_public_pem(anchor)
            pub.verify(b64d(signature_b64), data)
            return True
        except Exception:  # noqa: BLE001 - any crypto failure = invalid
            return False
