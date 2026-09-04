"""Phase 1: signed bundles, revocation, evidence ledger, local PDP."""
import json
import threading
import time

import pytest

from sentinel.bundle.bundle import BundleError, PolicyBundle, atomic_write_bundle
from sentinel.bundle.revocation import RevocationError, RevocationList
from sentinel.bundle.signing import (AnchorVerifier, FileEd25519Signer,
                                     canonical_json, digest_of, generate_keypair)
from sentinel.core.schema import Manifest
from sentinel.evidence import EvidenceError, EvidenceLedger
from sentinel.manifest_io import load as mio_load, save as mio_save
from sentinel.pdp.client import PDPClient
from sentinel.pdp.engine import PDPEngine
from sentinel.pdp.server import PDPServer

FAR_FUTURE = "2099-01-01T00:00:00+00:00"
RECENT_PAST = "2020-01-01T00:00:00+00:00"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    info = generate_keypair(d)
    return {"dir": d, **info}


@pytest.fixture(scope="module")
def signer(keys):
    return FileEd25519Signer(keys["private"])


@pytest.fixture(scope="module")
def verifier(keys):
    return AnchorVerifier(keys["dir"])


@pytest.fixture
def manifest_dict():
    return {
        "principal": {"agent": "claude-code"},
        "task": {"repo": "acme/backend", "objective": "fix_and_open_pr"},
        "tools": {"allow": ["github.*", "npm.*"], "deny": ["aws.*"]},
        "filesystem": {"read": ["workspace/**"], "write": ["workspace/**"],
                       "deny": ["**/.env"]},
        "network": {"allow": ["github.com"], "deny": []},
        "delegation": {"max_depth": 1},
        "not_before": RECENT_PAST,
        "expires_at": FAR_FUTURE,
    }


@pytest.fixture
def signed_bundle(manifest_dict, signer):
    b = PolicyBundle.build(Manifest.from_dict(manifest_dict), issued_for="test")
    b.sign(signer)
    return b


# ---------------------------------------------------------------- canonical
def test_canonical_json_is_order_insensitive():
    a = {"b": 1, "a": {"y": 2, "x": [3, 1]}}
    b = {"a": {"x": [3, 1], "y": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert digest_of(a) == digest_of(b)


# ------------------------------------------------------------------- bundle
def test_sign_and_verify_roundtrip(signed_bundle, verifier):
    signed_bundle.verify_signature(verifier)  # must not raise
    assert signed_bundle.bundle_id.startswith("bdl_")


def test_tampered_manifest_rejected(signed_bundle, verifier):
    raw = signed_bundle.to_dict()
    raw["manifest"]["tools"]["allow"].append("aws.*")  # privilege expansion!
    t = PolicyBundle.from_dict(raw)
    with pytest.raises(BundleError, match="tampered|hash mismatch"):
        t.verify_signature(verifier)


def test_tampered_meta_rejected(signed_bundle, verifier):
    raw = signed_bundle.to_dict()
    raw["meta"]["epoch"] = 99
    with pytest.raises(BundleError):
        PolicyBundle.from_dict(raw).verify_signature(verifier)


def test_wrong_key_rejected(manifest_dict, keys, signer, verifier,
                            tmp_path):
    # rogue keypair lives OUTSIDE the trust-anchor directory
    other = generate_keypair(tmp_path / "rogue_keys")
    b = PolicyBundle.build(Manifest.from_dict(manifest_dict))
    rogue = FileEd25519Signer(other["private"])
    b.sign(rogue)
    with pytest.raises(BundleError, match="signature invalid"):
        b.verify_signature(verifier)


def test_unknown_key_id_rejected(manifest_dict, verifier):
    b = PolicyBundle.build(Manifest.from_dict(manifest_dict))
    raw = {"bundle_version": "1",
           "manifest": b.manifest.to_dict(),
           "meta": b.meta,
           "signature": {"alg": "ed25519",
                         "key_id": "ed25519_notananchor00", "sig": "AAAA"}}
    with pytest.raises(BundleError, match="signature invalid"):
        PolicyBundle.from_dict(raw).verify_signature(verifier)


def test_expired_bundle_refused(manifest_dict):
    manifest_dict["expires_at"] = "2001-01-01T00:00:00+00:00"
    b = PolicyBundle.build(Manifest.from_dict(manifest_dict))
    with pytest.raises(BundleError, match="expired"):
        b.check_temporal()


def test_not_yet_active_refused(manifest_dict):
    manifest_dict["not_before"] = FAR_FUTURE
    b = PolicyBundle.build(Manifest.from_dict(manifest_dict))
    with pytest.raises(BundleError, match="not yet active"):
        b.check_temporal()


def test_atomic_deploy_then_load(tmp_path, signed_bundle, verifier):
    target = tmp_path / "deployed" / "current.bundle.json"
    atomic_write_bundle(signed_bundle, target)
    loaded = PolicyBundle.from_file(target)
    loaded.verify_signature(verifier)
    assert loaded.bundle_id == signed_bundle.bundle_id


# -------------------------------------------------------------- revocation
def test_revocation_flow(tmp_path, keys, signer, verifier, signed_bundle):
    rl = RevocationList(tmp_path / "revocations.jsonl")
    assert not rl.is_revoked(signed_bundle.bundle_id, verifier=verifier)
    rl.revoke(signed_bundle.bundle_id, "stale policy", signer)
    rl2 = RevocationList(tmp_path / "revocations.jsonl")
    assert rl2.is_revoked(signed_bundle.bundle_id, verifier=verifier)
    assert not rl2.is_revoked("bdl_doesnotexist", verifier=verifier)


def test_revocation_tamper_detected_strict(tmp_path, keys, signer, verifier,
                                           signed_bundle):
    p = tmp_path / "revocations.jsonl"
    rl = RevocationList(p)
    rl.revoke(signed_bundle.bundle_id, "original reason", signer)
    lines = p.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["reason"] = "forged reason"
    lines[0] = json.dumps(entry)
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(RevocationError, match="integrity"):
        RevocationList(p).is_revoked(signed_bundle.bundle_id,
                                     verifier=verifier, strict=True)


# ---------------------------------------------------------------- evidence
def test_receipt_chain_intact_and_signed(tmp_path, signer, verifier):
    led = EvidenceLedger(tmp_path / "evidence.jsonl", signer=signer)
    for i in range(3):
        led.record(bundle_id=f"bdl_{i}", policy_sha256="ab" * 32,
                   manifest_dict={"principal": {"agent": "a"},
                                  "mandate_id": f"mdt_{i}",
                                  "delegation": {"depth": 0}},
                   action={"type": "action", "target": "github.repo.read",
                           "detail": "github.repo.read"},
                   allowed=(i % 2 == 0), reason="test", rule="tools.allow")
    report = EvidenceLedger.verify(tmp_path / "evidence.jsonl",
                                   verifier=verifier)
    assert report["lines_checked"] == 3 and report["verdict"] == "INTACT"


def test_receipt_tamper_named_line(tmp_path, signer):
    p = tmp_path / "evidence.jsonl"
    led = EvidenceLedger(p, signer=signer)
    for i in range(3):
        led.record(bundle_id="bdl_x", policy_sha256="cd" * 32,
                   manifest_dict={}, action={"type": "action",
                                             "target": f"t{i}", "detail": f"t{i}"},
                   allowed=False, reason="r", rule="default-deny")
    lines = p.read_text().splitlines()
    obj = json.loads(lines[1])
    obj["decision"] = "ALLOW"  # forge an allow mid-chain
    lines[1] = json.dumps(obj)
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(EvidenceError, match="line 2"):
        EvidenceLedger.verify(p, verifier=None)


def test_receipt_bad_signature_detected(tmp_path, signer, verifier):
    p = tmp_path / "evidence.jsonl"
    led = EvidenceLedger(p, signer=signer)
    led.record(bundle_id="bdl_y", policy_sha256="ef" * 32, manifest_dict={},
               action={"type": "action", "target": "t", "detail": "t"},
               allowed=True, reason="r", rule="tools.allow")
    lines = p.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["key_id"] = "ed25519_unknown0000"
    p.write_text(json.dumps(obj) + "\n")
    with pytest.raises(EvidenceError, match="signature invalid or unknown key"):
        EvidenceLedger.verify(p, verifier=verifier)


# --------------------------------------------------------------------- PDP
class TestPDPEndToEnd:
    @pytest.fixture
    def deployed(self, tmp_path, signed_bundle):
        dep = tmp_path / "data"
        deploy_target = dep / "deployed" / "current.bundle.json"
        atomic_write_bundle(signed_bundle, deploy_target)
        return {"root": dep, "target": deploy_target,
                "keys": signed_bundle and self.keys_dir}

    keys_dir = None  # set per-test below

    def _engine(self, tmp_path, keys, signer, signed_bundle, mode="enforcing"):
        data = tmp_path / "pdpdata"
        deploy_target = data / "deployed" / "current.bundle.json"
        atomic_write_bundle(signed_bundle, deploy_target)
        engine = PDPEngine(
            deploy_path=deploy_target, keys_dir=keys["dir"],
            revocations_path=data / "revocations.jsonl",
            evidence_path=data / "evidence.jsonl",
            mode=mode, signer=signer)
        return engine

    def test_allow_deny_through_http(self, tmp_path, keys, signer,
                                     signed_bundle):
        engine = self._engine(tmp_path, keys, signer, signed_bundle)
        server = PDPServer(engine, port=0)
        port = server.port
        server.start_background()
        time.sleep(0.15)
        try:
            client = PDPClient(f"http://127.0.0.1:{port}/v1/evaluate")
            deny = client.evaluate({"kind": "spawn", "executable": "aws"})
            assert deny["decision"]["allowed"] is False
            assert deny["receipt"]["signed"] is True

            allow = client.evaluate({"kind": "host", "host": "github.com"})
            assert allow["decision"]["allowed"] is True

            outside = client.evaluate(
                {"kind": "path", "path": str(tmp_path / "elsewhere" / "x.txt"),
                 "mode": "r"})
            assert outside["decision"]["allowed"] is False
            assert outside["decision"]["rule"] == "fs-default-deny"

            health = client.health()
            assert health["status"] == "ready"
            assert health["bundle_id"] == signed_bundle.bundle_id
            assert health["mode"] == "enforcing"
        finally:
            server.httpd.shutdown()

    def test_fail_closed_without_bundle(self, tmp_path, keys, signer):
        data = tmp_path / "empty"
        engine = PDPEngine(deploy_path=data / "none" / "current.bundle.json",
                           keys_dir=keys["dir"],
                           revocations_path=data / "rev.jsonl",
                           evidence_path=data / "ev.jsonl", signer=signer)
        r = engine.evaluate({"kind": "action", "action": "github.repo.read"})
        assert r["decision"]["allowed"] is False
        assert r["decision"]["rule"] in ("no-bundle",)

    def test_revoked_bundle_denied(self, tmp_path, keys, signer, verifier,
                                   signed_bundle):
        data = tmp_path / "pdpdata2"
        deploy_target = data / "deployed" / "current.bundle.json"
        atomic_write_bundle(signed_bundle, deploy_target)
        rl = RevocationList(data / "revocations.jsonl")
        rl.revoke(signed_bundle.bundle_id, "compromised", signer)
        engine = PDPEngine(deploy_path=deploy_target, keys_dir=keys["dir"],
                           revocations_path=data / "revocations.jsonl",
                           evidence_path=data / "evidence.jsonl",
                           signer=signer)
        r = engine.evaluate({"kind": "action", "action": "github.repo.read"})
        assert r["decision"]["allowed"] is False
        assert r["decision"]["rule"] == "revoked"

    def test_advisory_mode_flagged_in_receipts(self, tmp_path, keys, signer,
                                               signed_bundle):
        engine = self._engine(tmp_path, keys, signer, signed_bundle,
                              mode="advisory")
        r = engine.evaluate({"kind": "action", "action": "github.repo.read"})
        assert r["enforcement"] == "advisory"

    def test_evidence_written_by_engine(self, tmp_path, keys, signer,
                                        signed_bundle, verifier):
        data = tmp_path / "pdpdata3"
        deploy_target = data / "deployed" / "current.bundle.json"
        atomic_write_bundle(signed_bundle, deploy_target)
        ev_path = data / "evidence.jsonl"
        engine = PDPEngine(deploy_path=deploy_target, keys_dir=keys["dir"],
                           revocations_path=data / "revocations.jsonl",
                           evidence_path=ev_path, signer=signer)
        engine.evaluate({"kind": "host", "host": "evil.com"})
        engine.evaluate({"kind": "host", "host": "github.com"})
        report = EvidenceLedger.verify(ev_path, verifier=verifier)
        assert report["lines_checked"] == 2

    def test_p99_latency_budget_under_10ms(self, tmp_path, keys, signer,
                                           signed_bundle):
        engine = self._engine(tmp_path, keys, signer, signed_bundle)
        for i in range(50):
            engine.evaluate({"kind": "action", "action": "github.repo.read"})
        lats = sorted(engine.status.latencies_ms)
        p99 = lats[int(len(lats) * 0.99)]
        assert p99 < 10.0, f"p99 {p99}ms exceeds budget"
