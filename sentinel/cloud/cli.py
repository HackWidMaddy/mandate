"""Control-plane CLI: serve, push, pull, backup, restore, token."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _data_root(args) -> Path:
    return Path(getattr(args, "data_root", None) or
                os.environ.get("SENTINEL_CLOUD_DATA") or
                Path.home() / ".sentinel" / "cloud")


def _validator(args):
    from .authn import TokenValidator
    return TokenValidator(
        issuer=args.issuer,
        audience=args.audience,
        hs_secret=os.environ.get("SENTINEL_DEV_SECRET"),
        jwks_url=args.jwks or None,
    )


def cmd_cloud_serve(args) -> int:
    import uvicorn

    from .app import build_app
    from .store import CloudStore

    app = build_app(_validator(args), CloudStore(_data_root(args)))
    uvicorn.run(app, host=args.host, port=int(args.port),
                log_level="warning")
    return 0


def cmd_cloud_token(args) -> int:
    from .authn import create_dev_token
    secret = os.environ.get("SENTINEL_DEV_SECRET")
    if not secret:
        print("error: set SENTINEL_DEV_SECRET first", file=sys.stderr)
        return 2
    tok = create_dev_token(secret, org_id=args.org, sub=args.sub,
                           role=args.role, ttl_s=int(args.ttl))
    print(tok)
    return 0


def cmd_cloud_push(args) -> int:
    """Upload a signed bundle so other machines can pull it."""
    import json as _json
    import urllib.error
    import urllib.request

    api = args.api.rstrip("/")
    body = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    req = urllib.request.Request(
        f"{api}/v1/workflows/{args.workflow}/bundles",
        data=_json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {args.token}",
                 "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            out = _json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"push rejected: {e.code} {e.read().decode()[:200]}")
        return 1
    print(f"[sentinel] pushed {out.get('bundle_id')} "
          f"(workflow {args.workflow}) -> {api}")
    return 0


def pull_bundle(api: str, workflow: str, token: str,
                keys_dir: str | Path, deploy_path: str | Path) -> dict:
    """Fetch the latest bundle and deploy it ONLY after local anchor
    verification. A compromised control plane cannot forge policy here."""
    import urllib.request

    from ..bundle.bundle import (BundleError, PolicyBundle,
                                 atomic_write_bundle)
    from ..bundle.signing import AnchorVerifier

    req = urllib.request.Request(
        f"{api.rstrip('/')}/v1/workflows/{workflow}/bundle",
        headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = json.loads(r.read().decode())
    bundle = PolicyBundle.from_dict(raw)
    bundle.verify_signature(AnchorVerifier(keys_dir))  # trust = local anchors
    atomic_write_bundle(bundle, deploy_path)
    return {"bundle_id": bundle.bundle_id, "sha256": bundle.digest}


def cmd_deploy_pull(args) -> int:
    from ..bundle.bundle import BundleError

    keys = Path(args.keys) if getattr(args, "keys", None) else \
        (Path.home() / ".sentinel" / "keys")
    target = Path(args.deploy_path) if getattr(args, "deploy_path", None) else \
        (Path.home() / ".sentinel" / "deployed" / "current.bundle.json")
    try:
        out = pull_bundle(args.api, args.workflow, args.token, keys, target)
    except BundleError as e:
        print(f"[sentinel] PULL REJECTED - signature/identity failure: {e}")
        print("[sentinel] existing deployed bundle left untouched.")
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"[sentinel] pull failed: {e}")
        return 2
    print(f"[sentinel] pulled {out['bundle_id']} -> {target} "
          "(anchor-verified before deploy)")
    return 0


# --------------------------------------------------------------- backup
BACKUP_MANIFEST = "sentinel-backup-manifest.json"


def cmd_cloud_backup(args) -> int:
    import tarfile

    from ..registry.policies import PolicyRegistry

    reg = PolicyRegistry(None if getattr(args, "dir", None) is None else args.dir)
    sources = []
    if reg.store.root.exists():
        sources.append((reg.store.root, "policies"))
    ev = Path.home() / ".sentinel" / "evidence.jsonl"
    if ev.exists():
        sources.append((ev, "evidence.jsonl"))
    dep = Path.home() / ".sentinel" / "deployed"
    if dep.exists():
        sources.append((dep, "deployed"))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)  # out IS the backup directory
    import time as _time

    stamp = _time.strftime("%Y%m%dT%H%M%SZ", _time.gmtime())
    archive = out / f"sentinel-backup-{stamp}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for src, arcname in sources:
            tar.add(src, arcname=arcname)
        info = {"created": stamp, "sources": [a for _, a in sources],
                "includes_private_keys": False}
        import io

        data = json.dumps(info, indent=2).encode()
        ti = tarfile.TarInfo(name=BACKUP_MANIFEST)
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))
    print(f"[sentinel] backup written: {archive}")
    print("[sentinel] note: private signing keys are EXCLUDED by design; "
          "back them up separately via your KMS/key-vault process.")
    return 0


def cmd_cloud_restore(args) -> int:
    import tarfile

    archive = Path(args.archive)
    target = Path(args.into)
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
        if any(n.endswith(".pem") for n in names):
            print("refusing restore: archive contains private key material")
            return 2
        tar.extractall(target, filter="data")
    print(f"[sentinel] restored {archive} into {target}")
    print("review contents before activating (policies/, evidence.jsonl, deployed/)")
    return 0
