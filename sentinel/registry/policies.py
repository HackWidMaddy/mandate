"""Versioned policy records + lifecycle state machine (with separation of
duties) on top of the git-backed store.

Lifecycle:  draft -> tested -> review -> approved -> signed -> deployed
            terminal: superseded | revoked  (revocable from any active state)

Enforced invariants:
  * versions are immutable - re-registering an existing version is an error
  * 'approved' requires a DISTINCT actor from the record author (SoD)
  * high/critical-risk expansions may not skip review
  * signing/deploying require prior approval; revocation is always possible
    while active, and is itself audited
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..core.schema import Manifest
from ..diffing import Severity, diff_manifests, max_severity, risk_from_manifest
from .gitstore import GitStore

STATES = ("draft", "tested", "review", "approved", "signed", "deployed",
          "superseded", "revoked")
TERMINAL = {"superseded", "revoked"}

TRANSITIONS = {
    "draft": {"tested"},
    "tested": {"review", "approved"},      # low-risk may skip review
    "review": {"approved"},
    "approved": {"signed"},
    "signed": {"deployed"},
    "deployed": {"superseded", "revoked"},
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TransitionDenied(Exception):
    reason: str

    def __str__(self):
        return self.reason


class PolicyRegistry:
    def __init__(self, root: str | Path | None = None):
        import os
        root = root or os.environ.get("SENTINEL_REGISTRY_DIR") or "policies"
        self.store = GitStore(Path(root))

    # ------------------------------------------------------------ helpers
    def _dir(self, name: str) -> str:
        return f"policies/{name}"

    def _meta_path(self, name: str) -> str:
        return f"{self._dir(name)}/meta.json"

    def _manifest_path(self, name: str, version: int) -> str:
        return f"{self._dir(name)}/manifest.v{version}.yaml"

    def _state_path(self, name: str, version: int) -> str:
        return f"{self._dir(name)}/state.v{version}.json"

    def _load_json(self, relpath: str) -> Optional[dict]:
        raw = self.store.read_file(relpath)
        return json.loads(raw) if raw else None

    @staticmethod
    def _digest(manifest: Manifest) -> str:
        body = json.dumps(manifest.to_dict(), sort_keys=True,
                          separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    # ------------------------------------------------------------ register
    def register(self, manifest_path: str, name: str, author: str,
                 note: str = "") -> dict:
        """Store manifest as the next immutable version; returns version info."""
        from ..manifest_io import load as _manifest_load
        m = _manifest_load(manifest_path)
        meta = self._load_json(self._meta_path(name)) or {}
        versions = meta.get("versions", [])
        digest = self._digest(m)

        for v in versions:
            if v["digest"] == digest:
                raise TransitionDenied(
                    f"identical content already registered as "
                    f"{name} v{v['version']} (immutable history)")

        version = (max((v["version"] for v in versions), default=0) + 1)
        rel = self._manifest_path(name, version)
        if self.store.read_file(rel):
            raise TransitionDenied(f"{rel} already exists")

        commit = self.store.write_file(
            rel, __import__("yaml").safe_dump(m.to_dict(), sort_keys=False),
            f"policy {name}: register v{version}"
            + (f" ({note})" if note else ""))

        versions.append({"version": version, "digest": digest,
                         "registered_at": _utcnow(),
                         "note": note})
        if not meta:
            meta = {"name": name, "author": author, "created_at": _utcnow()}
        meta["versions"] = versions
        self.store.write_file(self._meta_path(name), json.dumps(meta, indent=2),
                              f"policy {name}: meta v{version}")

        risk = self._risk_for(name, version, m)
        self.store.write_file(
            self._state_path(name, version),
            json.dumps({
                "workflow": name, "version": version, "state": "draft",
                "author": author, "risk": risk,
                "history": [{"at": _utcnow(), "to": "draft", "actor": author}],
                "commit": commit,
            }, indent=2),
            f"policy {name} v{version}: state=draft (risk {risk})")
        return {"name": name, "version": version, "state": "draft",
                "risk": risk, "digest": digest}

    def _risk_for(self, name: str, version: int, m: Manifest) -> str:
        prev = version - 1
        if prev >= 1:
            prev_raw = self.store.read_file(self._manifest_path(name, prev))
            if prev_raw:
                import yaml
                report = diff_manifests(Manifest.from_dict(yaml.safe_load(prev_raw)), m)
                return max_severity(report).value.lower()
        return risk_from_manifest(m)

    # -------------------------------------------------------------- reads
    def list_workflows(self) -> List[dict]:
        out = []
        if not self.store.root.exists():
            return out
        for d in sorted((self.store.root / "policies").glob("*")) if \
                (self.store.root / "policies").exists() else []:
            meta = self._load_json(f"{d.relative_to(self.store.root).as_posix()}/meta.json")
            if meta:
                latest = meta["versions"][-1]["version"]
                st = self.state(meta["name"], latest)
                out.append({"name": meta["name"],
                            "versions": len(meta["versions"]),
                            "latest": latest,
                            "latest_state": st.get("state"),
                            "latest_risk": st.get("risk")})
        return out

    def state(self, name: str, version: int) -> dict:
        st = self._load_json(self._state_path(name, version))
        if not st:
            raise TransitionDenied(f"unknown policy {name} v{version}")
        return st

    def load_version(self, name: str, version: int) -> Manifest:
        raw = self.store.read_file(self._manifest_path(name, version))
        if not raw:
            raise TransitionDenied(f"unknown policy {name} v{version}")
        import yaml
        return Manifest.from_dict(yaml.safe_load(raw))

    # --------------------------------------------------------- transition
    def transition(self, name: str, version: int, to_state: str, actor: str,
                   note: str = "") -> dict:
        to_state = to_state.lower().strip()
        if to_state not in STATES:
            raise TransitionDenied(f"unknown state '{to_state}'")
        st = self.state(name, version)
        cur = st["state"]
        if cur in TERMINAL:
            raise TransitionDenied(f"{name} v{version} is {cur}; terminal")
        if to_state == cur:
            raise TransitionDenied(f"already {cur}")
        if to_state not in TRANSITIONS.get(cur, set()) and to_state != "revoked":
            raise TransitionDenied(
                f"illegal transition {cur} -> {to_state} "
                f"(allowed: {sorted(TRANSITIONS.get(cur, {'revoked'}))})")

        # separation of duties
        if to_state == "approved":
            if actor == st.get("author"):
                raise TransitionDenied(
                    "separation of duties: the author may not approve their "
                    f"own policy (author={st['author']})")
            if st.get("risk") in (Severity.HIGH.value.lower(),
                                  Severity.CRITICAL.value.lower()) \
                    and "review" not in [h["to"] for h in st["history"]]:
                raise TransitionDenied(
                    f"risk={st['risk']} requires passing through review "
                    "before approval")
        if to_state == "signed" and "approved" not in \
                [h["to"] for h in st["history"]] and cur != "approved":
            raise TransitionDenied("signing requires approval first")
        if to_state == "deployed":
            hist = [h["to"] for h in st["history"]]
            if "signed" not in hist and cur != "signed":
                raise TransitionDenied("deployment requires a signed bundle")

        st["state"] = to_state
        st.setdefault("history", []).append(
            {"at": _utcnow(), "from": cur, "to": to_state,
             "actor": actor, **({"note": note} if note else {})})
        self.store.write_file(
            self._state_path(name, version), json.dumps(st, indent=2),
            f"policy {name} v{version}: {cur} -> {to_state}"
            + (f" by {actor}" + (f" [{note}]" if note else "")))
        return st

    def mark_superseded_if_older(self, name: str, new_version: int) -> None:
        """When vN deploys, older deployed versions become superseded."""
        for v in range(1, new_version):
            try:
                st = self.state(name, v)
            except TransitionDenied:
                continue
            if st["state"] == "deployed":
                self.transition(name, v, "superseded",
                                actor="registry", note=f"superseded by v{new_version}")
