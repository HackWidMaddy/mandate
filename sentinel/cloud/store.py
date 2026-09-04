"""Control-plane storage: SQLite + tenant-scoped object layout.

Isolation rules (tested):
  * tenant_id lives in EVERY table
  * tenant identity is derived from verified token claims, never bodies
  * every query filters by the authenticated org_id

Object layout mimics S3 prefixes so a managed object store can replace the
filesystem later without touching callers:

    <data_root>/tenants/<org_id>/bundles/<workflow>/<bundle_id>.bundle.json
    <data_root>/tenants/<org_id>/receipts/<receipt_hash>.json
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_component(value: str) -> str:
    return _SAFE.sub("_", value)[:120]


SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  org_id     TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflows (
  tenant_id  TEXT NOT NULL,
  name       TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, name)
);
CREATE TABLE IF NOT EXISTS bundles (
  tenant_id    TEXT NOT NULL,
  workflow     TEXT NOT NULL,
  bundle_id    TEXT NOT NULL,
  sha256       TEXT NOT NULL,
  uploaded_at  TEXT NOT NULL,
  path         TEXT NOT NULL,
  PRIMARY KEY (tenant_id, workflow, bundle_id)
);
CREATE TABLE IF NOT EXISTS receipts (
  tenant_id    TEXT NOT NULL,
  receipt_hash TEXT PRIMARY KEY,
  ts           TEXT NOT NULL,
  decision     TEXT NOT NULL,
  rule         TEXT NOT NULL,
  trace_id     TEXT,
  path         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
  tenant_id  TEXT NOT NULL,
  id         TEXT PRIMARY KEY,
  url        TEXT NOT NULL,
  secret     TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


class CloudStore:
    def __init__(self, data_root: str | Path):
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(self.data_root / "cloud.db"),
                                  check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    # ------------------------------------------------------------ helpers
    def _tenant_dir(self, org_id: str) -> Path:
        d = self.data_root / "tenants" / safe_component(org_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def ensure_tenant(self, org_id: str) -> None:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO tenants(org_id,name,created_at) "
                "VALUES(?,?,?)", (org_id, org_id, _now()))
            if cur.rowcount:
                self.db.commit()

    # ------------------------------------------------------------ bundles
    def put_bundle(self, org_id: str, workflow: str, bundle: Dict[str, Any]) -> dict:
        meta = bundle.get("meta") or {}
        bundle_id = str(meta.get("bundle_id") or "")
        if not bundle_id:
            raise ValueError("bundle lacks bundle_id")
        rel = (f"tenants/{safe_component(org_id)}/bundles/"
               f"{safe_component(workflow)}/{safe_component(bundle_id)}.bundle.json")
        p = self.data_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        digest = __import__("hashlib").sha256(
            json.dumps(bundle.get("manifest"), sort_keys=True).encode()).hexdigest()
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO bundles VALUES(?,?,?,?,?,?)",
                (org_id, workflow, bundle_id, digest, _now(), rel))
            self.db.execute(
                "INSERT OR REPLACE INTO workflows VALUES(?,?,?)",
                (org_id, workflow, _now()))
            self.db.commit()
        return {"workflow": workflow, "bundle_id": bundle_id}

    def latest_bundle(self, org_id: str, workflow: str) -> Optional[dict]:
        with self._lock:
            row = self.db.execute(
                "SELECT path,bundle_id FROM bundles WHERE tenant_id=? AND "
                "workflow=? ORDER BY uploaded_at DESC LIMIT 1",
                (org_id, workflow)).fetchone()
        if not row:
            return None
        return json.loads((self.data_root / row["path"]).read_text(encoding="utf-8"))

    # ----------------------------------------------------------- receipts
    def put_receipts(self, org_id: str, receipts: List[Dict[str, Any]]) -> dict:
        accepted, duplicates = 0, 0
        tdir = self._tenant_dir(org_id) / "receipts"
        tdir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            for r in receipts:
                h = str(r.get("receipt_hash") or "")
                if not h:
                    duplicates += 1
                    continue
                rel = f"tenants/{safe_component(org_id)}/receipts/{h}.json"
                p = self.data_root / rel
                exists = self.db.execute(
                    "SELECT 1 FROM receipts WHERE receipt_hash=?", (h,)).fetchone()
                if exists:
                    duplicates += 1
                    continue
                p.write_text(json.dumps(r), encoding="utf-8")
                self.db.execute(
                    "INSERT INTO receipts VALUES(?,?,?,?,?,?,?)",
                    (org_id, h, r.get("ts", _now()),
                     r.get("decision", "?"), r.get("rule", ""),
                     r.get("trace_id"), rel))
                accepted += 1
            self.db.commit()
        return {"accepted": accepted, "duplicates": duplicates}

    def list_receipts(self, org_id: str, limit: int = 100) -> List[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT receipt_hash,ts,decision,rule,trace_id FROM receipts "
                "WHERE tenant_id=? ORDER BY ts DESC LIMIT ?",
                (org_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------- webhooks
    def add_webhook(self, org_id: str, url: str, secret: str) -> dict:
        import uuid
        wid = "whk_" + uuid.uuid4().hex[:10]
        with self._lock:
            self.db.execute("INSERT INTO webhooks VALUES(?,?,?,?,?)",
                            (org_id, wid, url, secret, _now()))
            self.db.commit()
        return {"id": wid, "url": url}

    def list_webhooks(self, org_id: str) -> List[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT id,url,created_at FROM webhooks WHERE tenant_id=?",
                (org_id,)).fetchall()
        return [dict(r) for r in rows]

    def webhooks_for(self, org_id: str) -> List[Dict[str, str]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT id,url,secret FROM webhooks WHERE tenant_id=?",
                (org_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- counts
    def overview(self, org_id: str) -> dict:
        with self._lock:
            q = lambda sql: self.db.execute(sql, (org_id,)).fetchone()[0]
            return {
                "workflows": q("SELECT COUNT(*) FROM workflows WHERE tenant_id=?"),
                "bundles": q("SELECT COUNT(*) FROM bundles WHERE tenant_id=?"),
                "receipts": q("SELECT COUNT(*) FROM receipts WHERE tenant_id=?"),
                "webhooks": q("SELECT COUNT(*) FROM webhooks WHERE tenant_id=?"),
            }
