"""Conformance-vector runner.

Loads JSON vector files from sentinel/core/vectors/ and replays them through
the real evaluator at a fixed logical instant (2026-08-25T12:00:00Z) so
results are deterministic forever.

These vectors are the cross-language semantics contract: any future port
(Go/Rust data plane) must reproduce every result byte-for-byte to claim
SEMANTICS_VERSION compatibility.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .core.evaluator import Evaluator
from .core.schema import Manifest
from .core.semantics import SEMANTICS_VERSION

VECTOR_DIR = Path(__file__).parent / "core" / "vectors"
FIXED_NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)


def load_vector_files(directory: Path = VECTOR_DIR) -> list:
    files = []
    for path in sorted(Path(directory).glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("semantics_version") != SEMANTICS_VERSION:
            raise ValueError(
                f"{path.name}: vectors target semantics "
                f"{data.get('semantics_version')}, engine implements {SEMANTICS_VERSION}")
        files.append({"file": path.name, "family": data["family"], "vectors": data["vectors"]})
    return files


def _probe(ev: Evaluator, probe: dict):
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
    raise ValueError(f"unknown probe kind: {kind}")


def run_vectors(directory: Path = VECTOR_DIR) -> dict:
    results = []
    passed = failed = 0
    for entry in load_vector_files(directory):
        for v in entry["vectors"]:
            manifest = Manifest.from_dict(v.get("manifest", {}))
            base_dir = v.get("base_dir", str(Path.cwd()))
            try:
                dec = _probe(Evaluator(manifest, base_dir=base_dir, now=FIXED_NOW),
                             v["probe"])
            except Exception as e:  # noqa: BLE001 - engine crash is a failure
                dec = None
                err = f"engine exception: {type(e).__name__}: {e}"
            else:
                err = None
            exp = v["expected"]
            ok = (
                err is None
                and dec.allowed == exp["allowed"]
                and dec.rule == exp["rule"]
            )
            results.append({
                "family": entry["family"],
                "name": v["name"],
                "ok": ok,
                "expected": {"allowed": exp["allowed"], "rule": exp["rule"]},
                "actual": None if err else {"allowed": dec.allowed, "rule": dec.rule,
                                            "reason": dec.reason},
                "error": err,
            })
            passed += ok
            failed += not ok
    version = SEMANTICS_VERSION
    return {"semantics_version": version, "passed": passed, "failed": failed,
            "results": results}


def render_summary(report: dict) -> str:
    lines = [f"CONFORMANCE VECTORS  (semantics {report['semantics_version']})", ""]
    last_family = None
    for r in report["results"]:
        if r["family"] != last_family:
            last_family = r["family"]
            lines.append(f"{last_family}:")
        mark = "\u2713" if r["ok"] else "\u2717"
        lines.append(f"  {mark} {r['name']}")
        if not r["ok"]:
            lines.append(f"      expected {r['expected']} got {r['actual']} {r['error'] or ''}")
    lines += ["", f"{report['passed']} passed, {report['failed']} failed",
              f"RESULT: {'CONFORMANT' if report['failed'] == 0 else 'DIVERGENT'}"]
    return "\n".join(lines)
