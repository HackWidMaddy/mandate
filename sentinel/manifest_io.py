"""Manifest file I/O - the ONLY place Sentinel reads/writes manifest files.

Kept outside sentinel.core so the deterministic engine stays pure
(see tests/test_core_purity.py).
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .core.schema import Manifest


def load(path: str | Path) -> Manifest:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return Manifest.from_dict(yaml.safe_load(text) or {})
    return Manifest.from_dict(json.loads(text))


def save(manifest: Manifest, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.suffix.lower() in (".yaml", ".yml"):
        p.write_text(yaml.safe_dump(manifest.to_dict(), sort_keys=False),
                     encoding="utf-8")
    else:
        p.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
