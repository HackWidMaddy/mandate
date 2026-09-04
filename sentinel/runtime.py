"""sentinel run - execute a real process under task-scoped authority."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

BOOTSTRAP = """
import os, sys
sys.path.insert(0, os.environ["SENTINEL_HOME"])
from sentinel.adapters.python_audit_hook import install_and_run
install_and_run(sys.argv[1:])
"""


def run_guarded(manifest_path: str, target_cmd: list) -> int:
    repo_root = str(Path(__file__).resolve().parents[1])
    cwd = os.getcwd()
    evidence_path = os.path.join(cwd, "sentinel_evidence.jsonl")
    if os.path.exists(evidence_path):
        os.remove(evidence_path)

    env = dict(os.environ)
    env.update({
        "SENTINEL_MANIFEST": str(Path(manifest_path).resolve()),
        "SENTINEL_BASE": cwd,
        "SENTINEL_EVIDENCE": evidence_path,
        "SENTINEL_HOME": repo_root,
        "PYTHONPATH": repo_root + os.pathsep + env.get("PYTHONPATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
    })

    target_cmd = list(target_cmd)
    # `sentinel run -- python script.py`: we always execute under the current
    # interpreter, so a leading interpreter token is redundant.
    if target_cmd and os.path.basename(target_cmd[0]).lower().rstrip(".exe") == os.path.basename(sys.executable).lower().rstrip(".exe"):
        target_cmd = target_cmd[1:]

    cmd = [sys.executable, "-c", BOOTSTRAP] + target_cmd
    print(f"[sentinel] enforcing authority from {manifest_path}")
    print(f"[sentinel] running: {' '.join(target_cmd)}\n")
    proc = subprocess.run(cmd, env=env)

    blocked = allowed = 0
    if os.path.exists(evidence_path):
        with open(evidence_path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("allowed") is False:
                    blocked += 1
                elif rec.get("event"):
                    allowed += 1

    print(f"\n[sentinel] evidence: {allowed} authorized events checked, {blocked} BLOCKED")
    if blocked:
        print("[sentinel] the credential was valid. The action wasn't.")
    return proc.returncode

