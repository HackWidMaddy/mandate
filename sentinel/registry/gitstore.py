"""Thin git CLI wrapper for the policy registry.

The registry IS a normal git repository - versions are commits, history is
`git log`, rollback is `git revert`. Nothing clever: we shell out to the git
binary (present on effectively all developer/platform machines) and keep the
surface tiny. If a git command fails we raise GitStoreError with stderr.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional


class GitStoreError(Exception):
    pass


def _run(args: List[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(["git", *args], cwd=str(cwd),
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace")
    except FileNotFoundError as e:
        raise GitStoreError("git binary not found on PATH") from e
    if check and proc.returncode != 0:
        raise GitStoreError(f"git {' '.join(args)} failed: "
                            f"{(proc.stderr or proc.stdout).strip()}")
    return proc


class GitStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    # ------------------------------------------------------------ lifecycle
    def init(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if not (self.root / ".git").exists():
            _run(["init", "-q", "--initial-branch=main"], self.root)
        # registry commits must always be attributable
        if not _run(["config", "user.email"], self.root,
                    check=False).stdout.strip():
            _run(["config", "user.email", "sentinel-registry@local"], self.root)
            _run(["config", "user.name", "Sentinel Registry"], self.root)
        _run(["add", "-A"], self.root)
        _run(["commit", "-q", "-m", "registry: init", "--allow-empty"],
             self.root)

    def ensure_ready(self) -> None:
        if not (self.root / ".git").exists():
            raise GitStoreError(
                f"{self.root} is not a registry; run 'sentinel registry init'")

    def commit(self, message: str) -> str:
        self.ensure_ready()
        _run(["add", "-A"], self.root)
        status = _run(["status", "--porcelain"], self.root).stdout.strip()
        if not status:
            return ""  # nothing to commit; immutability made this a no-op
        _run(["commit", "-q", "-m", message], self.root)
        return self.head()

    # ------------------------------------------------------------- queries
    def head(self) -> str:
        return _run(["rev-parse", "--short", "HEAD"], self.root).stdout.strip()

    def log(self, path: Optional[str] = None, limit: int = 50) -> List[dict]:
        args = ["log", f"-{limit}", "--format=%h%x1f%aI%x1f%s"]
        if path:
            args += ["--", path]
        out = _run(args, self.root).stdout.strip()
        entries = []
        for line in filter(None, out.splitlines()):
            h, when, subject = line.split("\x1f")
            entries.append({"commit": h, "when": when, "subject": subject})
        return entries

    def write_file(self, relpath: str, content: str, commit_message: str) -> str:
        """Write inside the registry working tree and commit atomically."""
        self.ensure_ready()
        p = self.root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return self.commit(commit_message)

    def read_file(self, relpath: str) -> Optional[str]:
        p = self.root / relpath
        return p.read_text(encoding="utf-8") if p.exists() else None

    def delete_file(self, relpath: str, commit_message: str) -> None:
        p = self.root / relpath
        if p.exists():
            p.unlink()
            self.commit(commit_message)
