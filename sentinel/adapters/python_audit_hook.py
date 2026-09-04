"""Real enforcement via CPython audit hooks (PEP 578).

`sentinel run --manifest M -- python script.py` executes the target in a child
process with a sys.addaudithook installed. Every file open, process spawn and
socket connect the agent attempts is checked against the Authority Manifest
*at the OS API boundary*, in real time, on Windows/Linux/macOS.

Blocked operations raise PermissionError inside the agent - the credential may
be valid, but the action is not authorized.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

from ..core.evaluator import Decision, Evaluator

AUDIT_EVENTS = ("open", "subprocess.Popen", "os.system", "os.exec", "socket.connect")

WRITE_FLAGS = {os.O_WRONLY, os.O_RDWR, os.O_APPEND, os.O_CREAT, os.O_TRUNC}


class AuthorityGuard:
    def __init__(self, manifest, base_dir: str, evidence_path: str):
        self.evaluator = Evaluator(manifest, base_dir=base_dir)
        self.base_dir = os.path.abspath(base_dir)
        self.evidence_path = os.path.abspath(evidence_path)
        self._in_hook = False
        self.blocked = []
        self.checked = 0
        # Interpreter/stdlib internals must be readable for Python itself to run;
        # these are NOT part of the task's authority surface.
        self._runtime_prefixes = tuple(
            os.path.abspath(p).replace("\\", "/").lower() + "/"
            for p in {sys.prefix, getattr(sys, "base_prefix", sys.prefix),
                      os.path.dirname(sys.executable)}
            if p
        )

    # ------------------------------------------------------------------ log
    def _log(self, record: dict) -> None:
        self._in_hook = True  # reentrancy guard: writing evidence must not recurse
        try:
            with open(self.evidence_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass
        finally:
            self._in_hook = False

    def install(self) -> None:
        if not hasattr(sys, "addaudithook"):
            raise RuntimeError("CPython >= 3.8 required for real interception")
        sys.addaudithook(self._hook)

    # ----------------------------------------------------------------- hook
    def _hook(self, event: str, args) -> None:
        if self._in_hook or event not in AUDIT_EVENTS:
            return
        handler = {
            "open": self._on_open,
            "subprocess.Popen": self._on_spawn,
            "os.system": self._on_spawn,
            "os.exec": self._on_spawn,
            "socket.connect": self._on_connect,
        }[event]
        try:
            decision = handler(args)
        except Exception as e:  # noqa: BLE001 - never break the interpreter itself
            decision = Decision(True, f"internal evaluator error (fail-open): {e}", rule="internal")
        if decision is None:
            return
        self.checked += 1
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "event": event,
            "detail": getattr(decision, "_detail", ""),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "rule": decision.rule,
        }
        if decision.allowed:
            self._log(record)
            return
        self.blocked.append(record)
        self._log(record)
        raise PermissionError(f"[Sentinel] BLOCKED {event}: {decision.reason} [{decision.rule}]")

    # ------------------------------------------------------------- handlers
    def _on_open(self, args) -> Decision | None:
        path, mode, flags = args
        if isinstance(path, int):
            return None  # fd reuse, not a new filesystem grant
        path = str(path)
        norm = os.path.abspath(os.path.expanduser(path)).replace("\\", "/").lower()
        if norm.startswith(self._runtime_prefixes):
            return None
        if norm == self.evidence_path.replace("\\", "/").lower():
            return None
        flags = flags or 0
        mode = mode or ""
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC)) or any(
            c in mode for c in ("w", "a", "+", "x"))
        decision = self.evaluator.check_path(path, "w" if writing else "r")
        decision._detail = f"{'write' if writing else 'read'} {path}"
        return decision

    def _on_spawn(self, args) -> Decision:
        executable = args[0] if args else None
        if not executable and len(args) > 1 and isinstance(args[1], (list, tuple)) and args[1]:
            # Popen audit event passes executable=None when resolved from argv
            executable = args[1][0]
        decision = self.evaluator.check_spawn(str(executable or "<unknown>"))
        decision._detail = f"spawn {executable}"
        return decision

    def _on_connect(self, args) -> Decision | None:
        address = args[1] if len(args) > 1 else None
        host, port = None, None
        if isinstance(address, (tuple, list)) and address:
            host, port = address[0], address[1] if len(address) > 1 else None
        elif isinstance(address, str):
            host = address.split(":")[0]
        if host is None:
            return None
        port = int(port) if isinstance(port, int) else None
        if port == 53:
            return None  # DNS resolution; actual egress is judged at connect time
        decision = self.evaluator.check_host(str(host))
        decision._detail = f"connect {host}:{port}"
        return decision


def guard_from_env() -> AuthorityGuard:
    """Build a guard inside the intercepted child process from env vars."""
    from ..core.schema import Manifest
    from ..manifest_io import load as _manifest_load

    manifest = _manifest_load(os.environ["SENTINEL_MANIFEST"])
    return AuthorityGuard(
        manifest,
        base_dir=os.environ.get("SENTINEL_BASE", os.getcwd()),
        evidence_path=os.environ["SENTINEL_EVIDENCE"],
    )


def install_and_run(target_argv: list) -> None:
    """Child-process entrypoint: install hook, then execute the target script."""
    guard = guard_from_env()
    guard.install()
    import runpy  # imported after hook installation on purpose

    if not target_argv:
        print("[Sentinel] no target command given", file=sys.stderr)
        raise SystemExit(2)
    target, rest = target_argv[0], target_argv[1:]
    sys.argv = target_argv
    runpy.run_path(target, run_name="__main__")


