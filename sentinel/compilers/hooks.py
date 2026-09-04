"""Compile an Authority Manifest into a Claude Code PreToolUse hook.

The generated hook is a standalone Python script that reads the manifest,
receives Claude Code's PreToolUse JSON on stdin, evaluates it with the
deterministic Sentinel engine, and exits with code 2 to BLOCK the tool call
(exit 0 allows it).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.schema import Manifest

HOOK_TEMPLATE = '''#!/usr/bin/env python3
"""Sentinel Authority - Claude Code PreToolUse hook (generated).

Decision flow: LOCAL PDP FIRST (one shared deterministic boundary), with a
clearly-logged direct-manifest fallback when the daemon is unreachable.

Exit codes per Claude Code hooks spec:
  0 = allow   2 = block tool call (stderr shown to the model)
"""
import sys

sys.path.insert(0, r"{package_root}")

import json

from sentinel.core.evaluator import Evaluator
from sentinel.manifest_io import load as load_manifest
from sentinel.pdp.client import PDPClient, PDPConnectionError

MANIFEST = r"{manifest_path}"
PDP_URL = r"{pdp_url}"


def classify(tool_name, tool_input):
    """Map a Claude Code tool call onto Sentinel decision dimensions."""
    name = tool_name.lower()
    if name in ("read", "write", "edit", "notebookedit"):
        mode = "w" if name in ("write", "edit", "notebookedit") else "r"
        return ("path", tool_input.get("file_path") or tool_input.get("notebook_path") or "", mode)
    if name == "bash":
        first = (tool_input.get("command") or "").split()
        return ("spawn", first[0] if first else tool_input.get("command", ""), None)
    if name == "webfetch":
        return ("host", str(tool_input.get("url", "")).split("/")[2] if "://" in str(tool_input.get("url", "")) else tool_input.get("url", ""), None)
    if name.startswith("mcp__"):
        parts = name.split("__")
        action = ".".join(parts[1:]) or name
        return ("action", action, None)
    return ("action", name, None)


def probe_for(kind, value, mode):
    if kind == "path":
        return {{"kind": "path", "path": value, "mode": mode}}
    if kind == "host":
        return {{"kind": "host", "host": value}}
    if kind == "spawn":
        return {{"kind": "spawn", "executable": value}}
    return {{"kind": "action", "action": value}}


def decide_via_pdp(kind, value, mode):
    try:
        result = PDPClient(url=PDP_URL).evaluate(
            probe_for(kind, value, mode))
        dec = result["decision"]
        return dec["allowed"], f"{{dec['reason']}} [pdp rule: {{dec['rule']}}]", True
    except PDPConnectionError as e:
        print(f"[Sentinel] PDP unavailable ({{e}}); falling back to "
              "local manifest evaluation", file=sys.stderr)
        return None, "", False


def decide_locally(kind, value, mode):
    ev = Evaluator(load_manifest(MANIFEST))
    if kind == "path":
        dec = ev.check_path(value, mode)
    elif kind == "host":
        dec = ev.check_host(value)
    elif kind == "spawn":
        dec = ev.check_spawn(value)
    elif kind == "delegate":
        dec = ev.check_delegation(int(value or 0))
    else:
        dec = ev.check_action(value)
    return dec.allowed, str(dec), False


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0  # fail-open for malformed events; Sentinel policy assurance only

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {{}}) or {{}}
    kind, value, mode = classify(tool_name, tool_input)

    allowed, why, _via_pdp = decide_via_pdp(kind, value, mode)
    if allowed is None:
        allowed, why, _ = decide_locally(kind, value, mode)

    if not allowed:
        print(f"[Sentinel] BLOCKED: {{why}}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def compile_hooks(m: Manifest, out_path: str | Path | None = None,
                  manifest_path: str | None = None,
                  pdp_url: str | None = None) -> str:
    package_root = str(Path(__file__).resolve().parents[2])
    script = HOOK_TEMPLATE.format(
        package_root=package_root,
        manifest_path=manifest_path or "<authority.json>",
        pdp_url=pdp_url or "http://127.0.0.1:7433/v1/evaluate")
    settings_hint = json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command",
                                            "command": f"python {out_path or 'claude_hook.py'}"}]}
            ]
        }
    }, indent=2)
    header = f"# Add this snippet to .claude/settings.json:\n# {settings_hint}\n\n"
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(script, encoding="utf-8")
    return header + script


def compile_manifest_json(m: Manifest) -> str:
    """Hooks need JSON; YAML manifests are compiled to JSON alongside."""
    return json.dumps(m.to_dict(), indent=2)

