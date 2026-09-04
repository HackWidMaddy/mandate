"""Claude Code adapter - PreToolUse hook.

Official JSON decision output (permissionDecision allow/deny/ask) when the
platform supports it, with legacy exit-code mode (0/2) available via --style
code. Event schema per Anthropic Claude Code hooks reference.
"""
from __future__ import annotations

import sys
from typing import Any, Dict

from .base import AdapterSpec, host_from_url, first_token, run_adapter

WRITE_TOOLS = ("write", "edit", "notebookedit")


class ClaudeCodeAdapter(AdapterSpec):
    name = "claude-code"
    session_key = "session_id"
    supports_json_output = True

    def classify(self, event: Dict[str, Any]) -> Dict[str, Any]:
        tool = str(event.get("tool_name", "")).lower()
        ti = event.get("tool_input") or {}

        if tool == "bash":
            return {"kind": "spawn",
                    "executable": first_token(ti.get("command", ""))}
        if tool in WRITE_TOOLS:
            path = ti.get("file_path") or ti.get("notebook_path") or ""
            return {"kind": "path", "path": str(path), "mode": "w"}
        if tool == "read":
            path = ti.get("file_path") or ti.get("notebook_path") or ""
            return {"kind": "path", "path": str(path), "mode": "r"}
        if tool in ("webfetch", "websearch"):
            url = ti.get("url") or ti.get("query") or ""
            return {"kind": "host", "host": host_from_url(str(url))}
        if tool.startswith("mcp__"):
            parts = tool.split("__")
            action = ".".join(parts[1:]) if len(parts) > 2 else tool
            return {"kind": "action", "action": action,
                    "params": {k: v for k, v in ti.items()
                               if isinstance(v, (str, int, bool))}}
        return {"kind": "action", "action": tool or "unknown"}

    # ------------------------------------------------------ json payloads
    def json_allow_payload(self, result) -> dict:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": result.reason or "within authority",
            },
            "sentinel": self._sentinel_meta(result),
        }

    def json_block_payload(self, result, event: Dict[str, Any]) -> dict:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": result.reason,
            },
            "sentinel": self._sentinel_meta(result),
        }


def main(argv=None) -> int:
    return run_adapter(ClaudeCodeAdapter(), argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
