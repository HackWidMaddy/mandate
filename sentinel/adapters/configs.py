"""Per-platform configuration snippets for wiring adapters.

`sentinel adapters print-config <platform>` prints these. Sentinel NEVER
edits developer dotfiles itself - the operator copies the snippet.
"""
from __future__ import annotations

import json

CONFIGS = {
    "claude-code": {
        "config_path": ".claude/settings.json (project) or ~/.claude/settings.json",
        "snippet": {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*",
                     "hooks": [{"type": "command",
                                "command": "python -m sentinel.adapters.claude_code"}]}
                ]
            }
        },
        "notes": [
            "PreToolUse receives every tool call as JSON on stdin.",
            "Adapter responds with permissionDecision allow/deny JSON; "
            "exit 2 legacy mode via --style code.",
            "Requires the local PDP (sentinel pdpd) for signed-bundle "
            "enforcement; otherwise falls back to ./authority.yaml "
            "(logged to stderr).",
        ],
    },
    "cursor": {
        "config_path": "Cursor hooks settings (see Cursor docs; surface evolves)",
        "snippet": {
            "hooks": {
                "beforeShellExecution": "python -m sentinel.adapters.cursor",
                "beforeReadFile": "python -m sentinel.adapters.cursor",
                "beforeEditFile": "python -m sentinel.adapters.cursor",
                "beforeMCPRequest": "python -m sentinel.adapters.cursor",
            }
        },
        "notes": [
            "Mappings pinned to contract version 'pinned-contract-2026-08' "
            "(ADAPTERS.md). Re-verify after Cursor updates its hook schema.",
        ],
    },
    "codex": {
        "config_path": "~/.codex/config.toml (approval/exec hook per Codex docs)",
        "snippet": {
            # TOML-ish illustration emitted as text, not JSON
            "hook_exec_approval": "python -m sentinel.adapters.codex",
            "hook_patch_approval": "python -m sentinel.adapters.codex",
            "hook_network": "python -m sentinel.adapters.codex",
        },
        "notes": [
            "Codex managed-config layers vary by deployment; wire the "
            "adapter wherever exec/patch approvals are configurable.",
        ],
    },
}


def print_config(platform: str) -> int:
    if platform not in CONFIGS:
        print(f"unknown platform {platform!r}; known: {', '.join(CONFIGS)}")
        return 2
    cfg = CONFIGS[platform]
    print(f"# Sentinel adapter config - {platform}")
    print(f"# config file: {cfg['config_path']}")
    for n in cfg["notes"]:
        print(f"# note: {n}")
    print(json.dumps(cfg["snippet"], indent=2))
    return 0
