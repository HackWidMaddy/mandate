"""OpenAI Codex adapter - exec approvals / file ops / network events.

Schema pinned to our documented fixture contract (ADAPTERS.md).
Response contract: exit 0 = allow, exit 2 = block (stderr shown).
"""
from __future__ import annotations

import sys
from typing import Any, Dict

from .base import AdapterSpec, first_token, host_from_url, run_adapter


class CodexAdapter(AdapterSpec):
    name = "codex"
    session_key = "session_id"
    supports_json_output = False

    def classify(self, event: Dict[str, Any]) -> Dict[str, Any]:
        etype = str(event.get("type", "")).lower()

        if etype in ("exec_approval", "exec", "shell"):
            cmd = event.get("command") or ""
            executable = (cmd.split()[0] if isinstance(cmd, str)
                          else first_token(" ".join(map(str, cmd))))
            return {"kind": "spawn", "executable": executable}

        if etype in ("patch_approval", "apply_patch", "file_write"):
            return {"kind": "path",
                    "path": str(event.get("file_path") or event.get("path", "")),
                    "mode": "w"}

        if etype in ("file_read", "read_file"):
            return {"kind": "path",
                    "path": str(event.get("file_path") or event.get("path", "")),
                    "mode": "r"}

        if etype == "network":
            host = event.get("host") or host_from_url(event.get("url", ""))
            return {"kind": "host", "host": str(host),
                    **({"port": event["port"]}
                       if isinstance(event.get("port"), int) else {})}

        return {"kind": "action", "action": f"codex.{etype or 'unknown'}"}


def main(argv=None) -> int:
    return run_adapter(CodexAdapter(), argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
