"""Cursor adapter - agent lifecycle hooks.

Schema pinned to our documented fixture contract (ADAPTERS.md); Cursor's
hook surface evolves, so mappings are version-labeled and fixture-tested.
Response contract: exit 0 = allow, exit 2 = block (stderr shown).
"""
from __future__ import annotations

import sys
from typing import Any, Dict

from .base import AdapterSpec, first_token, run_adapter


class CursorAdapter(AdapterSpec):
    name = "cursor"
    session_key = "session_id"
    supports_json_output = False   # pinned to exit-code contract for now

    def classify(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ev = str(event.get("hook_event_name", "")).lower()

        if ev in ("beforeshellexecution", "shellexecution"):
            return {"kind": "spawn",
                    "executable": first_token(event.get("command", ""))}

        if ev in ("beforereadfile", "readfile"):
            return {"kind": "path", "path": str(event.get("path", "")),
                    "mode": "r"}

        if ev in ("beforeeditfile", "editfile", "afterfileedit"):
            return {"kind": "path", "path": str(event.get("path", "")),
                    "mode": "w"}

        if ev == "beforemcprequest":
            server = str(event.get("server", ""))
            tool = str(event.get("tool", ""))
            action = ".".join(p for p in (server, tool) if p) or "mcp.request"
            return {"kind": "action", "action": action.lower()}

        if ev == "beforesubmitprompt":
            # prompt submission itself is not an authority probe; advisory no-op
            return {"kind": "action", "action": "cursor.submit_prompt"}

        return {"kind": "action",
                "action": f"cursor.{ev or 'unknown_event'}"}


def main(argv=None) -> int:
    return run_adapter(CursorAdapter(), argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
