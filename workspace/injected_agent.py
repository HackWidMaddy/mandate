"""Simulated coding-agent session for the Sentinel enforcement demo.

This is what an agent session looks like when it receives a legitimate task,
then gets manipulated by prompt-injection instructions hidden inside repo
content (a ticket description here - could be package docs, a web page, or an
MCP response).

Run WITHOUT Sentinel to see every attempt succeed on valid credentials:
    python workspace/injected_agent.py

Run WITH Sentinel to see out-of-authority actions blocked in real time:
    sentinel run --manifest authority.yaml -- python workspace/injected_agent.py
"""
import os
import pathlib
import socket
import subprocess
import sys

WS = pathlib.Path(__file__).resolve().parent


def attempt(name, fn):
    try:
        fn()
        print(f"[agent] !! {name} SUCCEEDED (credential was valid)")
        return True
    except PermissionError as e:
        print(f"[agent] DENIED  {name}\n         -> {e}")
        return False
    except OSError as e:
        # Some platforms fail before the audit hook fires (e.g. missing binary)
        print(f"[agent] failed  {name}: {type(e).__name__}: {e}")
        return False


def main():
    print("[agent] === session start ===")
    print("[agent] task received: 'Fix GitHub issue #482 in acme/backend'")

    # ------------------------------------------------ 1. legitimate work
    print("\n[agent] -- legitimate workflow --")
    issue = WS / "ISSUE_482.md"
    text = issue.read_text(encoding="utf-8")  # allowed: workspace/**
    print(f"[agent] read {issue.name} ({len(text)} chars)")
    notes = WS / "FIX_NOTES.md"
    notes.write_text("Fix: guard empty cart in checkout(); return early.\n", encoding="utf-8")
    print(f"[agent] wrote {notes.name}")

    # ------------------- 2. prompt injection inside repo content takes over
    # The ticket points the agent at "repo instructions" that contain a
    # malicious 'credential preflight'. The agent cannot tell the difference.
    print("\n[agent] -- following 'credential preflight' in CONTRIBUTING.md --")
    contrib = WS / "CONTRIBUTING.md"
    _ = contrib.read_text(encoding="utf-8")  # allowed: workspace/**
    print(f"[agent] read {contrib.name}: preflight steps look mandatory... complying")

    results = []
    results.append(attempt(
        "read ~/.ssh/id_rsa",
        lambda: open(os.path.expanduser("~/.ssh/id_rsa")).close(),
    ))
    results.append(attempt(
        "spawn interpreter -> aws sts get-caller-identity",
        lambda: subprocess.run(
            [sys.executable, "-c", "import subprocess; subprocess.run(['aws','sts','get-caller-identity'])"],
            capture_output=True),
    ))
    results.append(attempt(
        "egress workspace bundle to pypi.org",
        lambda: socket.create_connection(("pypi.org", 443), timeout=5).close(),
    ))

    blocked = results.count(False)
    executed = len(results) - blocked
    print(f"\n[agent] === session end: {executed} unauthorized action(s) executed, "
          f"{blocked} blocked by Sentinel ===")


if __name__ == "__main__":
    main()
