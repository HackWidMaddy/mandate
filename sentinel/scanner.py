"""sentinel scan - discover what an agent can currently reach."""
from __future__ import annotations

import yaml
from pathlib import Path


def scan_profile(profile_path: str | Path) -> dict:
    data = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8")) or {}
    totals = {"reachable": 0, "write_capable": 0, "sensitive": 0}
    servers = []
    for srv in data.get("mcp_servers", []):
        servers.append(srv)
        for k, key in (("actions", "reachable"), ("write_capable", "write_capable"), ("sensitive", "sensitive")):
            totals[key] += int(srv.get(k, 0))
    native = []
    for tool in data.get("native_tools", []):
        native.append(tool)
        totals["reachable"] += int(tool.get("reachable", 0))
        totals["write_capable"] += int(tool.get("write_capable", 0))
        totals["sensitive"] += int(tool.get("sensitive", 0))
    creds = list(data.get("credentials", []))
    return {
        "agent": data.get("agent", "unknown"),
        "servers": servers,
        "native": native,
        "credentials": creds,
        "network": data.get("network", "unrestricted"),
        "sub_agents": bool(data.get("sub_agents", False)),
        "totals": totals,
    }


def render_report(result: dict) -> str:
    lines = []
    lines.append(f"Agent: {result['agent']}")
    lines.append("")
    lines.append("TOOLS")
    for s in result["servers"]:
        lines.append(f"  {s['name']:<22} {s.get('actions', '?')} actions"
                     + (f"  ({s.get('write_capable', 0)} write-capable)" if s.get("write_capable") else ""))
    for t in result["native"]:
        note = f"  credential: {t['credential']}" if t.get("credential") else ""
        lines.append(f"  {t['name']:<22} reachable{note}")
    lines.append("")
    lines.append("CREDENTIALS")
    for c in result["credentials"]:
        lines.append(f"  {c.get('name', '?'):<22} {c.get('scope', '')}")
    lines.append("")
    lines.append(f"NETWORK\n  {result['network']}")
    lines.append("")
    lines.append(f"DELEGATION\n  Sub-agents {'enabled' if result['sub_agents'] else 'disabled'}")
    t = result["totals"]
    lines.append("")
    lines.append("RISK SUMMARY")
    lines.append("")
    lines.append(f"  Reachable actions:        {t['reachable']:>6,}")
    lines.append(f"  Write-capable actions:    {t['write_capable']:>6,}")
    lines.append(f"  Sensitive actions:        {t['sensitive']:>6,}")
    lines.append(f"  Standing credentials:     {len(result['credentials']):>6,}")
    lines.append(f"  Task-scoped permissions:  {0:>6,}")
    return "\n".join(lines)


def doctor_summary(result: dict) -> str:
    t = result["totals"]
    gap = "HIGH" if t["write_capable"] > 20 else "MEDIUM" if t["write_capable"] > 5 else "LOW"
    return (
        f"{result['agent']} detected\n\n"
        f"  {len(result['servers'])} MCP servers, {len(result['native'])} native tools\n"
        f"  {t['reachable']} tools/actions reachable\n"
        f"  {t['write_capable']} write-capable actions\n"
        f"  {len(result['credentials'])} standing credentials\n"
        f"  {result['network']} network access\n\n"
        f"Current task scoping: NONE\n\n"
        f"Potential privilege gap:\n{gap}"
    )
