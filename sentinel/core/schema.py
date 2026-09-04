"""Authority Manifest v1.0 - Sentinel core.

The neutral representation of what authority an agent workflow should have.
Planners (rule-based or LLM) only *propose* manifests; deterministic systems
evaluate them. This module is part of the pure core: no I/O beyond YAML/JSON
serialization helpers is performed here.

v1 additions over v0.1:
    mandate_id / human_subject   who delegated authority to the agent
    delegation.parent_mandate/.depth   chain tracking for sub-agents
    constraints[]                argument-level rules (e.g. pr.base != main)
    guardrails[]                 org denies no workflow manifest may override
    not_before                   authority activation gate
    approvals[]                  lifecycle record (consumed in Phase 2)

v0.1 documents load unchanged; `sentinel migrate` upgrades them in place
semantics-preserving.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .semantics import MANIFEST_SCHEMA_VERSION


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Manifest:
    principal: Dict[str, Any] = field(default_factory=dict)
    task: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, list] = field(default_factory=lambda: {"allow": [], "deny": []})
    filesystem: Dict[str, list] = field(
        default_factory=lambda: {"read": [], "write": [], "deny": []}
    )
    network: Dict[str, list] = field(default_factory=lambda: {"allow": [], "deny": []})
    delegation: Dict[str, Any] = field(
        default_factory=lambda: {"max_depth": 0, "parent_mandate": None, "depth": 0}
    )
    environment: Dict[str, str] = field(default_factory=dict)
    # ---- v1 fields
    mandate_id: Optional[str] = None
    human_subject: Optional[str] = None
    not_before: Optional[str] = None
    constraints: List[Dict[str, Any]] = field(default_factory=list)
    guardrails: List[str] = field(default_factory=list)
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    # ---- lifecycle
    expiry_minutes: Optional[int] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None

    # ------------------------------------------------------------------ IO
    def __post_init__(self):
        # guarantee full delegation shape regardless of construction path
        base = {"max_depth": 0, "parent_mandate": None, "depth": 0}
        base.update(self.delegation or {})
        self.delegation = base

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "principal": self.principal,
            "task": self.task,
            "mandate_id": self.mandate_id,
            "human_subject": self.human_subject,
            "tools": self.tools,
            "filesystem": self.filesystem,
            "network": self.network,
            "delegation": self.delegation,
            "environment": self.environment,
            "constraints": self.constraints,
            "guardrails": self.guardrails,
            "approvals": self.approvals,
        }
        if self.not_before:
            d["not_before"] = self.not_before
        if self.expiry_minutes is not None:
            d["expiry_minutes"] = self.expiry_minutes
        if self.issued_at:
            d["issued_at"] = self.issued_at
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        data = data or {}
        m = cls()
        m.principal = dict(data.get("principal", {}))
        m.task = dict(data.get("task", {}))
        m.mandate_id = data.get("mandate_id")
        m.human_subject = data.get("human_subject")
        m.tools = {
            "allow": list(data.get("tools", {}).get("allow", [])),
            "deny": list(data.get("tools", {}).get("deny", [])),
        }
        fs = data.get("filesystem", {})
        m.filesystem = {
            "read": list(fs.get("read", [])),
            "write": list(fs.get("write", [])),
            "deny": list(fs.get("deny", [])),
        }
        net = data.get("network", {})
        m.network = {
            "allow": list(net.get("allow", [])),
            "deny": list(net.get("deny", [])),
        }
        m.delegation = {
            "max_depth": int(data.get("delegation", {}).get("max_depth", 0)),
            "parent_mandate": data.get("delegation", {}).get("parent_mandate"),
            "depth": int(data.get("delegation", {}).get("depth", 0)),
        }
        m.environment = {
            str(k): str(v).lower() for k, v in data.get("environment", {}).items()
        }
        m.constraints = [dict(c) for c in data.get("constraints", [])]
        m.guardrails = [str(g) for g in data.get("guardrails", [])]
        m.approvals = [dict(a) for a in data.get("approvals", [])]
        m.not_before = data.get("not_before")
        m.expiry_minutes = data.get("expiry_minutes")
        m.issued_at = data.get("issued_at")
        m.expires_at = data.get("expires_at")
        if not m.expires_at and m.expiry_minutes:
            m.issue()
        return m

    @classmethod
    def loads(cls, text: str) -> "Manifest":
        """Parse from a canonical JSON string (pure). File I/O and YAML
        handling live in sentinel.manifest_io."""
        return cls.from_dict(json.loads(text))

    # ------------------------------------------------------------- timing
    def issue(self, now: Optional[datetime] = None) -> None:
        now = now or _utcnow()
        self.issued_at = now.isoformat()
        if self.expiry_minutes:
            self.expires_at = (now + timedelta(minutes=self.expiry_minutes)).isoformat()

    def _parse_ts(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            ts = datetime.fromisoformat(value)
        except ValueError:
            return None
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    def expired(self, now: Optional[datetime] = None) -> bool:
        exp = self._parse_ts(self.expires_at)
        if exp is None:
            return False
        return (now or _utcnow()) > exp

    def not_yet_active(self, now: Optional[datetime] = None) -> bool:
        nb = self._parse_ts(self.not_before)
        if nb is None:
            return False
        return (now or _utcnow()) < nb

    # ------------------------------------------------------------- summary
    def summary_lines(self) -> list:
        lines = [
            f"schema.version   : {MANIFEST_SCHEMA_VERSION}",
            f"mandate_id       : {self.mandate_id or '-'}",
            f"human_subject    : {self.human_subject or '-'}",
            f"principal.agent  : {self.principal.get('agent', '?')}",
            f"task.objective   : {self.task.get('objective', '?')}",
            f"tools.allow      : {', '.join(self.tools['allow']) or '-'}",
            f"tools.deny       : {', '.join(self.tools['deny']) or '-'}",
            f"fs.read          : {', '.join(self.filesystem['read']) or '-'}",
            f"fs.write         : {', '.join(self.filesystem['write']) or '-'}",
            f"fs.deny          : {', '.join(self.filesystem['deny']) or '-'}",
            f"network.allow    : {', '.join(self.network['allow']) or '-'}",
            f"delegation       : max_depth={self.delegation.get('max_depth', 0)}"
            f" parent={self.delegation.get('parent_mandate') or '-'}"
            f" depth={self.delegation.get('depth', 0)}",
        ]
        if self.constraints:
            lines.append(f"constraints       : {len(self.constraints)} argument rule(s)")
        if self.guardrails:
            lines.append(f"guardrails       : {', '.join(self.guardrails)}")
        if self.approvals:
            lines.append(f"approvals        : {len(self.approvals)} recorded")
        window = self.expiry_minutes if self.expiry_minutes is not None else "-"
        lines.append(f"expiry           : {window}m")
        if self.not_before:
            lines.append(f"not_before       : {self.not_before}")
        if self.expires_at:
            lines.append(f"                   (until {self.expires_at})")
        if self.environment:
            lines.append(f"environment      : {self.environment}")
        return lines
