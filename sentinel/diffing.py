"""Semantic policy diff - the enterprise UX centerpiece.

This is NOT a YAML text diff. It compares two Authority Manifests along
security dimensions, classifies every change as EXPANSION (more authority),
CONTRACTION (less authority) or NEUTRAL, assigns severity, and produces a
recommendation the way the blueprint describes:

    + new tool discovered, not demonstrated as required -> REJECT

Severity ladder: INFO < LOW < MEDIUM < HIGH < CRITICAL.
"""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .core.schema import Manifest


class Severity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}

SENSITIVE_TOOL_PREFIXES = (
    "aws.", "kubernetes.", "production.", "iam", "secrets", "shell.",
    "process.spawn", "vault.", "database.",
)

DANGEROUS_NET = ("*", "*.*", "0.0.0.0/0",
                 "169.254.169.254", "metadata.google.internal")


@dataclass
class Delta:
    kind: str            # expansion | contraction | neutral
    dimension: str       # tools.allow / tools.deny / fs.write / ...
    detail: str          # human-readable single-line description
    severity: Severity = Severity.INFO
    justified: Optional[bool] = None   # did observed traces/task require it?

    def render_line(self) -> str:
        mark = {"expansion": "+", "contraction": "-", "neutral": "~"}[self.kind]
        sev = f"  [{self.severity.value}]" if self.severity in (
            Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL) else ""
        just = ""
        if self.kind == "expansion" and self.severity in (
                Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            just = ("  (demonstrated as required)" if self.justified
                    else "  (NOT demonstrated as required)")
        return f"{mark} {self.dimension:<16} {self.detail}{sev}{just}"


@dataclass
class DiffReport:
    deltas: List[Delta] = field(default_factory=list)

    def by_kind(self, kind: str) -> List[Delta]:
        return [d for d in self.deltas if d.kind == kind]

    @property
    def max_severity(self) -> Severity:
        return max((d.severity for d in self.deltas),
                   key=lambda s: _SEVERITY_ORDER[s], default=Severity.INFO)

    @property
    def verdict(self) -> str:
        crit = self.by_kind("expansion") and any(
            d.severity is Severity.CRITICAL for d in self.by_kind("expansion"))
        if crit:
            return "REJECT - ORG GUARDRAIL WEAKENED"
        highs = [d for d in self.by_kind("expansion")
                 if d.severity in (Severity.HIGH, Severity.CRITICAL)]
        if highs:
            if all(d.justified for d in highs):
                return "REVIEW REQUIRED - expansion justified by evidence"
            return "REJECT POLICY EXPANSION"
        meds = [d for d in self.by_kind("expansion")
                if d.severity is Severity.MEDIUM]
        if meds:
            return "REVIEW SUGGESTED"
        if self.by_kind("contraction"):
            return "OK - authority reduced"
        return "NO SEMANTIC CHANGE"

    @property
    def risk(self) -> Severity:
        return self.max_severity


# ------------------------------------------------------------------ engine
def _list_delta(dimension, before, after, *,
                expansion_severity: Severity = Severity.MEDIUM,
                contraction_severity=Severity.LOW,
                expansion_is_removal=False,
                detail_fmt="{item}") -> List[Delta]:
    """Generic set-diff helper. `expansion_is_removal` marks dimensions where
    REMOVING an entry grants more power (deny lists, constraints)."""
    out = []
    b, a = set(before or []), set(after or [])
    added, removed = a - b, b - a
    for item in sorted(added):
        if expansion_is_removal:
            out.append(Delta("contraction", dimension,
                             detail_fmt.format(item=item) + " added",
                             contraction_severity))
        else:
            out.append(Delta("expansion", dimension,
                             detail_fmt.format(item=item), expansion_severity))
    for item in sorted(removed):
        if expansion_is_removal:
            out.append(Delta("expansion", dimension,
                             detail_fmt.format(item=item) + " removed",
                             expansion_severity))
        else:
            out.append(Delta("contraction", dimension,
                             detail_fmt.format(item=item) + " removed",
                             contraction_severity))
    return out


def _tool_allow_severity(action: str) -> Severity:
    low = action.lower()
    if low.startswith(SENSITIVE_TOOL_PREFIXES):
        return Severity.HIGH
    if "*" == low.split(".")[-1] and "." in low:  # wildcard like slack.*
        return Severity.MEDIUM
    return Severity.MEDIUM


def _net_allow_severity(host: str) -> Severity:
    h = host.lower()
    if h in DANGEROUS_NET or h.endswith(".*"):
        return Severity.HIGH
    return Severity.MEDIUM


def _fs_scope_severity(patterns) -> Severity:
    for p in patterns:
        pl = p.lower().replace("\\", "/")
        if pl.startswith("**") or pl in ("/**", "*") or pl.startswith("/"):
            return Severity.HIGH
    return Severity.MEDIUM


def diff_manifests(old: Manifest, new: Manifest,
                   justifications: Optional[Dict[str, bool]] = None) -> DiffReport:
    """Compare two manifests. `justifications` maps a delta detail substring
    to True/False when callers have evidence about necessity."""
    justifications = justifications or {}
    deltas: List[Delta] = []

    def j(detail: str):
        for k, v in justifications.items():
            if k.lower() in detail.lower():
                return v
        return None

    # ---- tools
    deltas += _list_delta(
        "tools.allow", old.tools.get("allow"), new.tools.get("allow"),
        expansion_severity=Severity.MEDIUM)
    for d in deltas:
        if d.dimension == "tools.allow" and d.kind == "expansion":
            item = d.detail.replace(" added", "")
            d.severity = _tool_allow_severity(item)
            d.justified = j(item)
    deltas += _list_delta(
        "tools.deny", old.tools.get("deny"), new.tools.get("deny"),
        expansion_is_removal=True)
    for d in deltas:
        if d.dimension == "tools.deny" and d.kind == "expansion":
            d.severity = Severity.CRITICAL if "guardrail" in d.detail else Severity.HIGH
            d.justified = j(d.detail)

    # ---- filesystem
    for scope in ("read", "write"):
        deltas += _list_delta(f"fs.{scope}",
                              old.filesystem.get(scope), new.filesystem.get(scope),
                              expansion_severity=Severity.MEDIUM)
        for d in deltas:
            if d.dimension == f"fs.{scope}" and d.kind == "expansion":
                item = d.detail.replace(" added", "")
                d.severity = _fs_scope_severity([item])
                d.justified = j(item)
    deltas += _list_delta("fs.deny", old.filesystem.get("deny"),
                          new.filesystem.get("deny"),
                          expansion_is_removal=True)
    for d in deltas:
        if d.dimension == "fs.deny" and d.kind == "expansion":
            d.severity = Severity.HIGH
            d.justified = j(d.detail)

    # ---- network
    deltas += _list_delta("net.allow", old.network.get("allow"),
                          new.network.get("allow"),
                          expansion_severity=Severity.MEDIUM)
    for d in deltas:
        if d.dimension == "net.allow" and d.kind == "expansion":
            d.severity = _net_allow_severity(d.detail.replace(" added", ""))
            d.justified = j(d.detail)
    deltas += _list_delta("net.deny", old.network.get("deny"),
                          new.network.get("deny"), expansion_is_removal=True)
    for d in deltas:
        if d.dimension == "net.deny" and d.kind == "expansion":
            d.severity = Severity.HIGH

    # ---- delegation depth
    od, nd = int(old.delegation.get("max_depth", 0)), \
        int(new.delegation.get("max_depth", 0))
    if nd > od:
        deltas.append(Delta("expansion", "delegation.max_depth",
                            f"{od} -> {nd} (multi-hop laundering surface)",
                            Severity.HIGH, j("max_depth")))
    elif nd < od:
        deltas.append(Delta("contraction", "delegation.max_depth",
                            f"{od} -> {nd}", Severity.LOW))

    # ---- temporal widening
    oe, ne = old.expiry_minutes, new.expiry_minutes
    if oe is not None and ne is not None and ne > oe:
        deltas.append(Delta("expansion", "expiry.minutes", f"{oe}m -> {ne}m",
                            Severity.LOW))
    ofrom, nfrom = old.not_before, new.not_before
    if ofrom != nfrom:
        deltas.append(Delta("neutral", "temporal.not_before",
                            f"{ofrom or '-'} -> {nfrom or '-'}"))

    # ---- environments
    oenv, nenv = old.environment or {}, new.environment or {}
    for name in sorted(set(nenv) - set(oenv)):
        if nenv[name] == "allow":
            deltas.append(Delta("expansion", "environment.allow",
                                f"'{name}' now allowed", Severity.MEDIUM,
                                j(name)))
    for name in sorted(set(oenv) - set(nenv)):
        deltas.append(Delta("expansion", "environment.allow",
                            f"'{name}' grant removed", Severity.HIGH))

    # ---- argument constraints (removal = expansion)
    oc, nc = old.constraints or [], new.constraints or []
    ocs = {json.dumps(c, sort_keys=True) for c in oc}
    ncs = {json.dumps(c, sort_keys=True) for c in nc}
    for c in nc:
        k = json.dumps(c, sort_keys=True)
        if k not in ocs:
            deltas.append(Delta("contraction", "constraints.added",
                                f"{c.get('param')} {c.get('op')} "
                                f"{c.get('value')!r} on "
                                f"{c.get('action')}", Severity.LOW))
    for c in oc:
        k = json.dumps(c, sort_keys=True)
        if k not in ncs:
            deltas.append(Delta("expansion", "constraints.removed",
                                f"{c.get('param')} {c.get('op')} "
                                f"{c.get('value')!r} on "
                                f"{c.get('action')}",
                                Severity.HIGH, j("constraint")))

    # ---- guardrails (org-level; weakening is critical)
    og, ng = set(old.guardrails or []), set(new.guardrails or [])
    for g in sorted(ng - og):
        deltas.append(Delta("contraction", "guardrails.added", g, Severity.LOW))
    for g in sorted(og - ng):
        deltas.append(Delta("expansion", "guardrails.removed", g,
                            Severity.CRITICAL))

    # ---- neutral task metadata
    if old.task != new.task:
        deltas.append(Delta("neutral", "task.metadata",
                            f"{old.task.get('objective')} -> "
                            f"{new.task.get('objective')}"))
    if old.mandate_id != new.mandate_id:
        deltas.append(Delta("neutral", "mandate_id",
                            f"{old.mandate_id or '-'} -> {new.mandate_id or '-'}"))

    return DiffReport(deltas=deltas)


def max_severity(report: DiffReport) -> Severity:
    return report.max_severity


def risk_from_manifest(m: Manifest) -> str:
    """Baseline risk for a first version with no predecessor."""
    risky_allow = any(a.lower().startswith(SENSITIVE_TOOL_PREFIXES)
                      for a in m.tools.get("allow", []))
    wide_fs = _fs_scope_severity(m.filesystem.get("read") + m.filesystem.get("write")
                                 ) is Severity.HIGH
    wild_net = any(_net_allow_severity(h) is Severity.HIGH
                   for h in m.network.get("allow", []))
    if risky_allow or wild_net:
        return Severity.HIGH.value.lower()
    if wide_fs or int(m.delegation.get("max_depth", 0)) > 1:
        return Severity.MEDIUM.value.lower()
    return Severity.LOW.value.lower()


# ------------------------------------------------------------------ render
def render_report(report: DiffReport, title: str = "") -> str:
    lines = []
    if title:
        lines.append(title)
        lines.append("")
    groups = [("PRIVILEGE EXPANSION:", "expansion"),
              ("CONTRACTION:", "contraction"),
              ("NEUTRAL:", "neutral")]
    for header, kind in groups:
        items = report.by_kind(kind)
        if items:
            lines.append(header)
            for d in items:
                lines.append(f"  {d.render_line()}")
            lines.append("")
    lines.append(f"Risk assessment : {report.risk.value}")
    lines.append(f"Recommendation  : {report.verdict}")
    return "\n".join(lines)


def _md_sev_icon(sev: Severity) -> str:
    return {Severity.CRITICAL: "\U0001F534",
            Severity.HIGH: "\U0001F7E0",
            Severity.MEDIUM: "\U0001F7E1",
            Severity.LOW: "\u26AA",
            Severity.INFO: "\u2022"}.get(sev, "-")


def render_markdown(report: DiffReport, title: str = "") -> str:
    """PR-comment-ready rendering (GitHub-flavored markdown)."""
    icon = {"REJECT POLICY EXPANSION": "\u274C",
            }.get(report.verdict,
                  "\u26A0\uFE0F" if report.risk in (
                      Severity.HIGH, Severity.CRITICAL) else "\u2705")
    out = [f"## {icon} Sentinel Authority Diff" + (f" — {title}" if title else ""),
           ""]
    out.append(f"**Risk:** `{report.risk.value}` · "
               f"**Verdict:** `{report.verdict}`")
    out.append("")
    if not report.deltas:
        out.append("_No semantic authority changes._")
        return "\n".join(out)

    order = {"expansion": 0, "contraction": 1, "neutral": 2}
    rows = sorted(report.deltas,
                  key=lambda d: (order[d.kind], -_SEVERITY_ORDER[d.severity]))
    out += ["| Δ | Dimension | Detail | Severity | Justified? |",
            "|---|---|---|---|---|"]
    for d in rows:
        mark = {"expansion": "**+**", "contraction": "−",
                "neutral": "~"}[d.kind]
        just = ""
        if d.kind == "expansion" and d.severity in (
                Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            just = ("✅ demonstrated" if d.justified
                    else "❌ **NOT demonstrated as required**")
        detail = d.detail.replace("|", "\\|")
        out.append(f"| {mark} | `{d.dimension}` | {detail} "
                   f"| {_md_sev_icon(d.severity)} {d.severity.value} "
                   f"| {just or '—'} |")
    out += ["", "_Generated by Sentinel Authority — deterministic semantic "
            "diff; approvals enforced via the policy registry._"]
    return "\n".join(out)
