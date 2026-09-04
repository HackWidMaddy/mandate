"""Drift detection v1 - is the agent's *effective* authority still inside the
approved manifest?

Compares a live capability profile (from scanner.scan_profile) against an
approved Authority Manifest and reports findings. This catches the case where
"approved once" silently becomes unsafe because tooling, credentials or
network posture changed after review.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .core.schema import Manifest
from .diffing import Severity


@dataclass
class Finding:
    severity: Severity
    dimension: str
    detail: str
    recommendation: str = ""

    def render(self) -> str:
        return (f"[{self.severity.value:<8}] {self.dimension:<22} "
                f"{self.detail}"
                + (f"\n           -> {self.recommendation}"
                   if self.recommendation else ""))


@dataclass
class DriftReport:
    findings: List[Finding] = field(default_factory=list)
    checked_dimensions: int = 0

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings),
                   key=lambda s: list(Severity).index(s), default=Severity.INFO)

    @property
    def verdict(self) -> str:
        if not self.findings:
            return "NO DRIFT"
        m = self.max_severity
        if m in (Severity.HIGH, Severity.CRITICAL):
            return f"DRIFT DETECTED ({m.value}) - review required"
        return f"drift detected ({m.value})"


def detect_drift(profile: Dict, manifest: Manifest) -> DriftReport:
    """profile: result of scanner.scan_profile()."""
    findings: List[Finding] = []
    dims = 0

    # 1. standing credentials vs policy expectation of JIT/scoped authority
    creds = profile.get("credentials", [])
    dims += 1
    if creds:
        mandate_note = ("policy carries no mandate binding"
                        if not manifest.mandate_id else
                        f"mandate {manifest.mandate_id}")
        findings.append(Finding(
            Severity.HIGH, "standing-credentials",
            f"{len(creds)} standing credential(s) reachable by agent runtime "
            f"({', '.join(c.get('name', '?') for c in creds)}); "
            f"{mandate_note}",
            "replace with scoped temporary credentials (GitHub App tokens, "
            "STS); agents should never hold master secrets"))

    # 2. unrestricted network vs egress allowlist
    dims += 1
    net = str(profile.get("network", "")).lower()
    allows = [a.lower() for a in manifest.network.get("allow", [])]
    if "unrestricted" in net and "*" not in allows:
        findings.append(Finding(
            Severity.HIGH, "network-posture",
            "agent runtime has unrestricted outbound network; policy allowlists "
            f"{len(allows)} host(s)",
            "constrain egress at proxy/sandbox layer or widen the POLICY "
            "deliberately via review"))
    elif net and "*" not in allows:
        findings.append(Finding(
            Severity.LOW, "network-posture",
            f"runtime network posture: {profile.get('network')}; policy "
            f"allowlist: {', '.join(allows) or 'none'}"))

    # 3. sub-agents vs delegation budget
    dims += 1
    maxd = int(manifest.delegation.get("max_depth", 0))
    if profile.get("sub_agents") and maxd == 0:
        findings.append(Finding(
            Severity.MEDIUM, "delegation",
            "sub-agents enabled in runtime but policy max_depth=0",
            "disable sub-agents for this workflow or approve depth>0"))

    # 4. reachable-but-unauthorized action surface
    dims += 2
    totals = profile.get("totals", {})
    reachable = int(totals.get("reachable", 0))
    allowed_patterns = len(manifest.tools.get("allow", []))
    denied_patterns = len(manifest.tools.get("deny", []))
    write_capable = int(totals.get("write_capable", 0))
    if reachable and allowed_patterns + denied_patterns == 0:
        findings.append(Finding(
            Severity.HIGH, "authority-surface",
            f"{reachable} reachable actions with ZERO policy coverage",
            "generate and approve an authority manifest before production use"))
    elif reachable:
        findings.append(Finding(
            Severity.INFO, "authority-surface",
            f"runtime reach: {reachable} actions / {write_capable} "
            f"write-capable; policy covers via "
            f"{allowed_patterns} allow + {denied_patterns} deny patterns"))

    # 5. sensitive native tools without explicit deny coverage
    dims += 1
    sensitive_native = [t["name"].lower() for t in profile.get("native", [])
                        if t.get("sensitive")]
    denied = [d.lower() for d in manifest.tools.get("deny", [])]
    uncovered = [n for n in sensitive_native
                 if not any(n.split()[0].rstrip(":") in d or d.rstrip("*.").strip() in n
                            for d in denied)]
    if uncovered:
        findings.append(Finding(
            Severity.MEDIUM, "sensitive-tools",
            f"sensitive tools lack deny coverage: {', '.join(uncovered)}",
            "add explicit denies or justify access through allow rules"))

    return DriftReport(findings=findings, checked_dimensions=dims)


def render_drift(report: DriftReport, title: str = "") -> str:
    lines = []
    if title:
        lines += [title, ""]
    if report.findings:
        lines.append("FINDINGS")
        for f in sorted(report.findings,
                        key=lambda x: -list(Severity).index(x.severity)):
            lines.append(f"  {f.render()}")
        lines.append("")
    else:
        lines.append("No drift findings.")
        lines.append("")
    lines.append(f"dimensions checked : {report.checked_dimensions}")
    lines.append(f"verdict            : {report.verdict}")
    return "\n".join(lines)
