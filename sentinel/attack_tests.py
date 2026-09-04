"""sentinel test - adversarially attack the proposed authority.

Turns authorization into something engineering teams already understand:
a test suite that fails CI when authority is wrong.
"""
from __future__ import annotations

import copy
from datetime import timedelta
from typing import Callable

from .core.evaluator import Decision, Evaluator
from .core.schema import Manifest


class Case:
    def __init__(self, category: str, name: str, expect_allowed: bool,
                 probe: Callable[[Evaluator], Decision]):
        self.category = category
        self.name = name
        self.expect_allowed = expect_allowed
        self.probe = probe


def build_suite(manifest: Manifest) -> list:
    cases: list = []

    # ------------------------------------------------------------ benign
    benign = "benign workflow"
    cases += [
        Case(benign, "normal repository read", True,
             lambda ev: ev.check_action("github.repo.read")),
        Case(benign, "branch creation", True,
             lambda ev: ev.check_action("github.branch.create")),
        Case(benign, "commit write", True,
             lambda ev: ev.check_action("github.commit.write")),
        Case(benign, "pull request creation", True,
             lambda ev: ev.check_action("github.pull_request.create")),
        Case(benign, "dependency installation from npm", True,
             lambda ev: ev.check_action("npm.install")),
        Case(benign, "read CI status", True,
             lambda ev: ev.check_action("ci.status.read")),
        Case(benign, "read source file in workspace", True,
             lambda ev: ev.check_path("workspace/src/app.py", "r")),
        Case(benign, "write fix inside workspace", True,
             lambda ev: ev.check_path("workspace/src/fix.patch", "w")),
        Case(benign, "fetch from github.com", True,
             lambda ev: ev.check_host("github.com")),
        Case(benign, "fetch package metadata from npm registry", True,
             lambda ev: ev.check_host("registry.npmjs.org")),
        Case(benign, "single-level sub-agent delegation", True,
             lambda ev: ev.check_delegation(1)),
        Case(benign, "authority valid within task lifetime", True,
             lambda ev: ev.check_action("github.repo.read")),
    ]

    # -------------------------------------------------- privilege escalation
    esc = "privilege escalation"
    cases += [
        Case(esc, "access AWS STS (credential exists on host)", False,
             lambda ev: ev.check_action("aws.sts.GetCallerIdentity")),
        Case(esc, "write to S3", False,
             lambda ev: ev.check_action("aws.s3.PutObject")),
        Case(esc, "create IAM user", False,
             lambda ev: ev.check_action("aws.iam.CreateUser")),
        Case(esc, "delete the repository", False,
             lambda ev: ev.check_action("github.repository.delete")),
        Case(esc, "modify GitHub Actions workflows", False,
             lambda ev: ev.check_action("github.workflow.modify")),
        Case(esc, "read repository secrets", False,
             lambda ev: ev.check_action("github.secrets.read")),
        Case(esc, "merge own pull request", False,
             lambda ev: ev.check_action("github.pull_request.merge")),
        Case(esc, "post to Slack with standing token", False,
             lambda ev: ev.check_action("slack.chat.postMessage")),
        Case(esc, "apply Kubernetes manifests", False,
             lambda ev: ev.check_action("kubernetes.apply")),
        Case(esc, "cross into production environment", False,
             lambda ev: ev.check_environment("production")),
    ]

    # ------------------------------------- prompt injection / credential misuse
    inj = "prompt injection / credential misuse"
    cases += [
        Case(inj, "read ~/.ssh private key", False,
             lambda ev: ev.check_path("~/.ssh/id_rsa", "r")),
        Case(inj, "read .env secrets", False,
             lambda ev: ev.check_path("workspace/.env", "r")),
        Case(inj, "read cloud credentials file", False,
             lambda ev: ev.check_path("~/AppData/Roaming/.aws/credentials", "r")),
        Case(inj, "exfiltrate workspace to external host", False,
             lambda ev: ev.check_host("evil.example.com")),
        Case(inj, "reach cloud metadata service", False,
             lambda ev: ev.check_host("169.254.169.254")),
        Case(inj, "upload bundle to unknown collector", False,
             lambda ev: ev.check_host("uploads.external.io")),
    ]

    # ------------------------------------------------------ delegation laundering
    dlg = "delegation laundering"
    cases += [
        Case(dlg, "sub-agent chain depth 3", False,
             lambda ev: ev.check_delegation(3)),
        Case(dlg, "ask sub-agent to perform prohibited AWS action", False,
             lambda ev: ev.check_action("aws.execute")),
        Case(dlg, "delegate outside parent authority (any action)", False,
             lambda ev: ev.check_action("datadog.monitors.write")),
    ]

    # -------------------------------------------- tool chaining / param escalation
    chn = "tool chaining / parameter escalation"
    cases += [
        Case(chn, "use shell to bypass GitHub policy", False,
             lambda ev: ev.check_spawn("bash")),
        Case(chn, "spawn aws CLI directly", False,
             lambda ev: ev.check_spawn("aws")),
        Case(chn, "path traversal write outside workspace", False,
             lambda ev: ev.check_path("workspace/../../other-repo/file.txt", "w")),
        Case(chn, "read unrelated repository via traversal", False,
             lambda ev: ev.check_path("workspace/../secrets/vault.txt", "r")),
    ]

    # --------------------------------------------------------- temporal authority
    def _expired_action_probe(ev: Evaluator) -> Decision:
        exp_manifest = copy.deepcopy(manifest)
        from datetime import datetime, timezone
        exp_manifest.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        return Evaluator(exp_manifest, base_dir=ev.base_dir).check_action("github.repo.read")

    cases += [
        Case("temporal authority", "valid operation after task lifetime ends", False,
             _expired_action_probe),
    ]

    return cases


CATEGORY_COVERAGE = {
    "benign workflow": "actions+filesystem+network+delegation+time",
    "privilege escalation": "tool scope",
    "prompt injection / credential misuse": "filesystem+egress",
    "delegation laundering": "delegation graph",
    "tool chaining / parameter escalation": "composition",
    "temporal authority": "lifetime",
}

COVERAGE_DIMENSIONS = [
    "tool actions", "filesystem", "network", "delegation",
    "parameters", "time", "environments",
]


def run_suite(manifest: Manifest, base_dir: str | None = None) -> dict:
    ev = Evaluator(manifest, base_dir=base_dir)
    results = []
    passed = failed = 0
    by_cat: dict = {}
    for case in build_suite(manifest):
        dec = case.probe(ev)
        ok = dec.allowed == case.expect_allowed
        results.append({"case": case, "decision": dec, "ok": ok})
        by_cat.setdefault(case.category, []).append(ok)
        if ok:
            passed += 1
        else:
            failed += 1

    # coverage: which manifest surfaces did the suite exercise?
    touched = set()
    for r in results:
        c = r["case"]
        if c.category in ("privilege escalation", "benign workflow"):
            touched.update({"tool actions"})
        if any(k in c.name for k in ("path", "file", "key", ".env")):
            touched.add("filesystem")
        if any(k in c.name for k in ("host", "egress", "upload", "metadata", "collector")):
            touched.add("network")
        if "delegation" in c.category or "sub-agent" in c.name:
            touched.add("delegation")
        if "traversal" in c.name or "parameter" in c.name:
            touched.add("parameters")
        if "temporal" in c.category or "lifetime" in c.name:
            touched.add("time")
        if "environment" in c.name:
            touched.add("environments")
    coverage = round(100 * len(touched) / len(COVERAGE_DIMENSIONS))

    potential_missing = []
    if not any("provenance" in d.lower() for d in manifest.tools["deny"]):
        potential_missing.append("package provenance constraint")
    if not any("fork" in d.lower() for d in manifest.tools["deny"]):
        potential_missing.append("GitHub fork policy")

    verdict = "ENFORCING" if failed == 0 else "REVIEW"
    return {
        "results": results, "passed": passed, "failed": failed,
        "by_category": by_cat, "coverage": coverage,
        "potential_missing": potential_missing, "verdict": verdict,
    }


def render_report(report: dict) -> str:
    out = []
    out.append("AUTHORITY TEST")
    out.append("")
    last_cat = None
    for r in report["results"]:
        if r["case"].category != last_cat:
            last_cat = r["case"].category
            out.append(f"{last_cat.upper()}:")
        mark = "\u2713" if r["ok"] else "\u2717"
        outcome = "" if r["ok"] else "   <-- SUITE FAILURE (policy mismatch)"
        out.append(f"  {mark} {r['case'].name}{outcome}")
        if not r["ok"] or not r["decision"].allowed:
            out.append(f"      -> {r['decision']}")
    out.append("")
    for cat, oks in report["by_category"].items():
        p = sum(oks)
        out.append(f"  {cat:<40} {p}/{len(oks)} PASS")
    out.append("")
    out.append(f"Coverage                         {report['coverage']}%")
    if report["potential_missing"]:
        out.append("")
        out.append("Potentially missing:")
        for g in report["potential_missing"]:
            out.append(f"- {g}")
    out.append("")
    out.append(f"RESULT: {report['verdict']}")
    return "\n".join(out)
