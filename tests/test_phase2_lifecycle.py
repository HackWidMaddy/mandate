"""Phase 2: semantic diff, lifecycle registry (git), separation of duties,
drift detection."""
import json
import shutil
from pathlib import Path

import pytest

from sentinel.core.schema import Manifest
from sentinel.diffing import (Severity, diff_manifests, max_severity,
                              render_report, risk_from_manifest)
from sentinel.drift import detect_drift

git = pytest.importorskip if not shutil.which("git") else None
pytestmark = pytest.mark.skipif(not shutil.which("git"),
                                reason="git binary required for registry tests")


def base_manifest(**over):
    d = {
        "principal": {"agent": "claude-code"},
        "task": {"repo": "acme/backend", "objective": "fix_and_open_pr"},
        "tools": {"allow": ["github.*", "npm.*"], "deny": ["aws.*"]},
        "filesystem": {"read": ["workspace/**"], "write": ["workspace/**"],
                       "deny": ["**/.env"]},
        "network": {"allow": ["github.com"], "deny": []},
        "delegation": {"max_depth": 1},
        "not_before": "2020-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    d.update(over)
    return Manifest.from_dict(d)


# ------------------------------------------------------------------- diffing
class TestSemanticDiff:
    def test_identical_is_no_change(self):
        r = diff_manifests(base_manifest(), base_manifest())
        assert r.verdict == "NO SEMANTIC CHANGE"

    def test_new_tool_allow_is_expansion(self):
        old = base_manifest()
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("aws.s3.*")
        new = Manifest.from_dict(new_d)
        r = diff_manifests(old, new)
        exp = [d for d in r.by_kind("expansion") if "aws" in d.detail]
        assert exp and exp[0].severity is Severity.HIGH
        assert r.verdict == "REJECT POLICY EXPANSION"

    def test_justified_expansion_requires_review_not_reject(self):
        old = base_manifest()
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("aws.s3.*")
        r = diff_manifests(old, Manifest.from_dict(new_d),
                           justifications={"aws.s3.*": True})
        assert r.verdict.startswith("REVIEW REQUIRED")

    def test_deny_removal_is_high_expansion(self):
        old = base_manifest()
        new_d = base_manifest().to_dict()
        new_d["tools"]["deny"].remove("aws.*")
        r = diff_manifests(old, Manifest.from_dict(new_d))
        assert any(d.dimension == "tools.deny" and d.severity is Severity.HIGH
                   for d in r.by_kind("expansion"))

    def test_guardrail_weakening_is_critical(self):
        old_d = base_manifest().to_dict(); old_d["guardrails"] = ["kubernetes.*"]
        new_d = dict(old_d); new_d["guardrails"] = []
        r = diff_manifests(Manifest.from_dict(old_d), Manifest.from_dict(new_d))
        assert r.verdict.startswith("REJECT - ORG GUARDRAIL")
        assert max_severity(r) is Severity.CRITICAL

    def test_constraint_removal_is_expansion(self):
        old_d = base_manifest().to_dict()
        old_d["constraints"] = [{"action": "github.pull_request.create",
                                 "param": "base", "op": "neq", "value": "main"}]
        r = diff_manifests(Manifest.from_dict(old_d), base_manifest())
        assert any(d.dimension == "constraints.removed"
                   for d in r.by_kind("expansion"))

    def test_delegation_deepening_is_high(self):
        r = diff_manifests(base_manifest(), base_manifest(
            delegation={"max_depth": 3}))
        assert any(d.dimension == "delegation.max_depth"
                   and d.severity is Severity.HIGH
                   for d in r.by_kind("expansion"))

    def test_contraction_reports_ok(self):
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].remove("npm.*")
        new_d["expiry_minutes"] = 30
        r = diff_manifests(base_manifest(), Manifest.from_dict(new_d))
        assert not r.by_kind("expansion")
        assert r.verdict == "OK - authority reduced"

    def test_render_shows_markers_and_verdict(self):
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("slack.chat.postMessage")
        out = render_report(diff_manifests(base_manifest(),
                                           Manifest.from_dict(new_d)),
                            title="Policy: fix v1 -> v2")
        assert "+" in out and "PRIVILEGE EXPANSION:" in out
        assert "Recommendation" in out

    def test_risk_from_manifest_baseline(self):
        assert risk_from_manifest(base_manifest()) == "low"
        wild = base_manifest(network={"allow": ["*"], "deny": []})
        assert risk_from_manifest(wild) == "high"


# ----------------------------------------------------------------- registry
@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from sentinel.registry.gitstore import GitStore
    from sentinel.registry.policies import PolicyRegistry
    reg = PolicyRegistry(tmp_path / "policies")
    reg.store.init()
    return reg


def write_yaml(tmp_path, m: Manifest) -> Path:
    p = tmp_path / f"m_{abs(hash(json.dumps(m.to_dict(), sort_keys=True)))}.yaml"
    from sentinel.manifest_io import save as mio_save
    mio_save(m, p)
    return p


class TestLifecycle:
    def test_register_increments_versions_and_detects_duplicates(
            self, registry, tmp_path):
        p1 = write_yaml(tmp_path, base_manifest())
        a = registry.register(str(p1), name="fix-issue", author="alice")
        # identical content must NOT create v2 - history is immutable
        with pytest.raises(Exception, match="immutable|identical"):
            registry.register(str(p1), name="fix-issue", author="alice")
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("ci.status.read")
        p2 = write_yaml(tmp_path, Manifest.from_dict(new_d))
        b = registry.register(str(p2), name="fix-issue", author="alice")
        assert (a["version"], b["version"]) == (1, 2)

    def test_happy_path_lifecycle(self, registry, tmp_path):
        v1 = write_yaml(tmp_path, base_manifest())
        info = registry.register(str(v1), name="w", author="alice")
        v = info["version"]
        reg = registry
        reg.transition("w", v, "tested", actor="ci")
        reg.transition("w", v, "approved", actor="bob")
        reg.transition("w", v, "signed", actor="bob")
        reg.transition("w", v, "deployed", actor="bob")
        assert reg.state("w", v)["state"] == "deployed"

    def test_sod_author_cannot_approve(self, registry, tmp_path):
        v1 = write_yaml(tmp_path, base_manifest())
        info = registry.register(str(v1), name="sod", author="alice")
        registry.transition("sod", info["version"], "tested", actor="ci")
        with pytest.raises(Exception, match="separation of duties"):
            registry.transition("sod", info["version"], "approved",
                                actor="alice")

    def test_high_risk_requires_review(self, registry, tmp_path):
        low = write_yaml(tmp_path, base_manifest())
        i1 = registry.register(str(low), name="hr", author="alice")
        # craft a HIGH-risk successor so v2 inherits HIGH risk
        high_d = base_manifest().to_dict()
        high_d["tools"]["allow"].append("aws.iam.*")
        high = write_yaml(tmp_path, Manifest.from_dict(high_d))
        i2 = registry.register(str(high), name="hr", author="alice")
        assert i2["risk"] == Severity.HIGH.value.lower()
        registry.transition("hr", i2["version"], "tested", actor="ci")
        with pytest.raises(Exception, match="review"):
            registry.transition("hr", i2["version"], "approved", actor="bob")
        registry.transition("hr", i2["version"], "review", actor="bob")
        registry.transition("hr", i2["version"], "approved", actor="bob")

    def test_illegal_transition_rejected(self, registry, tmp_path):
        v1 = write_yaml(tmp_path, base_manifest())
        info = registry.register(str(v1), name="it", author="alice")
        with pytest.raises(Exception, match="illegal transition"):
            registry.transition("it", info["version"], "deployed", actor="bob")

    def test_deploy_supersedes_previous(self, registry, tmp_path):
        v1f = write_yaml(tmp_path, base_manifest())
        i1 = registry.register(str(v1f), name="sup", author="alice")
        for st in ("tested", "approved", "signed"):
            registry.transition("sup", i1["version"], st,
                                actor="bob" if st == "approved" else "ci")
        registry.transition("sup", i1["version"], "deployed", actor="bob")

        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("ci.status.read")
        v2f = write_yaml(tmp_path, Manifest.from_dict(new_d))
        i2 = registry.register(str(v2f), name="sup", author="alice")
        for st in ("tested", "approved", "signed"):
            registry.transition("sup", i2["version"], st,
                                actor="bob" if st == "approved" else "ci")
        registry.transition("sup", i2["version"], "deployed", actor="bob")
        registry.mark_superseded_if_older("sup", i2["version"])
        assert registry.state("sup", 1)["state"] == "superseded"

    def test_git_history_records_lifecycle(self, registry, tmp_path):
        v1 = write_yaml(tmp_path, base_manifest())
        info = registry.register(str(v1), name="gh", author="alice")
        registry.transition("gh", info["version"], "revoked",
                            actor="security", note="leak suspected")
        manifest_log = " | ".join(
            e["subject"] for e in
            registry.store.log(path=registry._manifest_path("gh", 1)))
        state_log = " | ".join(
            e["subject"] for e in
            registry.store.log(path=registry._state_path("gh", 1)))
        assert f"register v{info['version']}" in manifest_log
        assert "revoked by security" in state_log

    def test_diff_command_against_registry_versions(self, registry, tmp_path,
                                                    capsys):
        v1 = write_yaml(tmp_path, base_manifest())
        registry.register(str(v1), name="dv", author="alice")
        new_d = base_manifest().to_dict()
        new_d["tools"]["allow"].append("aws.s3.*")
        v2 = write_yaml(tmp_path, Manifest.from_dict(new_d))
        registry.register(str(v2), name="dv", author="alice")

        from sentinel.cli import main
        rc = main(["diff", "--name", "dv", "--frm", "1", "--to", "2"])
        out = capsys.readouterr().out
        assert rc == 0 and "REJECT POLICY EXPANSION" in out


# -------------------------------------------------------------------- drift
class TestDrift:
    def _profile(self, **over):
        p = {
            "agent": "claude-code",
            "servers": [],
            "native": [],
            "credentials": [{"name": "AWS", "scope": "AdministratorAccess"}],
            "network": "Unrestricted outbound",
            "sub_agents": True,
            "totals": {"reachable": 500, "write_capable": 60, "sensitive": 10},
        }
        p.update(over)
        return p

    def test_overprovisioned_profile_flags_high(self):
        report = detect_drift(self._profile(), base_manifest())
        sev = {f.dimension: f.severity for f in report.findings}
        assert sev.get("standing-credentials") is Severity.HIGH
        assert sev.get("network-posture") is Severity.HIGH
        assert "DRIFT DETECTED" in report.verdict

    def test_scoped_profile_cleaner(self):
        profile = self._profile(credentials=[], network="allowlisted egress",
                                sub_agents=False,
                                totals={"reachable": 40, "write_capable": 3,
                                        "sensitive": 0})
        m_d = base_manifest().to_dict()
        m_d["mandate_id"] = "mdt_x"
        m = Manifest.from_dict(m_d)
        report = detect_drift(profile, m)
        assert all(f.severity in (Severity.INFO, Severity.LOW)
                   for f in report.findings)

    def test_zero_coverage_is_high(self):
        profile = self._profile(credentials=[])
        empty = Manifest.from_dict({})
        report = detect_drift(profile, empty)
        assert any(f.dimension == "authority-surface"
                   and f.severity is Severity.HIGH for f in report.findings)
