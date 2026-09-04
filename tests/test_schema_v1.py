"""Schema v1 migration + vector-runner self-tests."""
import json

import pytest

from sentinel.core.schema import Manifest
from sentinel.vectors import run_vectors


def test_v01_manifest_loads_and_normalizes(manifest_dict):
    m = Manifest.from_dict(manifest_dict)
    assert m.delegation["max_depth"] == 1
    assert m.delegation["parent_mandate"] is None
    assert m.constraints == [] and m.guardrails == [] and m.approvals == []
    d = m.to_dict()
    assert d["schema_version"] == "1.0"


def test_v1_fields_roundtrip(tmp_path):
    from sentinel.manifest_io import load as mio_load, save as mio_save
    m = Manifest.from_dict({
        "principal": {"agent": "a"},
        "mandate_id": "mdt_abc123",
        "human_subject": "oidc:alice",
        "not_before": "2026-01-01T00:00:00+00:00",
        "constraints": [{"action": "github.pull_request.create",
                         "param": "base", "op": "neq", "value": "main"}],
        "guardrails": ["aws.*"],
        "approvals": [{"approver": "bob", "role": "security"}],
        "delegation": {"max_depth": 2, "depth": 1, "parent_mandate": "mdt_parent"},
    })
    p = tmp_path / "m.yaml"
    mio_save(m, p)
    m2 = mio_load(p)
    assert m2.mandate_id == "mdt_abc123"
    assert m2.human_subject == "oidc:alice"
    assert m2.constraints[0]["op"] == "neq"
    assert m2.guardrails == ["aws.*"]
    assert m2.approvals[0]["approver"] == "bob"
    assert m2.delegation["parent_mandate"] == "mdt_parent"


def test_constraint_evaluation_via_evaluator(manifest_dict):
    from sentinel.core.evaluator import Evaluator
    manifest_dict["constraints"] = [
        {"action": "github.commit.write", "param": "repo", "op": "eq",
         "value": "acme/backend"}]
    ev = Evaluator(Manifest.from_dict(manifest_dict), base_dir="D:/repo")
    ok = ev.check_action("github.commit.write", params={"repo": "acme/backend"})
    bad = ev.check_action("github.commit.write", params={"repo": "evil/other"})
    missing = ev.check_action("github.commit.write", params={})
    assert ok.allowed and not bad.allowed and not missing.allowed
    assert missing.rule == "constraint.missing-params"


def test_guardrails_dominate_workflow_policy(manifest_dict):
    from sentinel.core.evaluator import Evaluator
    manifest_dict["tools"]["allow"].append("aws.*")  # workflow tries to allow
    manifest_dict["guardrails"] = ["aws.*"]
    ev = Evaluator(Manifest.from_dict(manifest_dict), base_dir="D:/repo")
    d = ev.check_action("aws.s3.PutObject")
    assert not d.allowed and d.rule == "guardrail"


class TestConformanceVectors:
    def test_all_vectors_pass(self):
        report = run_vectors()
        assert report["failed"] == 0, json.dumps(
            [r for r in report["results"] if not r["ok"]], indent=2)

    def test_vector_volume(self):
        report = run_vectors()
        assert report["passed"] >= 50

    def test_semantics_version_tagged(self):
        assert run_vectors()["semantics_version"] == "1.0.0"
