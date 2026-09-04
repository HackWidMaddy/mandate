import copy

import pytest

from sentinel.core.evaluator import Evaluator
from sentinel.core.schema import Manifest


@pytest.fixture
def ev(manifest_dict):
    return Evaluator(Manifest.from_dict(manifest_dict), base_dir="D:/repo")


def test_benign_actions_allowed(ev):
    assert ev.check_action("github.repo.read").allowed
    assert ev.check_action("npm.install").allowed


def test_escalation_denied(ev):
    for action in ("aws.sts.GetCallerIdentity", "github.repository.delete",
                   "github.secrets.read", "kubernetes.apply"):
        d = ev.check_action(action)
        assert not d.allowed, action


def test_deny_wins_over_allow(manifest_dict):
    manifest_dict["tools"]["allow"].append("aws.s3.read")
    e = Evaluator(Manifest.from_dict(manifest_dict))
    assert not e.check_action("aws.s3.read").allowed


def test_workspace_paths(ev):
    assert ev.check_path("D:/repo/workspace/src/app.py", "r").allowed
    assert ev.check_path("D:/repo/workspace/src/fix.patch", "w").allowed
    assert not ev.check_path("D:/repo/workspace/.env", "r").allowed      # explicit deny
    assert not ev.check_path("C:/Users/x/.ssh/id_rsa", "r").allowed      # explicit deny
    assert not ev.check_path("D:/other/file.txt", "r").allowed           # default deny
    assert not ev.check_path("D:/repo/README.md", "w").allowed           # no write grant


def test_network(ev):
    assert ev.check_host("github.com").allowed
    assert ev.check_host("registry.npmjs.org").allowed
    assert not ev.check_host("evil.example.com").allowed
    assert not ev.check_host("169.254.169.254").allowed


def test_spawn_denied_by_default(ev):
    assert not ev.check_spawn("bash").allowed
    assert not ev.check_spawn("aws").allowed


def test_delegation_depth(ev):
    assert ev.check_delegation(1).allowed
    d = ev.check_delegation(3)
    assert not d.allowed
    assert "laundering" in d.reason or "exceeds" in d.reason


def test_temporal_expiry(manifest_dict):
    from datetime import datetime, timedelta, timezone
    m = Manifest.from_dict(manifest_dict)
    m.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    e = Evaluator(m)
    d = e.check_action("github.repo.read")
    assert not d.allowed and "expired" in d.reason


def test_environment_crossing(manifest_dict):
    m = Manifest.from_dict(manifest_dict)
    m.environment = {"development": "allow"}
    e = Evaluator(m)
    assert e.check_environment("development").allowed
    assert not e.check_environment("production").allowed


def test_yaml_roundtrip(tmp_path, manifest_dict):
    from sentinel.manifest_io import load, save
    p = tmp_path / "m.yaml"
    save(Manifest.from_dict(manifest_dict), p)
    m = load(p)
    assert m.task["issue"] == 482
    assert m.tools["deny"] == manifest_dict["tools"]["deny"]
