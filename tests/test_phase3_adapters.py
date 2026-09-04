"""Phase 3: cross-agent adapters, equivalence contract, CI gate."""
import io
import json
from pathlib import Path

import pytest

from sentinel.adapters import base as adapter_base
from sentinel.adapters.base import run_adapter
from sentinel.adapters.claude_code import ClaudeCodeAdapter
from sentinel.adapters.codex import CodexAdapter
from sentinel.adapters.configs import print_config
from sentinel.adapters.cursor import CursorAdapter
from sentinel.core.schema import Manifest
from sentinel.diffing import diff_manifests, render_markdown
from sentinel.manifest_io import save as mio_save
from sentinel.pdp.client import PDPConnectionError

FIXTURES = Path(adapter_base.__file__).parent / "fixtures"


def load_fix(platform: str, name: str) -> dict:
    return json.loads((FIXTURES / platform / f"{name}.json").read_text())


def make_manifest(**over):
    d = {
        "principal": {"agent": "claude-code"},
        "task": {"repo": "acme/backend", "objective": "fix_and_open_pr"},
        "tools": {"allow": ["github.repo.read", "github.branch.create",
                            "github.commit.write", "github.pull_request.create",
                            "ci.status.read", "npm.*"],
                  "deny": ["aws.*", "github.repository.delete"]},
        "filesystem": {"read": ["workspace/**"], "write": ["workspace/**"],
                       "deny": ["**/.env"]},
        "network": {"allow": ["github.com", "registry.npmjs.org"],
                    "deny": []},
        "delegation": {"max_depth": 1},
        "not_before": "2020-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    d.update(over)
    return Manifest.from_dict(d)


class StubPDP:
    """Deterministic stand-in for PDPClient; captures calls."""

    def __init__(self, allowed=True, rule="stub", enforcement="enforcing",
                 error=None):
        self.allowed = allowed
        self.rule = rule
        self.enforcement = enforcement
        self.error = error
        self.calls = []

    def evaluate(self, probe, trace_id=None):
        self.calls.append({"probe": probe, "trace_id": trace_id})
        if self.error is not None:
            raise self.error
        return {
            "decision": {"allowed": self.allowed,
                         "reason": f"stub:{self.rule}", "rule": self.rule},
            "enforcement": self.enforcement,
            "receipt": {"sequence": 1, "receipt_hash": "ab" * 32,
                        "trace_id": trace_id, "signed": True},
        }


@pytest.fixture
def fresh_manifest(tmp_path):
    p = tmp_path / "authority.yaml"
    mio_save(make_manifest(), p)
    return p


# ------------------------------------------------- cross-platform contract
def test_equivalence_aws_spawn_identical_probes():
    probes = {}
    for platform, fix, spec in (
            ("claude_code", "bash_aws", ClaudeCodeAdapter()),
            ("cursor", "terminal_aws", CursorAdapter()),
            ("codex", "shell_aws", CodexAdapter())):
        ev = load_fix(platform, fix)["event"]
        probes[platform] = spec.classify(ev)
    assert probes["claude_code"] == probes["cursor"] == probes["codex"]
    assert probes["claude_code"] == {"kind": "spawn", "executable": "aws"}


def test_equivalence_mcp_action_identical():
    c = ClaudeCodeAdapter().classify(load_fix("claude_code", "mcp_github_pr")["event"])
    u = CursorAdapter().classify(load_fix("cursor", "mcp_request")["event"])
    assert c["kind"] == u["kind"] == "action"
    assert c["action"] == u["action"] == "github.create_pull_request"


def test_fixture_expected_probes_match_classifiers():
    pairs = [
        ("claude_code", "bash_aws"), ("claude_code", "read_workspace"),
        ("claude_code", "write_outside"), ("claude_code", "webfetch_evil"),
        ("cursor", "terminal_aws"), ("cursor", "read_src"),
        ("cursor", "edit_outside"), ("codex", "shell_aws"),
        ("codex", "patch_outside"), ("codex", "net_evil"),
    ]
    for platform, name in pairs:
        fx = load_fix(platform, name)
        specs = {"claude_code": ClaudeCodeAdapter(), "cursor": CursorAdapter(),
                 "codex": CodexAdapter()}
        got = specs[platform].classify(fx["event"])
        # compare ignoring params ordering
        assert {k: v for k, v in got.items()} == fx["expected_probe"], \
            f"{platform}/{name}: {got} != {fx['expected_probe']}"


# ------------------------------------------------------------ decide flow
def test_decide_via_pdp_carries_session_trace():
    stub = StubPDP(allowed=False, rule="spawn-default-deny")
    res = ClaudeCodeAdapter().decide(
        load_fix("claude_code", "bash_aws")["event"], pdp_client=stub)
    assert res.blocked() and res.via == "pdp"
    assert stub.calls[0]["trace_id"] == "s-claude-001"
    assert "[via:pdp]" in res.rule


def test_pdp_down_logged_fallback_blocks(tmp_path, fresh_manifest, capsys):
    down = StubPDP(error=PDPConnectionError("refused"))
    res = ClaudeCodeAdapter().decide(
        load_fix("claude_code", "bash_aws")["event"],
        pdp_client=down, manifest_path=str(fresh_manifest))
    err = capsys.readouterr().err
    assert res.via == "local-fallback" and res.blocked()
    assert "falling back" in err


def test_fail_closed_without_pdp_or_manifest(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no authority.yaml anywhere near cwd
    down = StubPDP(error=PDPConnectionError("refused"))
    res = CursorAdapter().decide({"session_id": "x", "hook_event_name":
                                  "beforeShellExecution", "command": "git status"},
                                 pdp_client=down)
    assert res.blocked() and res.via == "error-fail-closed"
    assert res.rule == "no-bundle"


def test_advisory_enforcement_propagates():
    res = CodexAdapter().decide(
        load_fix("codex", "net_evil")["event"],
        pdp_client=StubPDP(allowed=False, rule="net-default-deny",
                           enforcement="advisory"))
    assert res.enforcement == "advisory"


def test_benign_workspace_read_allowed_locally(fresh_manifest):
    down = StubPDP(error=PDPConnectionError("down"))
    res = ClaudeCodeAdapter().decide(
        load_fix("claude_code", "read_workspace")["event"],
        pdp_client=down, manifest_path=str(fresh_manifest))
    assert not res.blocked()


# --------------------------------------------------------------- responses
def test_claude_json_block_payload_schema():
    spec = ClaudeCodeAdapter()
    res = spec.decide(load_fix("claude_code", "bash_aws")["event"],
                      pdp_client=StubPDP(False, "spawn-default-deny"))
    resp = spec.respond(res, style="json")
    assert resp.exit_code == 0
    out = resp.stdout_payload["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert out["hookEventName"] == "PreToolUse"
    assert resp.stdout_payload["sentinel"]["adapter"] == "claude-code"


def test_claude_exit_code_mode_blocks_with_stderr():
    spec = ClaudeCodeAdapter()
    res = spec.decide(load_fix("claude_code", "bash_aws")["event"],
                      pdp_client=StubPDP(False, "tools.deny:aws.*"))
    resp = spec.respond(res, style="code")
    assert resp.exit_code == 2 and "BLOCKED" in resp.stderr_text


@pytest.mark.parametrize("spec_cls,fixture,allowed,expect", [
    (CursorAdapter, "read_src", True, 0),
    (CursorAdapter, "edit_outside", False, 2),
    (CodexAdapter, "patch_outside", False, 2),
])
def test_exit_code_contracts(spec_cls, fixture, allowed, expect):
    spec = spec_cls()
    res = spec.decide(load_fix(spec.name, fixture)["event"],
                      pdp_client=StubPDP(allowed=allowed))
    assert spec.respond(res).exit_code == expect


def test_run_adapter_stdin_end_to_end(monkeypatch, capsys):
    down = StubPDP(error=PDPConnectionError("down"))
    monkeypatch.setattr(adapter_base, "PDPClient", lambda **kw: down)
    ev = load_fix("cursor", "terminal_aws")["event"]
    rc = run_adapter(CursorAdapter(), [], io.StringIO(json.dumps(ev)))
    assert rc == 2

    good = load_fix("claude_code", "webfetch_evil")
    monkeypatch.setattr(adapter_base, "PDPClient", lambda **kw: StubPDP(
        False, "net-default-deny"))
    rc2 = run_adapter(ClaudeCodeAdapter(), ["--style", "json"],
                      io.StringIO(json.dumps(good["event"])))
    out = json.loads(capsys.readouterr().out)
    assert rc2 == 0
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_print_config_snippets(capsys):
    assert print_config("claude-code") == 0
    out = capsys.readouterr().out
    assert "PreToolUse" in out and "sentinel.adapters.claude_code" in out
    assert print_config("nope") == 2


# ------------------------------------------------------------------- CI
def _pair(tmp_path, mutate):
    old = make_manifest()
    new_d = make_manifest().to_dict()
    mutate(new_d)
    po, pn = tmp_path / "o.yaml", tmp_path / "n.yaml"
    mio_save(old, po)
    mio_save(Manifest.from_dict(new_d), pn)
    return str(po), str(pn)


def test_markdown_renders_verdict_and_justification_column(tmp_path):
    from sentinel.manifest_io import load as _manifest_load
    o, n = _pair(tmp_path, lambda d: d["tools"]["allow"].append("aws.s3.*"))
    md = render_markdown(diff_manifests(_manifest_load(o), _manifest_load(n)),
                         title="fix v1->v2")
    assert "**Verdict:** `REJECT POLICY EXPANSION`" in md
    assert "NOT demonstrated as required" in md
    assert "| Δ |" in md


def test_ci_check_passes_on_identical(capsys, tmp_path):
    from sentinel.cli import main
    o, n = _pair(tmp_path, lambda d: None)
    rc = main(["ci-check", "--old", o, "--new", n])
    out = capsys.readouterr().out
    assert rc == 0 and "GATE: PASS" in out


def test_ci_check_fails_on_expansion(capsys, tmp_path):
    from sentinel.cli import main
    o, n = _pair(tmp_path, lambda d: d["tools"]["allow"].append("aws.s3.*"))
    rc = main(["ci-check", "--old", o, "--new", n])
    out = capsys.readouterr().out
    assert rc == 1 and "GATE: FAIL" in out
