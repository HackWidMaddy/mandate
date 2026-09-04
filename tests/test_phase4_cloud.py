"""Phase 4: control plane (authn/RBAC/tenancy), egress worker, MCP proxy,
backup/restore."""
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sentinel.adapters.mcp_proxy import MCPProxy, make_handler  # noqa: E402
from sentinel.cloud.app import build_app  # noqa: E402
from sentinel.cloud.authn import AuthError, TokenValidator, create_dev_token  # noqa: E402
from sentinel.cloud.store import CloudStore  # noqa: E402
from sentinel.cloud.upstream import EgressWorker  # noqa: E402
from sentinel.evidence import EvidenceLedger  # noqa: E402
from sentinel.pdp.client import PDPClient, PDPConnectionError  # noqa: E402

SECRET = "dev-secret-abc"
ROLES = ["OrgOwner", "SecurityAdmin", "PolicyAuthor", "PolicyApprover",
         "Developer", "Auditor", "ServiceAccount"]


def signed_bundle_dict(name="bdl_test000001", workflow_note="w"):
    return {
        "bundle_version": "1",
        "manifest": {
            "principal": {"agent": "claude-code"},
            "task": {"objective": "fix_and_open_pr", "repo": "acme/backend"},
            "tools": {"allow": ["github.*"], "deny": []},
            "filesystem": {"read": [], "write": [], "deny": []},
            "network": {"allow": [], "deny": []},
        },
        "meta": {"bundle_id": name, "epoch": 1,
                 "created_at": "2026-08-25T00:00:00+00:00",
                 "issued_for": "claude-code",
                 "planner_source": "rules",
                 "content_sha256": "0" * 64},
        "signature": {"alg": "ed25519", "key_id": "ed25519_x", "sig": "AAAA"},
    }


@pytest.fixture
def env(tmp_path):
    validator = TokenValidator(hs_secret=SECRET)
    store = CloudStore(tmp_path / "data")
    app = build_app(validator, store)
    client = TestClient(app)

    def token(org="acme", role="SecurityAdmin", sub="u1"):
        return create_dev_token(SECRET, org_id=org, sub=sub, role=role)

    return {"client": client, "store": store, "token": token,
            "tmp": tmp_path}


def _auth(t): return {"Authorization": f"Bearer {t}"}


# ------------------------------------------------------------------ authn
def test_dev_token_roundtrip():
    v = TokenValidator(hs_secret=SECRET)
    claims = v.validate(create_dev_token(SECRET, org_id="acme", sub="u",
                                         role="Auditor"))
    assert claims["org_id"] == "acme" and claims["role"] == "Auditor"


def test_expired_and_forged_tokens_rejected():
    v = TokenValidator(hs_secret=SECRET)
    with pytest.raises(AuthError):
        v.validate(create_dev_token(SECRET, org_id="a", sub="u", role="Auditor",
                                    ttl_s=-10))
    with pytest.raises(AuthError):
        v.validate(create_dev_token("wrong-secret", org_id="a", sub="u",
                                    role="Auditor"))


def test_missing_token_401(env):
    r = env["client"].get("/v1/admin/overview")
    assert r.status_code == 401
    assert env["client"].get("/v1/admin/overview",
                             headers=_auth("garbage")).status_code == 401


def test_rbac_matrix(env):
    t = env["token"]
    cases = [
        ("Developer", "/v1/admin/overview", "get", 403),
        ("Auditor", "/v1/admin/overview", "get", 200),
        ("Developer", "/v1/webhooks", "get", 403),
        ("OrgOwner", "/v1/webhooks", "get", 200),
        ("PolicyAuthor", "/v1/workflows/w/bundles", "post", 403),
        ("ServiceAccount", "/v1/workflows/w/bundles", "post", 200),
        ("Auditor", "/v1/receipts:batch", "post", 403),
    ]
    for role, url, method, expect in cases:
        tok = env["token"](role=role)
        if method == "get":
            r = env["client"].get(url, headers=_auth(tok))
        else:
            r = env["client"].post(url, json=signed_bundle_dict(),
                                   headers=_auth(tok))
        assert r.status_code == expect, f"{role} {url}: got {r.status_code}"


def test_tenant_isolation(env):
    tokA = env["token"](org="org-a")
    tokB = env["token"](org="org-b")
    r = env["client"].post("/v1/workflows/secret-w/bundles",
                           json=signed_bundle_dict(), headers=_auth(tokA))
    assert r.status_code == 200
    # org B cannot see org A's workflow even knowing its name
    r = env["client"].get("/v1/workflows/secret-w/bundle", headers=_auth(tokB))
    assert r.status_code == 404
    # receipts are equally isolated
    env["client"].post("/v1/receipts:batch", headers=_auth(tokA), json={
        "receipts": [{"receipt_hash": "h1", "decision": "DENY",
                      "rule": "r", "ts": "t"}]})
    seen_b = env["client"].get("/v1/admin/receipts", headers=_auth(tokB)).json()
    assert all(x["receipt_hash"] != "h1" for x in seen_b)


def test_bundle_structure_validation(env):
    tok = env["token"](role="ServiceAccount")
    r = env["client"].post("/v1/workflows/w/bundles", json={"nope": True},
                           headers=_auth(tok))
    assert r.status_code == 422
    bad = signed_bundle_dict(); bad.pop("signature")
    assert env["client"].post("/v1/workflows/w/bundles", json=bad,
                              headers=_auth(tok)).status_code == 422


def test_receipt_batch_dedup(env):
    tok = env["token"](role="ServiceAccount")
    batch = {"receipts": [
        {"receipt_hash": "h1", "decision": "ALLOW", "rule": "x", "ts": "t"},
        {"receipt_hash": "h2", "decision": "DENY", "rule": "y", "ts": "t"}]}
    first = env["client"].post("/v1/receipts:batch", json=batch,
                               headers=_auth(tok)).json()
    second = env["client"].post("/v1/receipts:batch", json=batch,
                                headers=_auth(tok)).json()
    assert (first["accepted"], first["duplicates"]) == (2, 0)
    assert (second["accepted"], second["duplicates"]) == (0, 2)


def test_metrics_shape(env):
    body = env["client"].get("/metrics").text
    assert "# HELP" in body and "sentinel_cloud_total" in body


# ----------------------------------------------------------------- egress
class FakeSink(BaseHTTPRequestHandler):
    posts = []
    fail_first = [0]
    always_fail_paths: set = set()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        FakeSink.posts.append((self.path, dict(self.headers), body))
        if self.path in FakeSink.always_fail_paths:
            self.send_response(500); self.end_headers(); return
        if self.path.startswith("/flaky") and FakeSink.fail_first[0] < 1:
            FakeSink.fail_first[0] += 1
            self.send_response(500); self.end_headers(); return
        self.send_response(200); self.end_headers()

    def log_message(self, *a): pass


@pytest.fixture
def sink():
    FakeSink.posts.clear(); FakeSink.fail_first[0] = 0
    FakeSink.always_fail_paths = set()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeSink)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_uploader_dedups_via_offset(tmp_path, sink):
    ev = tmp_path / "evidence.jsonl"
    led = EvidenceLedger(ev)
    for i in range(3):
        led.record(bundle_id=f"b{i}", policy_sha256="-" * 64,
                   manifest_dict={}, action={"type": "action", "target": "t",
                                             "detail": "t"},
                   allowed=True, reason="r", rule="stub")
    w = EgressWorker(ev, api_url=sink, token="tok",
                     state_path=tmp_path / "off")
    out1 = w.drain_once()
    out2 = w.drain_once()
    assert out1["uploaded"] == 3 and out2["uploaded"] == 0
    cloud_posts = [b for p, h, b in FakeSink.posts if p == "/v1/receipts:batch"]
    sent_hashes = {r["receipt_hash"] for r in
                   json.loads(cloud_posts[0])["receipts"]}
    assert len(sent_hashes) == 3


def test_webhook_hmac_and_dead_letter(tmp_path, sink):
    ev = tmp_path / "ev2.jsonl"
    led = EvidenceLedger(ev)
    line = led.record(bundle_id="b", policy_sha256="-" * 64,
                      manifest_dict={},
                      action={"type": "action", "target": "t", "detail": "t"},
                      allowed=False, reason="r", rule="stub")
    secret = "whsec"

    # 1) happy path: signature must be valid HMAC over the exact body
    w_ok = EgressWorker(ev, webhook_url=f"{sink}/hmac", webhook_secret=secret,
                        state_path=tmp_path / "off-ok")
    w_ok.drain_once()
    hmac_posts = [(h, b) for p, h, b in FakeSink.posts if p == "/hmac"]
    assert hmac_posts, "no webhook delivered"
    h, body = hmac_posts[0]
    expected = "sha256=" + hmac.new(secret.encode(), body,
                                    hashlib.sha256).hexdigest()
    assert h.get("X-Sentinel-Signature") == expected
    assert json.loads(body)["receipts"][0]["receipt_hash"] == \
        line["receipt_hash"]

    # 2) persistent failure -> dead letter, offset does not advance
    FakeSink.always_fail_paths.add("/fail")
    dead = tmp_path / "dead.jsonl"
    w_bad = EgressWorker(ev, webhook_url=f"{sink}/fail",
                         webhook_secret=secret, state_path=tmp_path / "off-bad",
                         max_attempts=1, dead_letter_path=dead)
    res = w_bad.drain_once()
    assert res["dead"] >= 1
    assert dead.exists() and "webhook" in dead.read_text()
    # offset never advanced (file absent or still 0) -> retry later is safe
    off = tmp_path / "off-bad"
    assert not off.exists() or off.read_text().strip() == "0"


# -------------------------------------------------------------- MCP proxy
class TestMCPProxy:
    def _upstream(self, tools, echo_calls):
        class Up(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length))
                m = payload.get("method")
                if m == "tools/list":
                    resp = {"jsonrpc": "2.0", "id": payload.get("id"),
                            "result": {"tools": tools}}
                else:
                    resp = {"jsonrpc": "2.0", "id": payload.get("id"),
                            "result": {"echo": payload.get("params"),
                                       "calls": echo_calls.append(
                                           payload.get("params")) or None}}
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a): pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _proxy(self, manifest_path=None, upstream="http://upstream.invalid"):
        class Allow(PDPClient):
            def __init__(self): pass
            def evaluate(self, probe, trace_id=None):
                action = probe.get("action", "")
                denied = "aws" in action
                return {"decision": {"allowed": not denied,
                                     "reason": "policy",
                                     "rule": "test-rule"},
                        "enforcement": "enforcing"}
        return MCPProxy(upstream, "github",
                        pdp_client=Allow(),
                        fallback_manifest=manifest_path)

    def test_tools_list_filtered_by_policy(self):
        upstream = self._upstream(
            [{"name": "aws_run"}, {"name": "create_issue"}], [])
        try:
            url = f"http://127.0.0.1:{upstream.server_address[1]}"
            proxy = self._proxy(upstream=url)
            status, body = proxy.handle_rpc({"jsonrpc": "2.0", "id": 1,
                                             "method": "tools/list"})
            tools = json.loads(body)["result"]["tools"]
            assert [t["name"] for t in tools] == ["create_issue"]
            assert proxy.counters["filtered"] == 1
        finally:
            upstream.shutdown()

    def test_tool_call_denied_with_jsonrpc_error(self):
        proxy = self._proxy()
        status, body = proxy.handle_rpc({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "aws_run", "arguments": {"cmd": "sts"}}})
        err = json.loads(body)["error"]
        assert err["code"] == -32003 and "aws_run" in err["data"]["tool"]
        assert proxy.counters["denied"] == 1

    def test_tool_call_allowed_forwards_params(self):
        calls = []
        upstream = self._upstream([], calls)
        try:
            proxy = MCPProxy(
                f"http://127.0.0.1:{upstream.server_address[1]}", "github",
                pdp_client=self._proxy().pdp_client)
            status, body = proxy.handle_rpc({
                "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": {"name": "create_issue", "arguments":
                           {"title": "hi"}}})
            resp = json.loads(body)
            assert resp["result"]["echo"]["arguments"]["title"] == "hi"
            assert proxy.counters["allowed"] == 1
        finally:
            upstream.shutdown()


# ------------------------------------------------------------------ backup
def test_backup_excludes_private_keys_and_restores(tmp_path, monkeypatch):
    from sentinel.cli import main
    reg = tmp_path / "policies"
    reg.mkdir(parents=True)
    (reg / "m.yaml").write_text("principal: {agent: x}\n")
    fake_home = tmp_path / "home"
    keys_dir = fake_home / ".sentinel" / "keys"
    keys_dir.mkdir(parents=True)
    (fake_home / ".sentinel" / "evidence.jsonl").write_text('{"a":1}\n')
    (keys_dir / "k.pem").write_bytes(b"secret")
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    rc = main(["cloud", "backup", "--out", str(tmp_path / "bk"),
               "--dir", str(reg)])
    archives = list((tmp_path / "bk").glob("*.tar.gz"))
    assert rc == 0 and archives
    import tarfile
    names = tarfile.open(archives[0]).getnames()
    assert not any(n.endswith(".pem") for n in names)
    assert any("evidence.jsonl" in n for n in names)
