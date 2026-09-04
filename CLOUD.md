# Sentinel Cloud — Control-Plane Skeleton (Phase 4)

The control plane **distributes signed bundles and receives evidence
asynchronously**. It can never forge policy (every client verifies bundle
signatures against local trust anchors before deploying) and can never
disable local enforcement (the PDP is offline-capable by construction).

```
        ┌─────────────────────────────┐          signed bundles DOWN
        │ sentinel cloud serve        │──────────────────────────────▶  PDPs / laptops
        │  FastAPI · JWT/OIDC · RBAC  │                                   (anchor-verified)
        │  SQLite + tenant object dir │◀──────────────────────────────  receipts UP
        └─────────────────────────────┘          async, at-least-once      (dedup by hash)
```

## Run it (dev mode)

```bash
export SENTINEL_DEV_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")

sentinel cloud token --org acme --sub alice --role SecurityAdmin   # dev HS256 token
sentinel cloud serve --port 7600

# bundles: push from the signing machine, pull anywhere
sentinel cloud push --bundle dist/<id>.bundle.json --workflow fix-issue \
                    --api http://127.0.0.1:7600 --token $TOKEN
sentinel cloud pull --workflow fix-issue --api http://127.0.0.1:7600 --token $TOKEN
#   -> fetched bytes are verified against ~/.sentinel/keys/*.pub BEFORE deploy;
#      a tampered/rogue cloud is rejected and the old bundle stays active.
```

## Enroll a PDP (receipts flow UP)

```bash
sentinel pdpd --enroll http://127.0.0.1:7600 --enroll-token $TOKEN
```

The egress worker tails `evidence.jsonl` with a persisted offset:
at-least-once delivery, exponential backoff, server-side dedup by
`receipt_hash`. Killing the cloud changes nothing locally — decisions stay
local and fast; uploads resume when it returns.

Optional SIEM fan-out on the same tailer:

```bash
sentinel pdpd ... --webhook-url https://siem.example/hook \
                  --webhook-secret whsec_...
# payloads carry X-Sentinel-Signature: sha256=HMAC(body, secret);
# persistent failures land in evidence.dead-letter.jsonl for replay.
```

## Production auth

Dev tokens (HS256) are for offline evaluation only. Production validates OIDC
JWTs against your identity provider's JWKS (`--jwks URL`, issuer/audience
config). Sentinel never stores passwords or MFA secrets; org membership maps
from IdP claims to `org_id`. Roles enforced server-side:
`OrgOwner, SecurityAdmin, PolicyAuthor, PolicyApprover, Developer, Auditor,
ServiceAccount` — matrix in `sentinel/cloud/rbac.py`, exercised by tests.

## Tenancy

Every table carries `tenant_id`; every query filters by the authenticated
claims' `org_id`. Object storage uses per-tenant prefixes
(`data/tenants/<org>/…`) ready to become S3 prefixes + KMS encryption
contexts later.

## MCP gateway prototype

```bash
python -m sentinel.adapters.mcp_proxy --upstream https://mcp.internal/github \
    --server-name github --port 7601 [--manifest authority.yaml]
```

Point any MCP-speaking agent at the proxy instead of the upstream server:

* `tools/list` → filtered to tools the manifest authorizes (each tool judged
  as action `mcp.<server>.<tool>`)
* `tools/call` → evaluated pre-forward; denial returns JSON-RPC error
  `-32003 "tool call outside task authority"` with rule + reason, and writes
  a receipt like every other decision

This gives tool-level enforcement to agents that have no native hooks.

## Backup / restore

```bash
sentinel cloud backup --out backups            # registry repo + evidence +
sentinel cloud restore --archive backups/...tar.gz --into ./restored
```

Private signing keys are excluded by design; back those up via your KMS/key
vault process only.

## Metrics

Both planes expose Prometheus text format: PDP decision counters + p99
latency at `pdpd :7433/metrics`, cloud counters at `cloud :7600/metrics`.
