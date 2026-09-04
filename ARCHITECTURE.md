# Sentinel Authority — Architecture

> Probabilistic planning. Deterministic authorization. Cryptographic evidence.

## The boundary Sentinel protects

Sentinel sits **upstream of and alongside** enforcement systems. It does not
replace IAM, Vault, gateways, or endpoint agents — it determines and proves
what their policies should be, then compiles to them.

```
Human / Business Objective
            │
            ▼  (planner: rules by default, LLM only as untrusted proposer)
┌───────────────────────────────────────────────┐
│ SENTINEL AUTHORIZATION ASSURANCE              │
│   discover → derive → test → diff →           │
│   approve/sign/version → compile → drift      │
└───────────────────────┬───────────────────────┘
                        │ signed Authority bundles
                        ▼
        ENFORCEMENT / IDENTITY (customer-owned)
   Cedar / OPA / agent hooks / MCP gateway / IAM / brokers
                        │
                        ▼
                 REAL SYSTEMS
```

## Process architecture (target)

```
CONTROL PLANE (later; design-partner pulled)      CUSTOMER ENVIRONMENT
┌──────────────────────────────┐    signed     ┌────────────────────────────┐
│ policy registry · approvals  │──bundles────▶ │ LOCAL PDP (deterministic)  │
│ org/tenant · SSO/RBAC        │               │  evaluates every decision  │
│ evidence ingestion · drift   │◀──receipts─── │  offline-capable           │
└──────────────────────────────┘  async only   └──────────┬─────────────────┘
                                                          │ synchronous
                                          Claude/Cursor/Codex adapters,
                                          MCP/tool proxy, credential brokers
```

Key property: **a control-plane outage must never disable local deterministic
enforcement.** Runtime decisions are local; telemetry flows asynchronously.

## Repository layout (Phase 0)

```
sentinel/
├── core/                     PURE deterministic engine
│   ├── schema.py             Authority Manifest v1.0 (dataclass, parse/normalize)
│   ├── evaluator.py          deny-wins engine, canonical order, constraints
│   ├── semantics.py          SEMANTICS_VERSION + rule registry + purity allowlist
│   └── vectors/*.json        cross-language conformance contract (59 vectors)
├── manifest_io.py            the ONLY manifest file I/O (yaml/json)
├── planner.py                rule-based planner + OpenRouter proposer + verifier
├── scanner.py                capability discovery + risk summary
├── attack_tests.py           adversarial suite (AgentAuthorityBench seed)
├── vectors.py                vector runner (fixed logical clock)
├── compilers/                cedar.py · opa.py · hooks.py
├── adapters/
│   └── python_audit_hook.py  PEP 578 demo/test adapter (NOT the trust boundary)
├── runtime.py                `sentinel run` bootstrap + evidence summary
└── cli.py                    scan|plan|test|compile|run|doctor|vectors|migrate
```

### Purity contract (`core/`)

Enforced by `tests/test_core_purity.py`:

* stdlib imports from a fixed allowlist only (`semantics.CORE_ALLOWED_IMPORTS`)
* no file I/O, network, subprocess, environment access in executable code
* no imports from the rest of the sentinel package

Anything in `core/` must be mechanically portable; `sentinel vectors run`
replays the conformance vectors and any port must match byte-for-byte.

### Canonical evaluation order

Defined in `core/semantics.py`, exercised by vector family 11:

```
guardrails > temporal(not_before/expires_at) > explicit deny >
environment crossing heuristic > explicit allow > default-deny
```

Spawn checks evaluate all executable aliases and let any explicit
deny/guardrail/temporal hit dominate an allow on another alias — an allow can
never launder a denial.

## Enforcement hierarchy (production direction)

No single layer claims perfection; depth comes from composition:

1. **Native agent hooks** (Claude Code PreToolUse, Cursor, Codex) — semantic,
   deterministic, first blocking point.
2. **Local PDP** — one signed-bundle evaluator shared by all adapters.
3. **Tool/MCP proxy** — cross-agent enforcement with argument context.
4. **Credential authority** — agents receive scoped short-lived capabilities,
   never standing secrets (GitHub App tokens, STS, Vault/Akeyless).
5. **OS/container boundary** — where available and required.

The PEP 578 audit hook is retained as an adapter for demos, research and
telemetry only.

## Phase 1: signed bundles + local PDP (implemented)

The enforcement path now runs on **signed artifacts**:

```
manifest.yaml ──sign──▶ <bundle_id>.bundle.json ──deploy──▶ ~/.sentinel/deployed/
       (ed25519 over canonical {manifest, meta}; identity = content hash)
                                    │
                                    ▼
                    sentinel pdpd  (127.0.0.1 only, stdlib HTTP)
                        verify sig → check revocation list →
                        temporal gate → deterministic evaluate →
                        signed + hash-chained receipt per decision
```

Properties delivered in this phase:

| Property | Mechanism |
|---|---|
| Compromised registry ≠ forged policy | Trust anchors are pinned `.pub` keys; PDP refuses unanchored signatures (`bundle/signing.py`) |
| Tamper detection | `content_sha256` identity + canonical-JSON signature; any flipped byte fails verification naming the cause |
| Revocation | Append-only **signed** revocation list; strict mode fails closed on list corruption (`bundle/revocation.py`) |
| Temporal safety | Bundles inert outside `[not_before, expires_at]`; expired ⇒ fail-closed until re-signed |
| Evidence | Every decision → individually ed25519-signed receipt, hash-chained; `sentinel evidence verify` names the first broken line (`evidence.py`) |
| Control-plane independence | Local evaluation has zero network dependencies — structural today, preserved when the SaaS plane arrives |
| Fail-closed default | No bundle / bad request / engine error ⇒ DENY with reason; advisory mode available for read-only classes |
| Latency budget | p99 measured per decision; asserted < 10 ms in tests |

Adapters consume decisions via `POST /v1/evaluate`. Generated Claude Code
hooks are **PDP-first** with an explicit local-manifest fallback (logged to
stderr) so one daemon enforces policy for every adapter.

## Phase 2: policy lifecycle (implemented)

Policy changes now flow through the GitOps-shaped workflow the blueprint
describes:

```
authority change ──▶ register ──▶ diff ──▶ tests ──▶ review/approve ──▶ sign ──▶ deploy
                     (git commit)  (semantic)  (attack suite)  (SoD enforced)        │
                                                                                      ▼
                                                              superseded / revoked / drift-checked
```

Components:

| Component | Mechanism |
|---|---|
| Immutable versions | `sentinel/registry/` - the registry IS a git repo; identical content can never be re-registered; every state change is a commit |
| Semantic diff | `sentinel/diffing.py` - classifies each change EXPANSION/CONTRACTION/NEUTRAL across tools/fs/network/delegation/temporal/constraints/guardrails; deny-list removals and guardrail weakening are HIGH/CRITICAL expansions |
| Verdict engine | `REJECT POLICY EXPANSION` when unjustified high-risk expansion; `REVIEW REQUIRED` when justified; `REJECT - ORG GUARDRAIL WEAKENED` on guardrail removal |
| Separation of duties | `approved` requires a distinct actor from the author; HIGH/CRITICAL risk must pass through review first (`registry/policies.py`) |
| Drift detection v1 | `sentinel/drift.py` - live profile vs approved manifest: standing credentials, unrestricted egress, sub-agents beyond budget, uncovered sensitive tools |

## Phase 4: control-plane skeleton + observability + MCP gateway (implemented)

The two-plane split is now real software:

```
CONTROL PLANE (FastAPI, cloud/…)                DATA PLANE (stdlib-only)
  OIDC JWT/JWKS + dev tokens                      local PDP (signed bundles)
  RBAC matrix · tenant_id everywhere              adapters: Claude/Cursor/Codex
  bundle distribution (push/pull)        ◀────▶   MCP gateway proxy
  receipt ingestion (dedup by hash)               evidence ledger + egress worker
  webhook fan-out (HMAC)                          /metrics (Prometheus text)
```

* Bundle flow DOWN is trust-anchored client-side: a compromised control plane
  cannot deploy policy anywhere.
* Receipt flow UP is at-least-once with persisted offsets; cloud outages
  delay uploads but never touch decisions.
* The MCP proxy gives tool-level enforcement to hook-less agents via the same
  PDP semantics (`tools/list` filtered, `tools/call` pre-evaluated).
* Backup excludes private keys by design; restore refuses archives that
  contain them.

## Deployment models (sequence)

| Model | When |
|---|---|
| Local CLI + local enforcement | now (POC/design partners) |
| Hybrid: customer-side enforcement, hosted metadata/evidence | enterprise default later |
| Dedicated tenant / VPC | when a regulated partner demands it |
| Air-gapped | contract-driven only |

## Data handling defaults

Telemetry contains identifiers, decisions, reasons, durations, hashes — never
raw prompts, code, credentials, file contents, or full tool responses. Payload
capture is a separately encrypted opt-in with explicit retention.
