# Sentinel Authority â€” Threat Model

Status: living document. Version 1.0 covers the POC + Phase 0 architecture
(pure deterministic core, adapters, local enforcement). Update on every
architectural change; review before each design-partner deployment.

## Scope and trust boundary

Sentinel is an **authorization-assurance** layer: it derives, tests, versions,
and compiles authority policies, and can evaluate decisions at a local Policy
Decision Point (PDP). Sentinel does **not** claim to be a sandbox, an endpoint
agent, or an identity provider.

Trust boundaries today:

1. `sentinel/core/` â€” pure deterministic engine. No I/O, stdlib-only,
   conformance-tested. This is the component security reviewers must be able
   to trust mechanically.
2. Adapters (Claude Code hooks, Python audit hook) â€” translate agent events to
   core decisions. An adapter is **one enforcement point**, never the whole
   guarantee.
3. Planner (rule-based or LLM) â€” **untrusted proposer**. Its output is always
   re-verified deterministically; LLM output additionally passes mechanical
   invariant checks before a human ever sees it.

The CPython audit hook (`sentinel/adapters/python_audit_hook.py`) is explicitly
a **demo/test adapter**. It mediates Python-level OS APIs from process start of
the guarded child onward; it cannot see non-Python processes, memory-corrupting
native code, or actions taken before hook installation, and Python's own docs
warn that audit hooks require stronger installation guarantees for
security-sensitive use. Production enforcement layers native agent hooks,
tool/MCP proxies, credential authorities, and OS/container controls.

## Threat register

| # | Threat | Example | Mitigation (module) | Status |
|---|--------|---------|---------------------|--------|
| 1 | Prompt injection | Repo file tells agent to exfiltrate SSH key | Task-scoped authority independent of untrusted instructions (`core/evaluator`, `attack_tests` injection suite); demo `workspace/CONTRIBUTING.md` | Enforced |
| 2 | Excess privilege | AWS admin credential present during GitHub fix task | Permission minimization + deny defaults (`planner.verify_manifest`, evaluator default-deny) | Enforced |
| 3 | Tool poisoning | Malicious MCP tool description manipulates behavior | Action/resource-level authority independent of tool descriptions; provenance checks planned (Phase 2 drift) | Partial |
| 4 | Delegation laundering | Agent A asks sub-agent B for action A lacks | `authority(child) âŠ† authority(parent)` depth cap (`check_delegation`) | Enforced |
| 5 | Argument escalation | Allowed tool used with dangerous arguments | Argument constraints fail-closed (`check_constraints`) | Enforced |
| 6 | Shell bypass | Generic shell command evades tool policy | Spawn treated as its own tool; alias laundering blocked (`check_spawn` vectors 05) | Enforced at PEP layer only |
| 7 | Runtime-hook bypass | Agent escapes CPython interception | Honest scope statement; production = native hooks + proxy + credential authority + OS boundary (ARCHITECTURE.md) | Documented / Phase 1+ |
| 8 | Policy compiler compromise | Malicious candidate policy widens access | Deterministic verifier + adversarial suite; signed bundles vs pinned anchors (`bundle/`); semantic-diff verdicts + separation-of-duties approval gate (`diffing.py`, `registry/policies.py`) | Enforced |
| 9 | Control-plane compromise | Attacker edits customer policy server-side | Signed bundles vs pinned anchors (client-side pull verification); cloud cannot deploy policy it cannot sign; approval workflow + SoD in registry | Enforced at skeleton |
| 10 | Tenant breakout | Customer A reads customer B data | tenant_id from verified token claims only; every table and query scoped by it (cloud/store.py, tested); Postgres RLS at managed deployment | Enforced at skeleton |
| 11 | Evidence tampering | Denied events deleted after incident | Individually signed receipts + hash chain; `sentinel evidence verify` names first broken entry (`evidence.py`) | Enforced |
| 12 | Credential theft | Agent reads standing tokens from disk | fs deny patterns (`**/.ssh/**`, `.aws`), JIT broker direction (never store raw secrets) | Partial |
| 13 | Token replay | Stolen temporary capability reused elsewhere | TTL/expiry gates (`not_before/expires_at`); audience binding planned with brokers | Partial |
| 14 | Sentinel supply-chain attack | Malicious dependency/update compromises data plane | Purity-constrained core reduces surface; SBOM/signed releases planned pre-pilot | Planned |
| 15 | Insider admin (Sentinel staff) | Employee inspects tenant telemetry | Metadata-only defaults; no raw prompts/code/secrets collected by design | Enforced by absence |
| 16 | Denial of service | Agent emits millions of decisions/sec | Local evaluation (no round trip); quotas planned with control plane | Partial |

## Non-goals (explicit)

* Complete mediation of arbitrary processes (see #7).
* Protecting a host whose kernel/user account is already compromised.
* Replacing IAM, Vault, MDM, or endpoint EDR.

## Review checklist for changes to `core/`

1. `pytest -q` green including purity linter.
2. `sentinel vectors run` â†’ CONFORMANT; any intentional semantic change bumps
   `SEMANTICS_VERSION` and updates vectors in the same PR.
3. No new imports outside `CORE_ALLOWED_IMPORTS`.
4. Every new rule id added to `core/semantics.py RULES`.

