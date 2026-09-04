# Security Policy

## Reporting a vulnerability

Email: **security@sentinel-authority.example** (placeholder until domain is live)

Please include: affected component (ideally a path under `sentinel/`),
reproduction steps or PoC, impact assessment, and whether you want credit.
We aim to acknowledge within **72 hours** and will coordinate disclosure
with you; we will not pursue legal action over good-faith research.

## Supported versions

| Version | Status | Notes |
|---|---|---|
| 0.1.x / core 1.0.0 | active development | pre-production; breaking changes likely |

## Security properties claimed today

* `sentinel/core/` is a pure, I/O-free, stdlib-only deterministic engine,
  enforced by an import-linter test and covered by machine-readable
  conformance vectors (`sentinel vectors run`).
* Deny-by-default semantics with canonical precedence
  (guardrails > temporal > deny > crossing > allow > default).
* Manifest v1 temporal gates: authority is inert outside
  `[not_before, expires_at]`.
* Delegation invariant: sub-agents can never exceed parent depth.
* Argument constraints fail closed on missing parameters.
* Metadata-first telemetry: no prompts, code, or secrets leave the machine;
  the `--llm` planner is opt-in and clearly labeled.

## Security properties NOT claimed today

* Complete mediation of arbitrary processes (the PEP 578 adapter is a demo
  adapter, not a sandbox — see THREAT_MODEL.md #7).
* Tamper-proof evidence (signed/hash-chained receipts are Phase 1).
* Multi-tenant isolation (control plane not yet built).
* Any compliance certification.

## Secure development practices (current)

* Protected planning: semantic changes to `core/` require conformance-vector
  updates in the same change.
* Dependency surface intentionally minimal (`PyYAML` runtime-only).
* No secrets ever committed; demo assets contain no real credentials.

Planned before any paid inline deployment: SBOM per release, artifact signing,
dependency scanning, SAST, external penetration test (see ARCHITECTURE.md).

## security.txt (draft)

```
Contact: mailto:security@sentinel-authority.example
Expires: 2027-08-25T00:00:00Z
Preferred-Languages: en
Policy: https://example.invalid/security-policy
```
