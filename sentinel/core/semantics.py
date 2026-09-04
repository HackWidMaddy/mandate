"""Versioned semantics of the Sentinel deterministic engine.

SEMANTICS_VERSION identifies the exact decision semantics implemented by
sentinel.core.evaluator. Conformance vectors are tagged with this version;
any port (Go, Rust) must pass the same vectors byte-for-byte to claim
compatibility.

Canonical evaluation order for every check (first match wins):

  1. guardrails            org-level denies; no workflow may override
  2. temporal gates        not_before / expires_at
  3. explicit denies       tools.deny / filesystem.deny / network.deny
  4. crossing heuristics   action names that name a forbidden environment
  5. explicit allows       tools.allow / filesystem.{read,write} / network.allow
  6. default deny          everything else

Delegation depth and argument constraints are independent checks evaluated
by their own methods; callers must consult them explicitly.
"""
from __future__ import annotations

SEMANTICS_VERSION = "1.0.0"

MANIFEST_SCHEMA_VERSION = "1.0"

RULES = {
    # ---- order 1: guardrails
    "guardrail": (
        "Organization guardrail deny: authority no workflow manifest can grant."),
    # ---- order 2: temporal
    "not_before": ("Authority not yet active: evaluated before not_before."),
    "expiry": ("Authority expired at the manifest's expires_at timestamp."),
    # ---- order 3: explicit denies
    "tools.deny": ("Action matched an explicit tool deny pattern."),
    "filesystem.deny": ("Path matched an explicit filesystem deny pattern."),
    "network.deny": ("Host matched an explicit network deny pattern."),
    # ---- order 4: crossing heuristics
    "environment.action-crossing": (
        "Action name itself references a non-authorized environment."),
    # ---- order 5: allows
    "tools.allow": ("Action granted by an allow pattern."),
    "filesystem.read": ("Path granted by filesystem read scope."),
    "filesystem.write": ("Path granted by filesystem write scope."),
    "network.allow": ("Egress granted by the network allowlist."),
    "environment": ("Environment explicitly allowed by the manifest."),
    "delegation": ("Delegation within the manifest's max_depth."),
    "constraints.satisfied": ("Argument constraints present and satisfied."),
    # ---- order 6 / fallbacks
    "default-deny": ("No rule authorizes this action; deny-by-default applies."),
    "fs-default-deny": ("Path outside every granted scope; deny-by-default."),
    "net-default-deny": ("Destination absent from the egress allowlist."),
    "spawn-default-deny": ("Shell/process authority never granted to this workflow."),
    "environment-default-deny": ("Environment not authorized for this workflow."),
    "constraint.missing-params": (
        "Constraint parameters were required but not supplied (fail closed)."),
    "constraint.violated": ("Supplied arguments violate a declared constraint."),
}

# stdlib modules core/ is permitted to import (purity contract)
CORE_ALLOWED_IMPORTS = {
    "__future__",
    "dataclasses",
    "datetime",
    "enum",
    "json",
    "os",
    "re",
    "typing",
}
