"""Deterministic allow/deny evaluator (pure core).

Design principles:
  * deny-by-default
  * explicit deny always wins over allow
  * organization guardrails dominate every workflow-level rule
  * temporal gates: authority is inert outside [not_before, expires_at]
  * delegation can never exceed the parent's max_depth
  * argument constraints fail closed when parameters are missing
  * every decision carries a machine-stable rule id + human-readable reason

Canonical evaluation order lives in semantics.py; both files are part of the
versioned semantics contract checked by conformance vectors.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .schema import Manifest


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: str = ""

    def __str__(self) -> str:
        tag = "ALLOW" if self.allowed else "DENY"
        return f"{tag}: {self.reason}" + (f" [rule: {self.rule}]" if self.rule else "")


def _norm_path(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(str(path)))
    return p.replace("\\", "/").lower()


def _glob_to_regex(pattern: str) -> str:
    """Translate a manifest glob ('workspace/**', '*.example.com') to regex.

    '**' matches across path separators, '*' matches within one segment,
    except for host patterns where '*' naturally spans labels.
    """
    pattern = pattern.strip().replace("\\", "/")
    i, out = 0, ""
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 3] == "**/":
                out += "(?:.*/)?"
                i += 3
            elif pattern[i : i + 2] == "**":
                out += ".*"
                i += 1 + 1
            else:
                out += "[^/]*"
                i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(c)
            i += 1
    return "^" + out + "$"


class Evaluator:
    def __init__(self, manifest: Manifest, base_dir: Optional[str] = None,
                 now=None):
        self.manifest = manifest
        self.base_dir = os.path.abspath(base_dir or os.getcwd()).replace("\\", "/")
        self._now = now

    # ------------------------------------------------------------ internals
    def _resolved(self, pattern: str) -> str:
        pattern = os.path.expanduser(pattern.strip())
        if os.path.isabs(pattern) or (len(pattern) > 1 and pattern[1] == ":"):
            return pattern.replace("\\", "/").lower()
        return (self.base_dir + "/" + pattern.replace("\\", "/")).lower()

    def _match(self, value: str, patterns: Iterable[str], resolver=None) -> Optional[str]:
        for pat in patterns:
            candidate = resolver(pat) if resolver else pat.lower().strip()
            if re.match(_glob_to_regex(candidate), value.lower()):
                return pat
        return None

    def _split_guardrail(self, g: str):
        """Guardrails may be plain action globs or prefixed 'fs:<glob>' / 'net:<glob>'."""
        low = g.lower()
        if low.startswith("fs:"):
            return "fs", g.split(":", 1)[1].strip()
        if low.startswith("net:"):
            return "net", g.split(":", 1)[1].strip()
        return "action", g.strip()

    def _guardrail_hit(self, kind: str, value: str,
                       resolver=None) -> Optional[str]:
        for g in self.manifest.guardrails:
            gkind, gpat = self._split_guardrail(g)
            if gkind != kind:
                continue
            candidate = resolver(gpat) if resolver else gpat.lower()
            if re.match(_glob_to_regex(candidate), value.lower()):
                return g
        return None

    def _temporal_decision(self) -> Optional[Decision]:
        m = self.manifest
        if m.not_yet_active(now=self._now):
            return Decision(
                False,
                f"authority not yet active (not_before {m.not_before})",
                rule="not_before",
            )
        if m.expired(now=self._now):
            return Decision(
                False,
                f"authority expired at {m.expires_at} "
                "(temporal authority boundary)",
                rule="expiry",
            )
        return None

    # -------------------------------------------------------------- checks
    def check_action(self, action: str, params: Optional[dict] = None) -> Decision:
        """Tool/API actions, e.g. 'github.repo.read'. Canonical order applies.

        When params are supplied and the manifest declares constraints for
        this action, they are evaluated as well.
        """
        a = action.lower().strip()

        # 1. guardrails - org denies no workflow can override
        hit = self._guardrail_hit("action", a)
        if hit:
            return Decision(
                False, f"action '{action}' blocked by organization guardrail '{hit}'",
                rule="guardrail")

        # 2. temporal gates
        temporal = self._temporal_decision()
        if temporal:
            return temporal

        # 3. explicit deny
        hit = self._match(a, self.manifest.tools["deny"])
        if hit:
            return Decision(False, f"action '{action}' matches explicit deny '{hit}'", rule=f"tools.deny:{hit}")

        # 4. environment crossing heuristic on the action name
        if a.startswith("production.") or ".production." in a or a.endswith(".production"):
            return Decision(False, f"action '{action}' crosses into production", rule="environment.action-crossing")

        # 5. explicit allow
        hit = self._match(a, self.manifest.tools["allow"])
        if hit:
            allowed = Decision(True, f"action '{action}' granted by allow '{hit}'", rule=f"tools.allow:{hit}")
            if params is not None and self.manifest.constraints:
                cdec = self.check_constraints(action, params)
                if not cdec.allowed:
                    return cdec
            return allowed

        # 6. default deny
        return Decision(
            False,
            f"action '{action}' is not part of this workflow's required authority "
            "(deny-by-default)",
            rule="default-deny",
        )

    def check_constraints(self, action: str, params: dict) -> Decision:
        """Evaluate declared argument constraints against supplied parameters.

        Fail-closed: constraints that apply but lack their parameter deny.
        """
        applicable = [
            c for c in self.manifest.constraints
            if re.match(_glob_to_regex(str(c.get("action", "*")).lower()),
                        action.lower())
        ]
        if not applicable:
            return Decision(True, "no constraints apply", rule="constraints.satisfied")
        for c in applicable:
            param = str(c.get("param", ""))
            op = str(c.get("op", "eq")).lower()
            expected = c.get("value")
            if params is None or param not in params:
                return Decision(
                    False,
                    f"constraint requires parameter '{param}' for action "
                    f"'{action}' (fail closed)",
                    rule="constraint.missing-params")
            actual = params[param]
            ok = {
                "eq": lambda: actual == expected,
                "neq": lambda: actual != expected,
                "in": lambda: actual in (expected or []),
                "not_in": lambda: actual not in (expected or []),
                "matches": lambda: re.match(_glob_to_regex(str(expected).lower()), str(actual).lower()) is not None,
                "not_matches": lambda: re.match(_glob_to_regex(str(expected).lower()), str(actual).lower()) is None,
            }[op]()
            if not ok:
                return Decision(
                    False,
                    f"parameter '{param}'={actual!r} violates constraint "
                    f"{param} {op} {expected!r}",
                    rule="constraint.violated")
        return Decision(True, f"{len(applicable)} constraint(s) satisfied",
                        rule="constraints.satisfied")

    def check_path(self, path: str, mode: str) -> Decision:
        """Filesystem access. mode: 'r' or 'w'.

        Relative paths resolve against base_dir (the task workspace root),
        never against the evaluator's own working directory.
        """
        raw = str(path)
        if not os.path.isabs(raw) and not (len(raw) > 1 and raw[1] == ":"):
            raw = os.path.join(self.base_dir, raw)
        norm = _norm_path(raw)

        # 1. guardrails (fs: prefix)
        hit = self._guardrail_hit("fs", norm, resolver=self._resolved)
        if hit:
            return Decision(False, f"path '{path}' blocked by guardrail '{hit}'",
                            rule="guardrail")

        temporal = self._temporal_decision()
        if temporal:
            return temporal

        writing = mode not in ("r", "rb", "")
        key = "write" if writing else "read"

        # 3. explicit deny
        hit = self._match(norm, self.manifest.filesystem["deny"], resolver=self._resolved)
        if hit:
            return Decision(
                False,
                f"path '{path}' matches explicit filesystem deny '{hit}'",
                rule=f"filesystem.deny:{hit}",
            )

        # 5. explicit allow
        hit = self._match(norm, self.manifest.filesystem[key], resolver=self._resolved)
        if hit:
            return Decision(True, f"path '{path}' allowed by filesystem.{key} '{hit}'", rule=f"filesystem.{key}:{hit}")

        # 6. default deny
        return Decision(
            False,
            f"path '{path}' outside task-scoped {key} scope "
            f"({', '.join(self.manifest.filesystem[key]) or 'no grants'})",
            rule="fs-default-deny",
        )

    def check_host(self, host: str, port: int = 443) -> Decision:
        h = str(host).strip().strip("[]").lower()

        hit = self._guardrail_hit("net", h)
        if hit:
            return Decision(False, f"egress to '{host}' blocked by guardrail '{hit}'",
                            rule="guardrail")

        temporal = self._temporal_decision()
        if temporal:
            return temporal

        hit = self._match(h, self.manifest.network["deny"])
        if hit:
            return Decision(False, f"host '{host}' matches network deny '{hit}'", rule=f"network.deny:{hit}")

        hit = self._match(h, self.manifest.network["allow"])
        if hit:
            return Decision(True, f"host '{host}' allowed by network.allow '{hit}'", rule=f"network.allow:{hit}")

        return Decision(
            False,
            f"egress to '{host}' not required by this workflow (deny-by-default egress)",
            rule="net-default-deny",
        )

    def check_spawn(self, executable: str) -> Decision:
        """Process / shell execution. Shell escape is treated as its own tool.

        Every alias of the executable is evaluated through the full canonical
        order; an explicit deny/guardrail/temporal hit on ANY alias wins over
        an allow on another alias (an allow must never launder a denial).
        """
        exe = os.path.basename(str(executable).strip('"')).lower() or str(executable).lower()
        names = (exe, f"shell.{exe}", f"process.{exe}", "process.spawn", "shell.*")
        decisions = [self.check_action(n) for n in names]
        for d in decisions:
            if not d.allowed and (
                d.rule.startswith(("guardrail", "tools.deny"))
                or d.rule in ("not_before", "expiry")
            ):
                return d
        for d in decisions:
            if d.allowed:
                return d
        return Decision(
            False,
            f"spawning '{executable}' requires shell/process authority that this "
            "workflow was never granted",
            rule="spawn-default-deny",
        )

    def check_environment(self, env_name: str) -> Decision:
        temporal = self._temporal_decision()
        if temporal:
            return temporal
        target = self.manifest.environment.get(env_name.lower())
        if target == "allow":
            return Decision(True, f"environment '{env_name}' explicitly allowed", rule="environment")
        return Decision(
            False,
            f"environment '{env_name}' not authorized for this workflow "
            "(environment crossing blocked)",
            rule="environment-default-deny",
        )

    def check_delegation(self, depth: int) -> Decision:
        temporal = self._temporal_decision()
        if temporal:
            return temporal
        maxd = int(self.manifest.delegation.get("max_depth", 0))
        if depth <= maxd:
            return Decision(True, f"delegation depth {depth} <= max_depth {maxd}", rule="delegation")
        return Decision(
            False,
            f"delegation depth {depth} exceeds max_depth {maxd}; "
            "a sub-agent may never gain authority its parent lacked (delegation laundering blocked)",
            rule="delegation",
        )
