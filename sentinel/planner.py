"""sentinel plan - task text -> candidate Authority Manifest.

Rule-based planner is the default (local-first, deterministic).
--llm uses OpenRouter (GLM by default) to *propose* a manifest; the
proposal is still only a candidate and is verified by the same
deterministic checks before it is trusted.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .core.schema import Manifest

DEFAULT_LLM_MODEL = os.environ.get("OPENROUTER_MODEL", "z-ai/glm-5.2")

# --------------------------------------------------------------------- rules
DENY_TOOLS = [
    "aws.*",
    "github.repository.delete",
    "github.workflow.modify",
    "github.secrets.read",
    "github.pull_request.merge",
    "kubernetes.*",
    "slack.*",
    "datadog.*",
    "production.*",
]

FS_DENY = ["**/.env", "**/.ssh/**", "**/.aws/**", "**/secrets/**", "**/*.pem"]

CODING_ALLOW = [
    "github.repo.read",
    "github.branch.create",
    "github.commit.write",
    "github.pull_request.create",
    "ci.status.read",
    "npm.*",
]


def detect_intent(task_text: str) -> dict:
    t = task_text.lower()
    intent = {
        "objective": "generic_task",
        "repo": None,
        "issue": None,
        "deploy": bool(re.search(r"\b(deploy|release|ship)\b", t)),
        "read_only": bool(re.search(r"\b(read[- ]only|investigate|analyse|analyze|review)\b", t))
        and not re.search(r"\b(fix|patch|implement|create|open)\b", t),
        "prod_mentioned": bool(re.search(r"\b(production|prod)\b", t)),
    }
    m = re.search(r"\b((?:[\w.-]+)/(?:[\w.-]+))\b", task_text)
    if m:
        intent["repo"] = m.group(1)
    m = re.search(r"#(\d+)", task_text)
    if m:
        intent["issue"] = int(m.group(1))
    if re.search(r"\b(fix|resolve|patch)\b", t):
        intent["objective"] = "fix_and_open_pr"
    elif intent["read_only"]:
        intent["objective"] = "read_and_report"
    return intent


def rule_based_plan(task_text: str) -> Manifest:
    intent = detect_intent(task_text)
    allow = list(CODING_ALLOW)
    if intent["read_only"]:
        allow = ["github.repo.read", "ci.status.read"]
    fs_write = [] if intent["read_only"] else ["workspace/**"]
    manifest = Manifest(
        principal={"agent": "claude-code"},
        task={
            "repo": intent["repo"] or "unknown/unknown",
            "issue": intent["issue"],
            "objective": intent["objective"],
            "raw": task_text.strip(),
        },
        tools={"allow": allow, "deny": list(DENY_TOOLS)},
        filesystem={
            "read": ["workspace/**"],
            "write": fs_write,
            "deny": list(FS_DENY),
        },
        network={"allow": ["github.com", "registry.npmjs.org"], "deny": ["169.254.169.254", "metadata.google.internal"]},
        delegation={"max_depth": 1},
        environment={"development": "allow"},
        expiry_minutes=60,
    )
    manifest.issue()
    return manifest


# ----------------------------------------------------------------- verifier
def verify_manifest(manifest: Manifest, task_text: str) -> list:
    """Deterministic sanity checks on any proposed manifest (rule or LLM)."""
    warnings = []
    intent = detect_intent(task_text)
    denies = manifest.tools.get("deny", [])

    def _denied(prefix: str) -> bool:
        return any(d == prefix or d.endswith("/*") and d.split("/*")[0] in prefix or prefix.startswith(d.replace("*", "")) for d in denies)

    aws_denied = any(d.lower() in ("*", "aws", "aws.*") for d in denies)
    if intent["deploy"] and not aws_denied:
        warnings.append(
            "task mentions deploy but AWS authority is not explicitly scoped - "
            "review whether deployment tools are truly required"
        )
    if not aws_denied:
        warnings.append("AWS is not deny-listed; least privilege expects 'aws: deny *' for non-deploy tasks")
    if manifest.expiry_minutes is None:
        warnings.append("no expiry set: temporal authority boundary missing")
    elif manifest.expiry_minutes > 480:
        warnings.append(f"expiry {manifest.expiry_minutes}m exceeds the recommended 480m maximum")
    if "*" in manifest.network.get("allow", []) or not manifest.network.get("allow"):
        warnings.append("network allowlist empty or unrestricted")
    if int(manifest.delegation.get("max_depth", 0)) > 1:
        warnings.append("delegation max_depth > 1 enables multi-hop laundering; verify each hop")
    if not manifest.filesystem.get("deny"):
        warnings.append("no filesystem deny patterns (secrets/.ssh/.env) present")
    return warnings


# ---------------------------------------------------------------------- LLM
LLM_SYSTEM_PROMPT = """You are Sentinel's policy planner. Given an agent task, output ONLY a JSON object \
describing the MINIMUM authority required (Authority Manifest v0.1). Schema:
{
  "principal": {"agent": "..."},
  "task": {"repo": "...", "issue": null|int, "objective": "..."},
  "tools": {"allow": ["tool.action globs"], "deny": ["..."]},
  "filesystem": {"read": ["globs"], "write": ["globs"], "deny": ["**/.env", "**/.ssh/**", "**/.aws/**", "**/secrets/**", "**/*.pem"]},
  "network": {"allow": ["hosts"], "deny": ["169.254.169.254"]},
  "delegation": {"max_depth": 0|1},
  "environment": {"development": "allow"},
  "expiry_minutes": 60
}
Rules: deny-by-default; always include aws.* and production denies unless the task explicitly requires them; \
never grant shell; expiry <= 480 minutes; output raw JSON with no markdown fences."""


def llm_plan(task_text: str) -> Manifest:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY not set; falling back to rule-based planning")
    model = DEFAULT_LLM_MODEL
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": LLM_SYSTEM_PROMPT},
            {"role": "user", "content": task_text},
        ],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read().decode())
    content = body["choices"][0]["message"]["content"].strip()
    # strip accidental markdown fences
    if content.startswith("```"):
        content = re.sub(r"^```[a-z]*\n?|\n?```$", "", content)
    data = json.loads(content)
    manifest = Manifest.from_dict(data)
    manifest.issue()
    return manifest


def plan(task_text: str, use_llm: bool = False):
    """Returns (manifest, source, warnings)."""
    if use_llm:
        try:
            return llm_plan(task_text), "llm", None
        except Exception as e:  # noqa: BLE001 - fall back, report why
            fallback_err = str(e)
    else:
        fallback_err = None
    return rule_based_plan(task_text), "rules", fallback_err
