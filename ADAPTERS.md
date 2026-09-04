# Sentinel Adapters — Cross-Agent Enforcement

One deterministic boundary, every coding agent:

```
Claude Code ──▶ claude_code.py ─┐
Cursor      ──▶ cursor.py     ──┼──▶ neutral probe dict ──▶ LOCAL PDP
OpenAI Codex──▶ codex.py      ──┘    (identical semantics)   (signed bundle)
```

## The contract (tested, not aspirational)

`tests/test_phase3_adapters.py::test_equivalence_*` asserts that
semantically-equal events from different platforms produce **byte-identical
probe dicts**, therefore identical decisions and correlated receipts.

Example — "run `aws sts get-caller-identity`":

| Platform | Event field path | Probe produced |
|---|---|---|
| Claude Code | `tool_name=Bash`, `tool_input.command` | `{"kind":"spawn","executable":"aws"}` |
| Cursor | `hook_event_name=beforeShellExecution`, `command` | identical |
| Codex | `type=exec_approval`, `command[]` | identical |

## Mapping tables

### claude-code (`PreToolUse`, schema: Anthropic hooks reference)

| tool_name | probe |
|---|---|
| `Bash` | spawn (first token of command) |
| `Read` | path r |
| `Write` / `Edit` / `NotebookEdit` | path w |
| `WebFetch` / `WebSearch` | host (from url/query) |
| `mcp__<server>__<tool>` | action `<server>.<tool>` + scalar params |

Response: structured JSON (`hookSpecificOutput.permissionDecision`
allow/deny/ask + `sentinel` metadata block), exit 0. Legacy exit-code mode
(0/2, stderr reason): `--style code`.

### cursor (contract version: **pinned-contract-2026-08**)

| hook_event_name | probe |
|---|---|
| `beforeShellExecution` | spawn |
| `beforeReadFile` | path r |
| `beforeEditFile` / `afterFileEdit` | path w |
| `beforeMCPRequest` | action `<server>.<tool>` |

Response contract: exit 0 allow / exit 2 block (stderr carries the reason).

### codex

| type | probe |
|---|---|
| `exec_approval` / `exec` / `shell` | spawn (argv[0] or first token) |
| `patch_approval` / `apply_patch` / `file_write` | path w |
| `file_read` / `read_file` | path r |
| `network` | host (+port) |

Response contract: exit 0 allow / exit 2 block.

> Schema drift policy: vendor hook surfaces evolve. Mappings here are pinned
> to fixture files under `sentinel/adapters/fixtures/<platform>/`; when a
> vendor changes shape, the fixtures diff visibly in review before any
> enforcement behavior changes silently.

## Usage

```bash
# wire an agent (prints snippet; Sentinel never edits your dotfiles)
sentinel adapters print-config claude-code   # also: cursor | codex

# run an adapter against a stdin event
echo '{"session_id":"s1","hook_event_name":"PreToolUse",
       "tool_name":"Bash","tool_input":{"command":"aws sts get-caller-identity"}}' \
  | python -m sentinel.adapters.claude_code

# decision flow: PDP-first (trace_id = session id), logged local fallback on
# ./authority.yaml when the PDP is unreachable; fail-closed if neither.
```

Receipts: every decision lands in the evidence ledger with
`trace_id = <agent session id>`, so one agent session = one contiguous
evidence chain segment.
