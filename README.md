# agent-guard

Least-privilege authorization + audit for AI agent tool calls. One small library that wraps the seam every agent has — the tool-dispatch boundary — and decides `allow` / `deny` / `require_human` per call, then logs every decision.

Harness-agnostic by design: it wraps a plain `dispatch(tool, args)` function, which is the shape of a raw agent loop, an MCP `call_tool`, and a native function-calling executor alike. No framework lock-in.

## The problem

Agents run with their operator's full permissions and no record of what they did. One prompt injection reaches everything the human can touch. `agent-guard` puts a policy-as-code boundary in front of the tool call, so an agent physically cannot run an irreversible action that policy forbids — and every attempt is auditable.

## Install

```bash
pip install -e .            # core, zero dependencies
pip install -e ".[yaml]"    # + YAML policy files
```

## 30-second use

```python
from agent_guard import Guard, Policy, JsonlAuditSink

policy = Policy.from_dict({
    "default": "allow",
    "rules": [
        {"id": "no-drop", "decision": "deny", "tools": ["sql"],
         "arg_patterns": [r"(?i)\bdrop\s+table\b"], "reason": "no destructive sql"},
        {"id": "gate-force-push", "decision": "require_human", "tools": ["git", "shell"],
         "arg_patterns": [r"git\s+push\b.*--force"], "reason": "force-push needs a human"},
    ],
})

guard = Guard(policy, audit=JsonlAuditSink("audit.jsonl"), agent_id="agent-42")

# wrap whatever your harness already calls to run a tool:
guarded = guard.wrap(my_dispatch)
guarded("sql", {"query": "SELECT 1"})          # runs, audited
guarded("sql", {"query": "DROP TABLE users"})  # raises BlockedError, audited, never executed
```

## Run the demo

```bash
python examples/demo.py
```

Shows a benign query allowed, a `DROP TABLE` blocked, a `git push --force` gated to a human (denied here), and the audit trail for all four.

## Core model

- Policy — an explicit `default` (required — no silent fallback) plus ordered `rules`. First matching rule wins.
- Rule — `tools` (glob) + optional `arg_patterns` (regex over the rendered args) → a `decision`.
- Guard — wraps a `dispatch(tool, args)`; evaluates, gates, executes, audits.
- Audit — one structured record per decision (`JsonlAuditSink`, `MemoryAuditSink`, or your own `AuditSink`).

## Design stance

- Fail loud at the edge. A policy with no `default` is rejected at load, not silently defaulted.
- Human gate is fail-closed. `require_human` with no approver denies. The safe posture is the default.
- Capability = what policy permits, not what the prompt says. Enforcement is code, not instruction.
- Cross-harness. The wrapped seam is a plain callable, so the same guard fits a raw loop, MCP, or native function-calling.

## Where this is going

Identity (who the agent is, scoped and short-lived) + this guard (what it may do) + audit (what it did) is the trio. This repo is the `what` and the `did`. The `who` — per-agent identity, delegated from a human, cross-vendor — is the next block.

## Status

Early. API will move. Issues and real-world policy examples welcome.

## License

Apache-2.0.
