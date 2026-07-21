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

## Scaling policy — federated, layered, cached (goose-style)

One flat file doesn't scale to many tools, teams, and MCP servers. Compose instead: each source ships a `PolicyModule` that owns a tool namespace and a layer. A `PolicyRegistry` aggregates them, compiles a layer-ordered index (cached, recompiled on change), and evaluates by namespace — the same shape goose uses for tools (per-source, namespaced, cached).

```python
from agent_guard import PolicyRegistry, PolicyModule, Decision, Guard, JsonlAuditSink

org = PolicyModule.from_dict({"name": "org-base", "namespace": "*", "layer": 100,
    "rules": [{"id": "no-drop", "decision": "deny", "tools": ["sql"],
               "arg_patterns": [r"(?i)drop table"]}]})
sql = PolicyModule.from_dict({"name": "sql-defaults", "namespace": "sql*", "layer": 0,
    "rules": [{"id": "reads-ok", "decision": "allow", "tools": ["sql"]}]})

compiled = PolicyRegistry(default=Decision.DENY).register(org).register(sql).compile()
guard = Guard(compiled, audit=JsonlAuditSink("audit.jsonl"), agent_id="agent-42")
```

Higher layer wins (org override beats provider default). Every verdict carries `module`, `layer`, `rule_id`, and `reason` — call `verdict.trace()` to see exactly which module/layer/rule decided, so federated policy stays debuggable. Provider-declared defaults are the payoff: a tool source ships its own module with sane guardrails; the org only writes overrides.

## LLM judge for the ambiguous band

Some decisions the heuristic can't make. A rule can opt into a judge — consulted only when it matches, like conflict-lens's optional resolver:

```python
from agent_guard import Guard, CallableJudge, Decision

judge = CallableJudge(lambda req: (Decision.DENY, "path looks destructive"))
guard = Guard(compiled, audit=sink, agent_id="a", judge=judge)
```

Fenced, on purpose:
- The judge may only tighten. Its result is clamped to the rule's `judge_ceiling` (default `require_human`) — it can escalate toward safe, never unilaterally `allow` an irreversible action.
- Fail-closed. No judge configured, judge errors, or judge times out → fall back to the rule's decision, never a silent allow.
- Use a different model family for security-relevant judging; a same-family self-grade shares its own blind spots.

## Design stance

- Fail loud at the edge. A policy with no `default` is rejected at load, not silently defaulted.
- Human gate is fail-closed. `require_human` with no approver denies. The safe posture is the default.
- Capability = what policy permits, not what the prompt says. Enforcement is code, not instruction.
- Cross-harness. The wrapped seam is a plain callable, so the same guard fits a raw loop, MCP, or native function-calling.

## Four pillars — identity, authorization, audit, isolation

The `identity/` package is a local-first companion block: it mints a scoped, short-lived per-agent identity from an attested runtime, so the guard authorizes on *who the agent is* and *where it runs* — not the human's inherited permissions.

```
spawn (isolated runtime) -> attest -> mint scoped token -> guard authorizes on tier -> audit
```

Run the whole thing on your laptop, zero cloud:

```bash
python examples/end_to_end.py
```

It spawns a local sandbox, attests it, mints an identity whose scopes are `human_grant ∩ task_scope`, then shows a read allowed, a `DROP TABLE` denied, and a `prod_write` blocked because a `local.container` identity is below the `remote.microvm` tier the policy requires — a local agent cannot self-elevate.

The block boundary is deliberate: `identity` does not import `agent_guard` and vice versa; the example wires them. Identity says *who/where*, the guard says *what*, the audit sink says *did*. See `docs/DESIGN-runtime-identity-binding.md` for the local-and-remote design and the honest trust gradient.

## Status

Early. API will move. Issues and real-world policy examples welcome.

## License

Apache-2.0.
