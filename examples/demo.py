from __future__ import annotations

from agent_guard import BlockedError, Guard, MemoryAuditSink, Policy


def raw_dispatch(tool: str, args: dict) -> str:
    return f"EXECUTED {tool}({args})"


def always_deny(_request) -> bool:
    return False


def build_policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "block-sql-drop",
                    "decision": "deny",
                    "tools": ["sql", "db_*"],
                    "arg_patterns": [r"(?i)\bdrop\s+table\b"],
                    "reason": "destructive SQL is never allowed for an agent",
                },
                {
                    "id": "gate-force-push",
                    "decision": "require_human",
                    "tools": ["shell", "git"],
                    "arg_patterns": [r"git\s+push\b.*--force"],
                    "reason": "force-push rewrites shared history",
                },
            ],
        }
    )


def main() -> None:
    audit = MemoryAuditSink()
    guard = Guard(build_policy(), audit=audit, agent_id="agent-42", approver=always_deny)
    dispatch = guard.wrap(raw_dispatch)

    attempts = [
        ("sql", {"query": "SELECT * FROM users LIMIT 10"}),
        ("sql", {"query": "DROP TABLE users"}),
        ("shell", {"cmd": "git push --force origin main"}),
        ("shell", {"cmd": "ls -la"}),
    ]

    print("=== agent-guard demo ===\n")
    for tool, args in attempts:
        try:
            result = dispatch(tool, args)
            print(f"ALLOWED  {tool}: {args}\n         -> {result}")
        except BlockedError as err:
            print(f"BLOCKED  {tool}: {args}\n         -> {err}")
        print()

    print("=== audit trail ===")
    for record in audit.records:
        flag = "ran" if record.executed else "blocked"
        print(f"[{flag}] {record.decision:<13} {record.tool:<6} rule={record.rule_id} :: {record.reason}")

    blocked = sum(1 for r in audit.records if not r.executed)
    assert blocked == 2, f"expected 2 blocked calls, got {blocked}"
    print(f"\n{blocked} irreversible/gated actions stopped before execution. Every decision is in the audit trail.")


if __name__ == "__main__":
    main()
