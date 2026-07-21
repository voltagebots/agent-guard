from __future__ import annotations

import argparse
import os
import subprocess
import sys

from agent_guard import BlockedError, Guard, JsonlAuditSink, MemoryAuditSink, Policy, load_policy
from agent_guard.guard import ApprovalRequest
from identity import Broker, ContainerRuntime, LocalAttestor, LocalRuntime, RefusedError, RuntimeSpec


def _shell(tool: str, args: dict) -> str:
    if tool not in {"shell", "exec"}:
        raise ValueError(f"unsupported tool '{tool}'")
    result = subprocess.run(args["cmd"], shell=True, capture_output=True, text=True)
    return (result.stdout + result.stderr).strip()


def _default_policy() -> Policy:
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "id": "block-rm-rf",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"\brm\s+-rf\b", r"\brm\s+-fr\b"],
                    "reason": "recursive force delete blocked",
                },
                {
                    "id": "block-sql-drop",
                    "decision": "deny",
                    "tools": ["shell"],
                    "arg_patterns": [r"(?i)\bdrop\s+table\b"],
                    "reason": "destructive sql blocked",
                },
                {
                    "id": "gate-force-push",
                    "decision": "require_human",
                    "tools": ["shell"],
                    "arg_patterns": [r"git\s+push\b.*--force", r"git\s+push\b.*-f\b"],
                    "reason": "force-push rewrites shared history",
                },
            ],
        }
    )


def _tty_approver(request: ApprovalRequest) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"\n  approve '{request.tool}: {request.args.get('cmd', request.args)}'? [{request.reason}] (y/N) ")
    return answer.strip().lower() in {"y", "yes"}


def _build_sandbox(args):
    if args.runtime == "container":
        runtime = ContainerRuntime()
        sandbox = runtime.spawn(RuntimeSpec(kind="local.container", image=args.image, network=args.network))
        return sandbox, sandbox.attest()
    runtime = LocalRuntime(tool_fn=_shell)
    sandbox = runtime.spawn(RuntimeSpec(code_digest=args.digest, kind="local.process"))
    return sandbox, sandbox.attest()


def _run(args) -> int:
    sandbox, attestation = _build_sandbox(args)

    allowlist = set(args.allow_digest)
    if args.dev_trust_runtime:
        allowlist.add(attestation.code_digest)
    result = LocalAttestor(allowlist).verify(attestation)

    try:
        token = broker_mint(result, args)
    except RefusedError as err:
        print(f"refused: {err}", file=sys.stderr)
        sandbox.close()
        return 2

    policy = load_policy(args.policy) if args.policy else _default_policy()
    audit = JsonlAuditSink(args.audit) if args.audit else MemoryAuditSink()
    guard = Guard(
        policy,
        audit=audit,
        agent_id=token.agent_id,
        trust_tier=token.trust_tier,
        approver=_tty_approver,
    )

    command = " ".join(args.command)
    print(f"[{token.agent_id} @ {token.trust_tier}] $ {command}", file=sys.stderr)
    exit_code = 0
    try:
        output = guard.wrap(sandbox.dispatch)("shell", {"cmd": command})
        if output:
            print(output)
    except BlockedError as err:
        print(f"blocked: {err}", file=sys.stderr)
        exit_code = 3
    finally:
        sandbox.close()

    if isinstance(audit, MemoryAuditSink) and args.show_audit:
        print("--- audit ---", file=sys.stderr)
        for record in audit.records:
            flag = "ran" if record.executed else "blocked"
            print(f"  [{flag}] {record.decision} :: {record.reason}", file=sys.stderr)
    return exit_code


def broker_mint(result, args):
    secret = os.urandom(32)
    grant = set(args.scope)
    return Broker(secret=secret, ttl_seconds=args.ttl).mint(
        result, subject=args.subject, human_grant=grant, task_scope=grant
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard", description="Run a command in a governed sandbox.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a command through the guard")
    run.add_argument("--runtime", choices=["local", "container"], default="local")
    run.add_argument("--image", help="container image (container runtime only)")
    run.add_argument("--network", action="store_true", help="allow container network (default: none)")
    run.add_argument("--policy", help="policy file (yaml/json); default blocks rm -rf / drop table, gates force-push")
    run.add_argument("--audit", help="append audit records to this JSONL file")
    run.add_argument("--subject", default=f"human:{os.environ.get('USER', 'unknown')}")
    run.add_argument("--scope", action="append", default=[], help="granted scope (repeatable)")
    run.add_argument("--allow-digest", action="append", default=[], help="allowlisted code digest (repeatable)")
    run.add_argument("--dev-trust-runtime", action="store_true", help="dev: trust the spawned runtime's digest")
    run.add_argument("--digest", default="dev", help="local runtime code digest")
    run.add_argument("--ttl", type=int, default=300)
    run.add_argument("--show-audit", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run")
    run.set_defaults(func=_run)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    command = [c for c in getattr(args, "command", []) if c != "--"]
    args.command = command
    if not command:
        print("nothing to run; usage: guard run -- <command>", file=sys.stderr)
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
