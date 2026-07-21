from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any

from .guard import Guard


def _blocked_response(msg_id: Any, reason: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"content": [{"type": "text", "text": f"blocked by agent-guard: {reason}"}], "isError": True},
        }
    )


def handle_line(line: str, guard: Guard) -> tuple[str | None, str | None]:
    """Core proxy decision, pure and testable. Returns (forward_to_server, reply_to_client).
    Non-JSON and non-`tools/call` messages pass straight through. A `tools/call` is
    evaluated by the guard: allowed -> forward; blocked -> a tool-error reply to the
    client, the server never sees it. Exactly one of the tuple slots is set."""
    stripped = line.strip()
    if not stripped:
        return None, None
    try:
        msg = json.loads(stripped)
    except json.JSONDecodeError:
        return line, None
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return line, None

    params = msg.get("params") or {}
    name = params.get("name", "")
    args = params.get("arguments") or {}
    allowed, verdict = guard.decide(name, args)
    guard.record(name, args, verdict, executed=allowed)
    if allowed:
        return line, None
    return None, _blocked_response(msg.get("id"), verdict.reason)


def run_proxy(server_argv: list[str], guard: Guard, stdin=None, stdout=None) -> int:
    """Sit between an MCP client and a stdio MCP server, guarding every tools/call.
    Wrap your server command: `guard mcp --policy p.yaml -- <server cmd>`."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    server = subprocess.Popen(server_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def pump_client_to_server() -> None:
        for line in stdin:
            forward, reply = handle_line(line, guard)
            if forward is not None:
                server.stdin.write(forward if forward.endswith("\n") else forward + "\n")
                server.stdin.flush()
            if reply is not None:
                stdout.write(reply + "\n")
                stdout.flush()
        server.stdin.close()

    def pump_server_to_client() -> None:
        for line in server.stdout:
            stdout.write(line)
            stdout.flush()

    threads = [threading.Thread(target=pump_client_to_server), threading.Thread(target=pump_server_to_client)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return server.wait()
