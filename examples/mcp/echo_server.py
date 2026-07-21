"""A minimal stdio MCP-style server for the worked example — just enough protocol to
demonstrate the guard in front of it. Handles initialize, tools/list, and tools/call
over line-delimited JSON-RPC on stdin/stdout. Not a full MCP implementation; it exists
so `guard mcp -- python echo_server.py` has something real to proxy."""

from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "run_sql", "description": "Run a SQL query", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
]


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "echo"}},
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        text = f"[echo-server] executed {name} with {json.dumps(args)}"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        }
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = handle(json.loads(line))
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
