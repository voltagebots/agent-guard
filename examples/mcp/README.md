# Worked example — guard an MCP server

`guard mcp` sits between an MCP client and a stdio MCP server and checks every `tools/call` against your policy. Zero changes to the server or the agent.

## Try it against the echo server

```bash
# a benign call is forwarded (the server runs it):
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_sql","arguments":{"q":"SELECT 1"}}}' \
  | guard mcp --policy examples/mcp/policy.yaml -- python examples/mcp/echo_server.py

# a destructive call is blocked BEFORE the server sees it:
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_sql","arguments":{"q":"DROP TABLE users"}}}' \
  | guard mcp --policy examples/mcp/policy.yaml -- python examples/mcp/echo_server.py
```

Expected:

```
{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "[echo-server] executed run_sql ..."}], "isError": false}}
{"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "blocked by agent-guard: destructive or unscoped SQL is not allowed"}], "isError": true}}
```

The block reply comes from the guard; the server never received it.

## Wire it into a real MCP client

In any MCP client config (Claude Desktop, Claude Code, Cursor, ...), wrap the server command:

```jsonc
{
  "mcpServers": {
    "db": {
      "command": "guard",
      "args": ["mcp", "--policy", "/abs/path/policy.yaml", "--audit", "/abs/path/audit.jsonl",
               "--", "your-real-mcp-server", "--flag", "value"]
    }
  }
}
```

Every tool call now passes policy and lands in `audit.jsonl`. Tighten `policy.yaml` per server — tool names come from the server's `tools/list`.
