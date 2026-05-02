#!/usr/bin/env bash
# Quick smoke test that exercises the MCP server over stdio with a few
# canned JSON-RPC calls. Reads the responses on stdout.
set -euo pipefail
cd "$(dirname "$0")/../.."
TOML=/home/dima/retal/.jwasm-mcp.toml
BIN=$HOME/go/bin/jwasm-mcp

# Build the request stream: initialize, tools/list, then a few tool calls.
{
  cat <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"which_proc","arguments":{"file":"render3d.inc","line":250}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"addr_to_location","arguments":{"addr":"0xa17c"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"find_callers","arguments":{"name":"Blit"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"find_callees","arguments":{"name":"Main"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"module_layout","arguments":{"file":"main.inc"}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"unresolved","arguments":{"limit":10}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"function_context","arguments":{"name":"Main","caller_context_lines":3}}}
EOF
} | "$BIN" -config "$TOML"
