# vexa-mcp

`vexa-mcp` is the Vexa MCP edge (`core/gateway/services/mcp`, contract
`core/gateway/contracts/mcp.tools.v1`) as a native process. It keeps the Python
service's contract: the streamable-HTTP MCP transport at `/mcp` (sessions,
JSON-RPC shapes, status codes, SSE), the tool list and each tool's input schema,
the 18 built-in tool routes, the tools it assembles from each domain's
`/.well-known/mcp-tools.json` and OpenAPI (late domains included), the
`VEXA_MCP_TOOLS_*` visibility rules, the standing notices, the error rendering,
and the boot refusals.

```sh
vexa-mcp        # listens on HOST:PORT, default 0.0.0.0:8010
```

The settings are the Python service's variables (`GATEWAY_URL`, `ADMIN_API_URL`,
`MEETING_API_URL`, `AGENT_API_URL`, `FLOWS_API_URL`, `CRM_API_URL`,
`VEXA_FEATURES`, `VEXA_MCP_*`, `VEXA_TICKET_SINK_*`, `VEXA_JITSI_HOSTS`). They
are read once at boot. One thread serves each connection.

`src/surface.json` is the built-in surface (instructions, prompts, the 18 tools
with their schemas and routes), generated from the Python service:

```sh
cd core/gateway/services/mcp
.venv/bin/python ../../../../apps/vexa-mcp/gen_surface.py
```

`vexa-daemon` runs it in the `services` group, after agent-api, flows and crm
answer `/health`. `VEXA_NATIVE_PY_MCP=1` runs the Python mcp in the core
process group again, with the same environment.

`PARITY.md` lists what is the same as the Python service and what is not
checked. Two checks run against both:

```sh
cargo build --release --manifest-path apps/vexa-mcp/Cargo.toml
cd core/gateway/services/mcp
# the same requests to the Python and the Rust service, each answer compared
.venv/bin/python ../../../../apps/vexa-mcp/parity.py
# the Python service's own test suite, with create_app starting the Rust binary
PYTHONPATH=../../../../apps/vexa-mcp .venv/bin/python -m pytest -p pytest_rust -p no:cacheprovider tests
```
