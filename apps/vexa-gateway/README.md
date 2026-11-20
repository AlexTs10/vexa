# vexa-gateway

`vexa-gateway` is the Vexa API gateway (`core/gateway/services/gateway`) as a native process. It
keeps the Python service's contracts: the public edge (api.v1, the route table that the routes.v1
manifests assemble), the websockets (ws.v1 `/ws`, the voice-note and sign-in live-view relays),
the signed identity it stamps on every forward (gateway-identity.v1), the logevent.v1 lines, and
the service door with its subject tickets (subject-ticket.v1).

```sh
vexa-gateway                                  # the edge on HOST:PORT (default 0.0.0.0:8000)
vexa-gateway keygen SIGNING.pem PUBLIC.pem    # keep or make the identity key pair
```

The settings are the Python service's variables (`config.v1.json` next to the Python code: the
config.v1 preflight, `ADMIN_API_URL`, `MEETING_API_URL`, `MCP_URL`, `AGENT_API_URL`,
`CRM_API_URL`, `REDIS_URL`, `VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE`, `VEXA_AGENT_ALLOW`,
`GUARD_*`). Where `VEXA_FLOWS_SERVICE_KEY` is set, the same process serves the service door on
`VEXA_GATEWAY_SERVICE_DOOR_PORT` (default 8002). The binary reads the routes.v1 manifests and
`config.v1.json` from the checkout (`VEXA_SOURCE_DIR`, or the folders above the binary). One
thread serves each connection.

`vexa-daemon` runs it in the `services` group, after the core process group.
`VEXA_NATIVE_PY_GATEWAY=1` runs the Python gateway and its door in the core group again, with the
same environment.

`PARITY.md` lists what is the same as the Python service, what differs and what is not checked.
The check that runs against both:

```sh
cargo build --release --manifest-path apps/vexa-gateway/Cargo.toml
cd core/gateway/services/gateway
# the same requests to the Python and the Rust gateway: answers, upstream requests, log lines
.venv/bin/python ../../../../apps/vexa-gateway/parity.py
```
