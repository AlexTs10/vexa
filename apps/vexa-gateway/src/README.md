# vexa-gateway source

- `main.rs`: the boot (config.v1 preflight, the key, the manifests, the route table, the two listeners) and `keygen`.
- `edge.rs`: the request pipeline (guard, body limit, trace id, routing), the authorization of every forward, the buffered forward, the stream relays, `/health`, `/auth/me` and `/internal/mcp/taint`.
- `routes.rs`, `manifest.rs`: the route table in the Python registration order, Starlette matching, the 422 checks, and the routes.v1 assembly.
- `multiplex.rs`, `ws.rs`: the `/ws` multiplex (Redis fan-in, the signals stream, re-authorization), the voice-note and live-view relays, and RFC 6455 framing.
- `door.rs`, `tickets.rs`, `link.rs`: the service door, subject-ticket.v1, and meeting-link parsing.
- `identity.rs`: gateway-identity.v1 (Ed25519 keys, claims, tokens, headers).
- `guard.rs`, `taint.rs`, `redis.rs`: the edge guard and rate limits, the privacy mark, and a RESP client.
- `paths.rs`, `obs.rs`: path parameters as the Python edge forwards them, trace ids and log lines.
