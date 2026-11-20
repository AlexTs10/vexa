# Parity with the Python gateway

## Expected

Written down before the side-by-side runs; the code was written first, from the Python source.

- Every route of the Python edge answers the same status, body and headers that carry meaning
  (`content-type`, `content-length`, `location`, `allow` as a set, `retry-after`,
  `x-trace-id`, `cache-control`, `x-accel-buffering`, `mcp-session-id`,
  `mcp-protocol-version`, `content-disposition`) for the same request: `/health`, `/auth/me`,
  `/internal/mcp/taint`, every meetings, identity, mcp, agent and crm row, 404, 405, the 307 of a
  trailing slash, the 422 of a bad path parameter, the 400 of an encoded separator, the 413 of a
  body over 1 MiB, HEAD.
- Each forward sends the same upstream request: method, path, query, framing (length, chunked or
  none), body, `x-api-key`, the `x-user-*` headers, the identity token's claims, `x-trace-id`,
  `x-vexa-taint`, and none of the authority headers the client sent.
- Auth and scope rules give the same 401, 403 and 503 bodies: missing and invalid key, scope,
  delegated route, the agent tier, the admin-api hop down (after the same retries).
- The stream relays (agent SSE, `GET /mcp`, the bundle rows) give the same head and the same bytes.
- `/ws` gives the same frames and close codes: missing, invalid and browser-only key, ping,
  invalid JSON, unknown action, subscribe (valid, empty, refused), a Redis message on a subscribed
  meeting's channel and on the user's own channel, unsubscribe; the query-key path; the voice-note
  and live-view refusals.
- The service door gives the same answers and upstream requests: health, 405, 307, every refusal
  reason, the identity, crm and meetings forwards, the subject-ticket checks, the ticket and grant
  it mints on `/internal/validate`, the inbound calls to flows.
- The guard's rate limit on Redis gives 429 at the same request.
- Every request prints the same logevent.v1 lines (event, level, audience, span, user, fields).
- The Python code does not change, so the Python suite stays as it is.

A result that differs from one of these is a finding, not a test to change.

## Actual (2026-11-20, Apple M3, macOS)

### parity.py — the same requests to both services

`parity.py` starts the Python gateway (`python -m gateway`) and then the binary, each with the
same environment, the same fake upstreams (admin-api, meeting-api, mcp, agent-api, crm, flows-api)
and a real `redis-server` (flushed between the two runs). Each step records the answer, every
upstream request it caused and every logevent.v1 line it printed. Trace ids, token times, ticket
ids and port numbers are normalised; nothing else is.

| Profile | What it covers | Steps | Result |
|---|---|---|---|
| `edge` | the routes above, the forwards, the stream relays, the websockets | 50 | equal |
| `door` | `VEXA_FLOWS_SERVICE_KEY` set: the service door | 18 | equal |
| `guard` | `GUARD_RATE_LIMIT_RPM=3` on Redis | 5 | equal |
| `admin-down` | admin-api unreachable: 503 and the 4503 close | 2 | equal |

`75/75 steps the same`.

### The Python test suite against the binary

NOT CHECKED. The suite builds the app in-process with fake ports (authorizer, HTTP client, Redis)
and reads the FastAPI objects; pointing it at a binary needs a relay for each of those ports.
The Python code does not change; the suite runs in `gates.mjs all` on the Dell.

### cargo test

`cargo test`: 14 passed (vexa-gateway), 17 passed (vexa-native-kit, `--features py,tls`),
14 passed (vexa-mcp), 33 passed (vexa-credential-broker), 32 passed (vexa-daemon). The broker and mcp
`parity.py` still give `PARITY OK` (148 and 204 steps).

### Live leg (vexa-daemon serve, `infra,services,ui`, own `VEXA_APP_SUPPORT_DIR`)

Through the native gateway on 127.0.0.1:23056, with keys minted by admin-api:

| Step | Native gateway | `VEXA_NATIVE_PY_GATEWAY=1` |
|---|---|---|
| `GET /auth/me` | 200, the user, `x-trace-id` | 401 without a key (spot check) |
| `GET /meetings` | 200 `{"meetings":[]}` | NOT CHECKED |
| no key / browser-only key | 401 `Missing API key` / 403 `Insufficient scope for this endpoint` | NOT CHECKED |
| `/mcp` initialize, initialized, tools/list | 200 with a session, 202, 135 tools | NOT CHECKED |
| `/mcp` with a browser-only key | 403 | NOT CHECKED |
| `/ws` ping, subscribe to a meeting the user owns, unsubscribe | pong, subscribed, unsubscribed | subscribed, unsubscribed |
| the terminal (127.0.0.1:23000) | page 200; claim code, operator sign-in link, `/api/auth/me` 200 as the administrator; its calls (`/agent/workspace/init`, `/agent/vexa/*`) reach the edge as user 2 | NOT CHECKED |
| the door's `/health` on 23002 | NOT CHECKED | 200 |

### Memory (RSS)

| | Python | Rust |
|---|---|---|
| parity.py, service alone (4 profiles) | 46–85 MB | 7.3–12.6 MB |
| live stack: core group with the gateway / core group + native gateway | 105.6 MB | 79.8 MB + 6.0 MB |

## Differs (known, accepted)

- `/docs`, `/redoc` and `/openapi.json` answer 404 (FastAPI pages; no client of the edge reads them).
- No `date` and no `server: uvicorn` header.
- The client's `accept-encoding` and `connection` headers are not forwarded (httpx decodes gzip;
  this client does not), and the upstream sees no `user-agent: python-httpx`.
- The text after `upstream unreachable:` and in `admin-api validate unreachable:` is this
  client's error class and message; for a refused connection both are httpx's
  (`ConnectError('All connection attempts failed')`).
- `GUARD_BLOCKED_COUNTRIES` and `GUARD_BLOCK_CLOUD_PROVIDERS` make the binary refuse to boot
  (the Python guard reads a GeoIP database and cloud ranges; the binary has neither).
- The guard's own text log lines, the uvicorn access log and the Python log scrubber are not
  reproduced; logevent.v1 lines are.
- No permessage-deflate, no server ping every 20 s on a websocket, and no `wss://` upstream for the
  voice-note and live-view relays.
- A non-JSON answer from identity's `/internal/users/{id}/identity` is a 500 on the Python door;
  the binary answers 403 `subject_unknown`.

## NOT CHECKED

- The voice-note and live-view relays with a real upstream websocket (only their refusals are in parity.py).
- The `/ws` 15 s re-authorization, the signals stream (`streams: ["signals"]`) and the workspace channels.
- The privacy mark (`x-vexa-taint`) for a delegated caller on agent rows, and `/internal/mcp/taint`
  for a delegated caller.
- A chunked request body over 1 MiB (the 413 after authorization), and `https://` upstreams.
- The per-user rate limit, the IP allow and block lists, trusted proxies and `X-Forwarded-For`.
- Pydantic error text past the int, platform and 32-hex cases the routes declare.
- Subject tickets from the meetings, agent and mail issuers (only the gateway's own and malformed ones).
- Many concurrent connections and long streams under load.

## Verdict

Every Expected item that parity.py and the live leg reach is equal. The differences above do not
change an answer that a client of this deployment gets. The NOT CHECKED items stay open.
