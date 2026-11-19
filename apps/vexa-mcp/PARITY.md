# Parity with the Python mcp service

## Expected (written before the port)

- `POST /mcp` gives the same JSON-RPC answer, HTTP status and headers
  (`content-type`, `mcp-session-id`, `x-trace-id`, `allow`) as the Python
  service for: `initialize` (each protocol version, an unknown one), a
  notification (202), `ping`, `tools/list`, `tools/call`, `prompts/list`,
  `prompts/get`, an unknown method, a request with no session, an unknown or
  deleted session, a parse error, a wrong `content-type` or `accept`, a bad
  `mcp-protocol-version`, `DELETE /mcp` and `GET /mcp` (SSE).
- `tools/list` names the same tools in the same order, each with the same
  description and the same `inputSchema` (JSON-equal), for the same
  `VEXA_FEATURES`, `VEXA_MCP_TOOLS_*` and deployed domains — built-in and
  assembled tools, the late domains included.
- A tool call sends the same upstream requests (method, path, query, the
  headers that carry meaning, JSON body) and gives the same result text and
  `isError`: success, upstream refusal (4xx/5xx, rendered), input validation
  error (jsonschema message), FastAPI validation error (422 detail), unknown or
  hidden tool, stringified arguments, standing notices, taint report.
- The REST routes (`/health`, the 18 built-in tool routes, 404, 405, 401, the
  unknown-argument 422) answer the same status and body.
- The same environment boots or refuses to boot (exit code not 0) in the same
  cases: a configured domain that never answers, a manifest error, an
  `auth: admin` tool without its key.
- The gateway's `/mcp` route (scopes `bot`, `tx`) gives 403
  `Insufficient scope` to a `browser`-only key; this is the gateway's rule and
  does not change.
- The Python test suite stays green (the Python code does not change).

A result that differs from one of these is a finding, not a test to change.

## Actual (2026-11-19, Apple M3, macOS)

### parity.py — the same requests to both services

`parity.py` starts the Python service (uvicorn) and the binary with the same
environment and one fake upstream (gateway, every domain, the ticket sink),
sends each step to both, and compares status, headers that carry meaning, the
JSON body (or text), and every upstream request each side made. Session ids,
minted trace ids and times are normalised; nothing else is.

| Profile | What it covers | Result |
|---|---|---|
| `all` | `VEXA_FEATURES=all`, every domain: transport (initialize per version, notification 202, ping, no/unknown/deleted session, parse error, bad content-type/accept/protocol version, GET SSE + 409, DELETE, PUT 405, query on /mcp), tools/list, prompts/list + get, every built-in tool, assembled tools (path, query, body, admin, taint, withheld), refusals, validation errors, stringified arguments, notices, visibility, the REST routes (health, 404, 405, 401, 422, 307) | equal |
| `release` | the release default `VEXA_FEATURES` | equal |
| `github-sink` | `report_issue` with `VEXA_TICKET_SINK_FORMAT=github` | equal |
| `late` | flows down at boot, then up: its tools join tools/list | equal |
| boot | 4 environments the Python service refuses (identity silent, admin tool without its key, placeholder admin key, mounted manifest without its URL) | both refuse |

`PARITY OK: 204 steps`, and all 4 boot refusals agree.

Two normalisations are for Python behaviour that changes between runs of the
Python service itself: the order of the `allow` header of a 405 (Starlette joins
a Python set), and the `type` fastapi-mcp gives a union argument with two
non-null branch types (`next(iter(set))`). parity.py compares those as sets.

### The Python test suite against the binary

`pytest_rust.py` replaces `create_app` with one that starts the binary and
relays every upstream hop to the test's own `httpx` transport.

| Python suite | Passed | Failed | Why it fails |
|---|---|---|---|
| on the Python service | 650 | 0 | — |
| on the binary (`-p pytest_rust`), 42 files | 581 | 55 + 11 errors | 61 read `app.state` / `app.openapi()` (the FastAPI objects); 6 read the Python log capture (`caplog`, `obs.capture`). No failure is an answer that differs. |
| `test_mcp_sessioned_sse.py` | NOT CHECKED with the binary | — | it drives raw ASGI with a stream that does not end; the relay cannot. GET SSE is in parity.py. |

### cargo test

`cargo test`: 14 passed (vexa-mcp), 33 passed (vexa-credential-broker), 32 passed
(vexa-daemon), 10 + 13 passed (vexa-native-kit, default and `py`).

### Live leg (vexa-daemon serve, `infra,services`, own `VEXA_APP_SUPPORT_DIR`)

Through the gateway `/mcp` with a key minted by admin-api:

| Step | Native mcp | `VEXA_NATIVE_PY_MCP=1` |
|---|---|---|
| initialize | 200, session id, 2025-03-26 | same |
| notifications/initialized | 202 | same |
| tools/list | 200, 135 tools | 200, 135 tools |
| tools/call list_meetings | 200, `{"meetings": []}` | same |
| tools/call parse_meeting_link | 200, google_meet abc-defg-hij | same |
| browser-only key | 403 `Insufficient scope for this endpoint` | same |
| DELETE /mcp | 200 | same |

### Memory (RSS)

| | Python | Rust |
|---|---|---|
| parity.py, service alone (4 profiles) | 61–80 MB | 9–13 MB |
| boot to listening (parity.py) | 0.41–0.71 s | 0.05–0.07 s |
| live stack: core group with mcp / core group + native mcp | 195 MB | 110 MB + 11.5 MB |

## Differs (known, accepted)

- `/docs`, `/redoc` and `/openapi.json` are not served (FastAPI pages; no
  client of the edge reads them).
- The settings are read once at boot. The Python service reads
  `VEXA_TICKET_SINK_*` and `VEXA_JITSI_HOSTS` on each call; a running process's
  environment does not change, so a deployment sees no difference.
- A log line's `ts` always has 6 fraction digits.
- The text after "Request failed:" and "Ticket sink unreachable:" (the network
  error's own words: httpx vs this client).
- A tool's unknown-name warning for `VEXA_MCP_TOOLS_*` is printed on stderr, not
  through Python logging.

## NOT CHECKED

- Pydantic error text beyond the cases parity.py sends (missing, model type,
  literal, the string/int/bool coercions, the bounds and patterns the tools
  declare).
- NaN, Infinity and integers past 64 bits in tool arguments.
- An https ticket sink against a real TLS server (the TLS code is
  native-tls; parity used http).
- More than one concurrent SSE stream under load, and the 15 s ping over a long
  session (parity checks the first bytes and the 409).
- `VEXA_MCP_MANIFEST_DIR` with files other than the repository's manifests.

## Verdict

Every Expected item that parity.py, the Python suite and the live leg reach is
equal. The differences above do not change an answer a client gets in a
deployment. The NOT CHECKED items stay open.
