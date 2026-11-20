# Parity with the Python crm

## Expected

Written down before the side-by-side runs; the code was written first, from the Python source
(core/crm/src/crm).

- Every route of crm-api answers the same status, JSON body (byte for byte: compact, not
  ASCII-escaped, the same key order) and the headers that carry meaning (`content-type`,
  `x-vexa-privacy`) for the same request: `/health`, `/openapi.json`,
  `/.well-known/mcp-tools.json`, every `/records`, `/objects`, `/proposals`, `/config`,
  `/workspaces`, `/desk/*`, `/card/*`, `/person/*`, `/blocks/*`, `/profile/*` and
  `/internal/*` row, 404, 405, and the 422 of every body model (missing field, wrong type, extra
  field, too long, bad literal, strict bool and int, invalid JSON).
- The middlewares answer in the same order: the workspace-binding 403 (no privacy label), the
  privacy label on every other answer, the `feature_disabled` refusal for `crm`, `desktop`,
  `desktop_cards`, `personal_crm` and `public_profiles`; an unhandled error is a plain-text 500.
- Caller rules give the same 401, 403 and 503 bodies: no token, a token identity refuses, identity
  down, a delegated (agent) caller, an unwatched worker (`human_session_required`), a shared
  conversation (`shared_conversation`), a workspace principal, a cross-org audience, the
  private-data hold (409 `private_sources_to_shared`).
- Every step writes the same database rows in the same tables: records, revisions (`before` and
  `after` snapshots), outbox events, audit rows (op, outcome, principal, on behalf of, workspace),
  change proposals, match identifiers, relationships, bindings, rosters, card layouts, desk, card
  members, card nonces, member settings, profiles. Generated ids (uuid4) and times are normalised;
  uuid5 ids (idempotent create, the sign-in Person) are equal.
- A refused or failed step writes nothing but its audit row, as the Python does (one transaction).
- The outbox posts the same `/events` request to flows (path, `x-flows-publisher-key`, body:
  `event_type`, `source_event_id`, `refs`, the sealed `envelope`) and marks the same rows
  delivered on 202 only. The Ed25519 seal over the same envelope, fact and time is the same
  bytes (`sig` included).
- Start-up refuses the same way: the config.v1 preflight, a superuser database role, a schema
  version that is not 10, a missing or placeholder seal key while the outbox is on.
- The Python code does not change, so the Python suite stays as it is.

A result that differs from one of these is a finding, not a test to change.

## Actual (2026-11-20, Apple M3, macOS, PostgreSQL 17.11 as a host process)

### parity.py — the same requests to both services, on the same database

`parity.py` gives each profile a fresh database (a template made by `python -m crm.migrate init`
and `python -m crm.fact_keys keygen`), starts the Python crm (`native_launch.py crm`, the
deployed pydantic 2.14.0, FastAPI 0.143.0, SQLAlchemy 2.0.57) and then the binary with the same
environment, sends the same steps, and compares each answer (status, `content-type`,
`x-vexa-privacy`, the exact body text), the row count of every table after each step, every
row at the end, the `/events` requests the fake flows received (path, headers, body), the
WARNING/ERROR log lines and the requests to identity and agent-api.

| Profile (`VEXA_FEATURES`) | Steps | Result |
|---|---|---|
| core (`all`) | 132 | the same; 218 rows, 18 outbox events |
| off (``) | 7 | the same |
| crm-only (`crm`) | 5 | the same; 1 event |
| profiles (`all,public_profiles`) | 5 | the same; 2 events |
| personal (`crm,personal_crm,desktop`) | 4 | the same |
| boot refusals | 7 | the same exit status and message (superuser role, no org, no secret, no or placeholder publish key, no seal key, wrong password) |

`PARITY OK`: 153/153 steps, 7/7 refusals. The steps reach all 43 routes of crm-api.

- uuid4 ids are numbered in order of first appearance in the answers; ids that no answer names
  (outbox and audit row ids) become one placeholder, so their order is not compared. Times,
  nonces, content hashes, the seal's `sig`, `iat`, `exp` and a published profile's random
  handle are placeholders.
- The seal bytes are compared in `cargo test` (`fact_envelope::seal_equals_python_vector`): the
  same key, envelope, fact and time give the same `sig`.
- The 422 text: `validate_cases.json` (370 cases, the smallest of each path, status and first
  error type) is in `cargo test`; the full set of 1381 cases from `gen_openapi.py` also passed.

### Tests

- `cargo test`: vexa-crm 22, vexa-native-kit (`--features py,pg,tls`, with `VEXA_TEST_PG_URL`)
  22, vexa-mcp 11, vexa-gateway 14, vexa-credential-broker 33, vexa-daemon 32: all passed.
- The parity checks of the other ports after the kit change: mcp `PARITY OK: 204 steps`, gateway
  75/75 steps the same, broker `PARITY OK`.
- The Python suite (`core/crm`, its own venv): 507 passed, 13 skipped. The Python code did not
  change.

### Live leg (vexa-daemon serve, `infra,services`, own `VEXA_APP_SUPPORT_DIR`)

`VEXA_FEATURES=all,personal_crm,public_profiles` and `VEXA_FLOWS_DEFS_EXTRA=flows_defs.crm` (the CRM
flow pack; without it flows-api answers 400 `no_flow_reacts_to: crm.record.changed` to the Python
outbox and to this one alike). Through the native gateway on 127.0.0.1:23056 with a `bot,tx` key
minted by admin-api:

| Step | Native crm | `VEXA_NATIVE_PY_CRM=1` |
|---|---|---|
| `/crm/card/list`, `create`, `read`, `update` | 200 each; revision 1, then 2 with `Next` | 200 each, the same shapes |
| outbox | both `crm.record.changed` rows delivered: flows-api verified the seal and answered 202 | both rows delivered |
| `/mcp` initialize, tools/list | session, 171 tools with `card_*`, `crm_*`, `desktop_*` | 171 tools |
| `/mcp` tools/call `card_list` | the card just made | the card just made |

### RSS

| Run | Python | Rust |
|---|---|---|
| parity.py, service alone (5 profiles) | 81–93 MB | 8.1–11.1 MB |
| live stack: core group with crm / core group without crm + native crm | 90.4 MB | 86.4 MB + 9.4 MB |

## Differs (known, accepted)

- A start-up refusal prints `ERROR:crm.api:<message>` where the Python prints a traceback that ends
  in `<Exception>: <message>`; the message and the exit status (1, or 3 for the outbox's lifespan
  refusals) are the same. The config.v1 preflight prints the same traceback text.
- No `date` and no `server: uvicorn` header.
- One thread serves each connection (the Python runs one event loop with a thread pool); the
  database pool has the same size (3, no overflow).

## NOT CHECKED

- The Python suite against the binary: its tests build `create_app` in process over a SQLite or
  in-memory store and read FastAPI objects, so they cannot drive an HTTP binary.
- Two delivery loops on one database (`FOR UPDATE SKIP LOCKED`), many concurrent connections,
  and the wait when all 3 pooled connections are busy.
- The hourly audit purge (`retention.rs`) with rows past their retention.
- Desk limits read from a real `_global/POLICIES.md` (parity's agent-api answers 404, so the
  defaults apply).
- An identity or agent-api that is slow or answers non-JSON; `https://` upstreams; PostgreSQL
  over TLS or a non-loopback host.
- The `crm.migrate` and `crm.fact_keys` commands: they stay Python (the daemon jobs run them).

## Verdict

Every Expected item that parity.py, cargo test and the live leg reach is the same as the Python
crm. The items above are not checked.
