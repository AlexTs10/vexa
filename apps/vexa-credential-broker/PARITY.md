# Parity with the Python credential broker

## Expected (written before the port)

- Each route of `credential_broker.main` answers the same status, the same JSON
  body (keys and order) and the same headers (`cache-control: no-store`,
  `x-content-type-options: nosniff`, `x-trace-id`) for the same request.
- A request with no assertion, a bad assertion, a reused nonce or a wrong role
  gets 401 `Product identity refused`; `/health` and `/ready` need none.
- A body that does not validate gets 422 `Invalid request fields` before the
  route checks the identity.
- The same environment boots or refuses with the same sentence (config.v1).
- A state directory written by Python is read by Rust, and the audit trail of
  the same request sequence is the same row for row.
- `pytest` of the Python service stays green (the Python code does not change).

A result that differs from one of these is a finding, not a test to change.

## Actual (2026-11-19)

- `parity.py`: 148 steps against both brokers with the same keys: `PARITY OK`.
  Bodies are compared after ids, times, OAuth state and setup tokens are
  replaced by placeholders. Audit trail: 105 rows on each side, equal. Rust
  boots over a copy of the Python state and lists the same connections, Git
  names and grants.
- `cargo test`: 33 passed (assertion and identity goldens, all request
  goldens of the contract, config refusals, time zones, setup errors, JSON text).
- Python `pytest`: 501 passed.
- Live, `vexa-daemon serve` with `infra,services` over a new state directory:
  `/health` and `/ready` 200; agent without assertion 401; agent, human and
  `/api/sensor-grants` lists 200; the git, bots and sensors internal routes and
  `/api/setup` refuse an empty body with 422. The same requests with
  `VEXA_NATIVE_PY_CREDENTIAL_BROKER=1` (Python broker in the core group) gave
  the same answers. RSS: native broker 6.4 MiB + core group 66.9 MiB; Python
  broker in the core group 86.7 MiB.

| Area | Result |
|---|---|
| `/health`, `/ready`, 404, 405, 401 refusal, 422 order, error headers | matched |
| connections: prepare, setup, save, list, get, delete, successor (410) | matched |
| OAuth: Google authorize, custom OAuth application, authorize, callback refusals | matched |
| Git names (`owned_by`), bot accounts, mail secrets, signals keys (CLI) | matched |
| sensor grants: issue, view, status, adopt | matched |
| action policy refusals (409), audit rows | matched |
| custom service execute: SSRF refusal, redaction, size limit, one retry | matched (api.github.com, dummy key) |
| Google calls with a dummy token: fault mapping | matched |
| Python state read by Rust | matched |
| Rust state read by Python | NOT CHECKED |
| MIME bytes of Gmail drafts (header folding, transfer-encoding choice) | differs possibly; NOT CHECKED byte for byte |
| HTML to text of mail bodies | differs for entities outside a short table |
| floats with an exponent in JSON text | NOT CHECKED |
| trailing-slash redirects | NOT CHECKED |
| pydantic length errors when list items also fail | NOT CHECKED |
| OpenBao store | NOT CHECKED live |
| successful Google reads, drafts, calendar writes | NOT CHECKED (no real account) |
| time zones at a DST fold | NOT CHECKED |
| calls from agent-api, the terminal and flows sensors through their own clients | NOT CHECKED live (the same signed requests were sent by a script) |
| `import_git_legacy` | NOT PORTED (one-time import of an old layout) |
