# vexa-native-kit

Shared building blocks of the native Vexa Mac processes (`vexa-daemon`, `vexa-stt`,
`vexa-credential-broker`, `vexa-mcp`, `vexa-gateway`, `vexa-crm`). The default build has no external crates.

- `json`: a JSON value that keeps object key order, a parser, a writer, and the canonical
  (sorted-key) form that Python writes with `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
- `http`: a one-request-per-connection HTTP/1.1 server side and a client for `http://` URLs.
- `sha256`: SHA-256, HMAC-SHA256 and a constant-time compare.
- `ids`: the clock, UTC stamps and random hex ids as the Python services write them.
- `reason`: HTTP reason phrases as uvicorn writes them.
- `binary`: where the daemon finds a native process's binary.
- `httpd`: a keep-alive HTTP/1.1 server (Content-Length and chunked bodies, 100-continue, streamed
  answers, the connection handed over for a websocket upgrade).
- `client`: an HTTP/1.1 client with connect, read and write timeouts, request bodies sent whole or
  chunked, and answers read as they arrive; `https://` with the `tls` feature (native-tls).
- `b64`: base64 and canonical base64url.

The `py` feature adds modules over `serde_json` values (the broker, mcp and crm use them):

- `pyjson`: the text `json.dumps` and `repr` write for a JSON value.
- `pyjson_decode`: `json.loads` with Python's error text.
- `pyd`: pydantic's validation (lax coercion) and its error items, as FastAPI answers them in a 422.
- `schema`: jsonschema's Draft 2020-12 validation and its error messages.
- `logevent`: one logevent.v1 line, in the Python `obs.py` key order.

The `pg` feature (crm) adds `pg`: a pool of blocking PostgreSQL clients (the `postgres` crate,
MIT OR Apache-2.0), explicit transactions with savepoints, rows as JSON maps, and the SQLAlchemy URL
forms (`postgresql+pg8000://`).

`cargo test` (and `cargo test --features py,pg,tls`; set `VEXA_TEST_PG_URL` for the PostgreSQL round trip) runs the FIPS 180-4 and RFC 4231 vectors and the
JSON, HTTP, id and binary checks.
