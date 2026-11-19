# vexa-native-kit

Shared building blocks of the native Vexa Mac processes (`vexa-daemon`, `vexa-stt`,
`vexa-credential-broker`, `vexa-mcp`). The default build has no external crates.

- `json`: a JSON value that keeps object key order, a parser, a writer, and the canonical
  (sorted-key) form that Python writes with `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
- `http`: a one-request-per-connection HTTP/1.1 server side and a client for `http://` URLs.
- `sha256`: SHA-256, HMAC-SHA256 and a constant-time compare.
- `ids`: the clock, UTC stamps and random hex ids as the Python services write them.
- `reason`: HTTP reason phrases as uvicorn writes them.
- `binary`: where the daemon finds a native process's binary.

The `py` feature adds two modules over `serde_json` values (the broker and mcp use them):

- `pyjson`: the text `json.dumps` and `repr` write for a JSON value.
- `logevent`: one logevent.v1 line, in the Python `obs.py` key order.

`cargo test` (and `cargo test --features py`) runs the FIPS 180-4 and RFC 4231 vectors and the
JSON, HTTP, id and binary checks.
