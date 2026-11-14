# vexa-native-kit

Shared building blocks of the native Vexa Mac processes (`vexa-daemon`, `vexa-stt`). It has no
external crates.

- `json`: a JSON value that keeps object key order, a parser, a writer, and the canonical
  (sorted-key) form that Python writes with `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
- `http`: a one-request-per-connection HTTP/1.1 server side and a client for `http://` URLs.
- `sha256`: SHA-256, HMAC-SHA256 and a constant-time compare.

`cargo test` runs the FIPS 180-4 and RFC 4231 vectors and the JSON and HTTP checks.
