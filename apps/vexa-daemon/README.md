# Vexa daemon

`vexa-daemon` is the local control plane for the Mac app. It now owns the Mac
shell and its local health-status routes. The current Vexa services keep their
existing behavior.

It owns the future local folders below `~/Library/Application Support/Vexa`:

- `config`
- `data`
- `logs`
- `recordings`
- `state`

Commands:

```sh
cargo run --manifest-path apps/vexa-daemon/Cargo.toml -- init
cargo run --manifest-path apps/vexa-daemon/Cargo.toml -- store-init
cargo run --manifest-path apps/vexa-daemon/Cargo.toml -- status
cargo run --manifest-path apps/vexa-daemon/Cargo.toml -- serve
```

`serve` exposes local-only endpoints on `127.0.0.1:13001`:

- `GET /health`
- `GET /status`
- `GET /` (Mac shell)
- `GET /app.css`

The moved shell group has parity checks for its HTTP response, routes, and
assets. Later changes will move one Vexa service group at a time behind this
daemon. This order keeps existing features working during the migration.

`store-init` creates an independent local SQLite database at
`~/Library/Application Support/Vexa/data/vexa.sqlite3`. It currently owns only
local settings and migration state. It does not copy, delete, or change the
existing Postgres data. Future migrations can move one data group at a time and
keep a reversible export path.

## Native stack

`serve` also runs the native Vexa stack as host processes, with no Docker.
`VEXA_NATIVE_GROUPS` selects the groups (comma-separated, in start order;
`none` runs only the shell). The default is `infra`.

| Group | Processes | Compose equivalent |
|---|---|---|
| `infra` | PostgreSQL 17, Valkey/Redis 7.2, versitygw, storage-init | `postgres`, `redis`, `storage`, `storage-init` |

The daemon starts each process, waits until it is ready, restarts it after a
crash (backoff 1–32 s), and stops all processes in reverse order on SIGINT or
SIGTERM. Each process gets only `PATH`, `HOME`, the locale, `TMPDIR`, `USER`
and its own settings. Logs go to `logs/<name>.log`.

Settings and secrets are in `config/native.env` (mode 0600). The daemon
creates it and mints each missing secret. Native ports use the 23xxx range,
so the native stack can run beside the Compose stack.

Host tools: PostgreSQL 17 (`brew install postgresql@17`), `valkey-server` or a
BSD-licensed `redis-server` 7.2, `versitygw`, and `uv`. Override a path with
`VEXA_PG_BIN_DIR`, `VEXA_REDIS_SERVER`, `VEXA_VERSITYGW` or `VEXA_UV`.
`VEXA_SOURCE_DIR` points at the Vexa checkout.

Measured on 2026-11-13 (Apple M3): the `infra` group plus the daemon use
37.5 MiB of physical memory.
