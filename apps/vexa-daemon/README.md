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
| `services` | key jobs, schema jobs, admin-api, credential-broker, runtime (`process` backend), model-proxy, meeting-api, agent-api, crm (with outbox), gateway (with service door), flows (API and worker), mcp | the same services, with the desktop Flows and CRM overlays |

By default related services share one Python process
(`python/native_group.py`): the **edge** group runs admin-api, meeting-api,
gateway with its service door, and mcp; the **agent** group runs agent-api and
model-proxy. mcp starts last in the edge process, after agent-api, flows and
crm answer `/health`, because it assembles their tools when it is built. The
runtime (it forks children) and the credential-broker (it sets a process-wide
umask) keep their own processes. A group gets the union of its members'
settings; two members that need different values for one setting stop the
start with an error. The edge environment is `python/groups/edge`, made by
`python/merge_groups.py` from the members' requirements and limited to the
highest version each member's own lock uses. `VEXA_NATIVE_SPLIT=1` runs one
process per service.

In a group, every member can read the group's settings. For example gateway
and mcp code can read the database password that admin-api and meeting-api
use. This is acceptable for a single-user local app; the Compose layout keeps
the per-service separation.

Each Python service runs from `runtime/apps/<name>`, a symlink tree with the
same layout as its image (`/app`), built from the `COPY` lines of its
Dockerfile. Its environment is `runtime/venvs/<name>`, made by `uv sync`
with the Dockerfile's arguments. A source change needs only a restart.
`python/native_launch.py` runs crm-api and model-proxy on loopback and a
given port; their image entry points use fixed ports on all interfaces.

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

Measured on 2026-11-13 (Apple M3, `scripts/desktop-memory.py`):

| Layout | Host footprint |
|---|---|
| Compose stack in Docker Desktop | 8778 MiB |
| `infra` + daemon | 37.5 MiB |
| `infra,services`, one process per service (`VEXA_NATIVE_SPLIT=1`) | 1018 MiB |
| `infra,services`, process groups (default) | 632 MiB |

Checked through the native gateway: a token minted by admin-api resolves at
`/auth/me`, `/meetings` answers 200, and MCP `tools/list` returns 171 tools
from every domain. The process groups give the same results.
