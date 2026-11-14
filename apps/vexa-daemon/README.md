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
`none` runs only the shell). The default is `infra,services,ui`.

| Group | Processes | Compose equivalent |
|---|---|---|
| `infra` | PostgreSQL 17, Valkey/Redis 7.2, versitygw, storage-init, vexa-stt | `postgres`, `redis`, `storage`, `storage-init`, the `transcription` stack |
| `ui` | the Next.js terminal (`node server.mjs`, built with `pnpm --filter @vexa/terminal run build`) on 127.0.0.1:23000 | `terminal` |
| `services` | key jobs, schema jobs, admin-api, credential-broker, runtime (`process` backend), model-proxy, meeting-api, agent-api, crm (with outbox), gateway (with service door), flows (API and worker), mcp | the same services, with the desktop Flows and CRM overlays |

By default the Python services share two processes
(`python/native_group.py`):

- **core**: admin-api, meeting-api, gateway with its service door, mcp,
  credential-broker, crm (with its outbox) and flows (API, with the worker loop
  on its own thread). mcp starts last, after agent-api, flows and crm answer
  `/health`, because it assembles their tools when it is built.
- **agent**: agent-api and model-proxy.

agent-api is not in core: it needs other values than meeting-api for
`VEXA_FLOWS_API_URL` and `VEXA_SUBJECT_TICKET_KEY_FILE`, and one process has one
environment. The runtime keeps its own process (it forks the bots and
workers). A group gets the union of its members' settings; two members that
need different values for one setting stop the start with an error. The core
environment is `python/groups/core`, made by `python/merge_groups.py` from the
members' requirements and limited to the highest version each member's own
lock uses. `VEXA_NATIVE_SPLIT=1` runs one process per service.

In a group, every member can read the group's settings. For example gateway
and mcp code can read the database password that admin-api and meeting-api
use. This is acceptable for a single-user local app; the Compose layout keeps
the per-service separation. credential-broker sets umask 077, so every file
the core process writes is private to the Mac user. `vexa-daemon specs` prints
each core member's own settings; `python/group_env_check.py` reads that output
and lists each setting that one member sets and another member's code names,
for review.

### Meeting bots and agent workers

The runtime uses its `process` backend: each meeting bot and each agent
worker is a normal host process, not a container.

- `bin/vexa-bot-launch` runs the bot (`core/meetings/services/bot/dist`) with
  Node and the Playwright Chromium in `runtime/ms-playwright`. Each bot gets a
  private folder for `HOME`, the browser profile, the join screenshots
  (`VEXA_SCREENSHOT_DIR`) and the signal tapes; the folder is removed when the
  bot ends. Audio capture runs in the page, so no X display or PulseAudio is
  needed. Speaking in a meeting (TTS) needs PulseAudio and is not available.
  The browser window is visible on the Mac desktop.
- `bin/vexa-agent-worker` runs `python -m worker` from the agent-worker image
  layout, with the claude-code and codex versions that its Dockerfile pins
  (installed into `runtime/node-tools`). Each worker gets a private `HOME`.

A host process runs as the Mac user. The container isolation of Compose
(dropped capabilities, separate networks, a separate tools user, seccomp)
does not exist here; Chromium keeps its own macOS sandbox.

Prepare the bot once from the checkout:

```sh
pnpm install --frozen-lockfile
pnpm --filter "@vexa/capture-codec" --filter "@vexa/gmeet-capture" \
  --filter "@vexa/mixed-capture-core" --filter "@vexa/record-chunker" \
  --filter "@vexa/jitsi-capture" --filter "@vexa/teams-capture" \
  --filter "@vexa/zoom-capture" run build
pnpm --filter "@vexa/bot..." run build
R="$HOME/Library/Application Support/Vexa/runtime"
(cd core/meetings/modules/remote-browser && \
  PLAYWRIGHT_BROWSERS_PATH="$R/ms-playwright" pnpm exec playwright install chromium)
VEXA_HF_CACHE="$R/hf-cache" node core/meetings/services/bot/warm-hf-cache.mjs
```

Checked on 2026-11-13: a bot sent to a Google Meet code that does not exist
ran as launcher → node → Chromium, reported `requested` → `joining` →
`failed` (`join_failure`), uploaded its join screenshot to the native storage
through meeting-api, and left no process or folder.

Each Python service runs from `runtime/apps/<name>`, a symlink tree with the
same layout as its image (`/app`), built from the `COPY` lines of its
Dockerfile. Its environment is `runtime/venvs/<name>`, made by `uv sync`
with the Dockerfile's arguments. A source change needs only a restart.
`python/native_launch.py` runs crm-api and model-proxy on loopback and a
given port when each service runs alone (`VEXA_NATIVE_SPLIT=1`); their image
entry points use fixed ports on all interfaces.

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

Measured on 2026-11-13 and 2026-11-14 (Apple M3, `scripts/desktop-memory.py`):

| Layout | Host footprint |
|---|---|
| Compose stack in Docker Desktop | 8778 MiB |
| `infra` + daemon | 37.5 MiB |
| `infra,services`, one process per service (`VEXA_NATIVE_SPLIT=1`) | 1018 MiB |
| `infra,services`, process groups (default), transcription model unloaded | 611.5 MiB |
| the same, transcription model loaded (`whisper-server`, 488 MiB) | 1101.5 MiB |
| `infra,services,ui` (adds the terminal, 136 MiB), model loaded | 1225.6 MiB |
| the same, with the core group (2026-11-14) | 1088.8 MiB |

A new instance shows the terminal's claim screen. The one-time admin claim
code is in `logs/core.log` (`grep -A4 'ADMIN CLAIM CODE'`).

Checked through the native gateway: a token minted by admin-api resolves at
`/auth/me`, `/meetings` answers 200, and MCP `tools/list` returns 171 tools
from every domain. The process groups give the same results.
