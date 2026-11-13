# Vexa Mac shell

`vexa-mac` is the first native macOS shell for a local Vexa deployment.

It does not replace the current Vexa UI. It checks the local terminal and
gateway, then opens the current terminal in the default browser. This keeps
all current features while the native daemon work is in progress.

## Run during development

```sh
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- status
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- open
```

The default terminal URL is `http://127.0.0.1:13000/`. The default gateway
health URL is `http://127.0.0.1:18056/health`.

Use `VEXA_TERMINAL_URL` or `VEXA_GATEWAY_URL` for another local port.

## Build a local app bundle

```sh
bash apps/vexa-mac/scripts/build-macos-app.sh
open apps/vexa-mac/target/Vexa.app
```

The bundle contains a native macOS launcher. It opens Vexa only after the
local terminal is ready. The next migration step will make this bundle start
the native Vexa daemon as well.

## Run the static Mac shell

```sh
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- serve
```

Open `http://127.0.0.1:13001/`. The shell shows local service status and has a
link to the unchanged Vexa terminal. Its route replacement rules are in
[MIGRATION.md](MIGRATION.md).

## Scope

This module does not change Docker Compose, data storage, the browser bot, or
the current Next.js terminal. It is safe to add while the existing stack
remains the supported local path.
