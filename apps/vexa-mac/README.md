# Vexa Mac shell

`vexa-mac` is the first native macOS shell for a local Vexa deployment.

It starts the native Vexa daemon, then opens the local Mac shell. The shell
keeps the current Vexa terminal unchanged. This keeps all current features
while native routes replace it in small steps.

## Run during development

```sh
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- status
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- start
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

The bundle contains the Mac launcher and `vexa-daemon`. It starts the daemon
before it opens the local shell. It opens the current Vexa terminal only after
the terminal is ready.

## Run the daemon in the foreground

```sh
cargo run --manifest-path apps/vexa-mac/Cargo.toml -- daemon
```

Open `http://127.0.0.1:13001/`. The daemon now owns the static Mac shell and
the local health-status routes. The shell has a link to the unchanged Vexa
terminal. Its route replacement rules are in [MIGRATION.md](MIGRATION.md).

## Scope

This module does not change Docker Compose, data storage, the browser bot, or
the current Next.js terminal. It is safe to add while the existing stack
remains the supported local path.
