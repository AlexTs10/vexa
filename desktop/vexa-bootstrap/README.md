# Vexa local bootstrap

`vexa-bootstrap` is the first native part of the macOS migration.

It creates the local Vexa folders and checks the services that implement the
current product. It does not start Docker, change a service, move user data,
or remove a product feature.

## Commands

```zsh
cargo run --manifest-path desktop/vexa-bootstrap/Cargo.toml -- init
cargo run --manifest-path desktop/vexa-bootstrap/Cargo.toml -- status
```

`init` creates these folders by default:

```text
~/Library/Application Support/Vexa/
  config/
  state/
  logs/
  runtime/
  recordings/
```

Set `VEXA_DESKTOP_HOME` or pass `--data-dir PATH` to use another location.

`status` checks the Terminal, gateway, meetings, agents, flows, MCP, runtime,
and administration HTTP services. It exits with code `1` when a required
service is not ready.

## Migration limit

This command does not replace the current Compose initialization jobs yet.
It defines the native local state boundary first. Later migration work will
move each initialization action into this module with an equivalent behavior
check.
