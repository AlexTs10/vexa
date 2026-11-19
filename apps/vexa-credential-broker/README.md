# vexa-credential-broker

`vexa-credential-broker` is the Connections credential broker
(`core/agent/services/credential-broker`, credential-broker.v1) as a native
process. It keeps the Python service's contract: the routes, the JSON shapes,
the status codes, the auth rules (the credential-broker.v1 role assertion and
the gateway-identity.v1 signature), the config.v1 boot checks, and the state
directory (`metadata.sqlite`, `secrets.sqlite`, `state-hmac.key`). It reads a
state directory that the Python broker wrote, and the Python broker reads its
state.

```sh
vexa-credential-broker [serve] [--port N]       # default port: VEXA_CREDENTIAL_BROKER_PORT, else 23110
vexa-credential-broker mail-secret put|delete <name>   # the value on stdin
vexa-credential-broker signals-key put|delete <name>   # the value on stdin
```

It listens on 127.0.0.1 only, one thread per connection, and sets umask 077.
The settings are the Python service's `VEXA_CONNECTIONS_*` variables
(`config.v1.json` is compiled in from the Python tree).

`vexa-daemon` runs it in the `services` group. `VEXA_NATIVE_PY_CREDENTIAL_BROKER=1`
runs the Python broker in the core process group again, with the same
environment and state.

`PARITY.md` lists what is the same as the Python service and what is not
checked. `parity.py` runs both brokers side by side and compares each answer:

```sh
cargo build --release --manifest-path apps/vexa-credential-broker/Cargo.toml
cd core/agent/services/credential-broker
uv run --frozen python ../../../../apps/vexa-credential-broker/parity.py
```
