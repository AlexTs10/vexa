# vexa-credential-broker source

- `main.rs`: the subcommands and the boot checks.
- `server.rs`, `net.rs`: the HTTP server, the probes and the assertion boundary.
- `routes.rs`: the route table and every route handler.
- `broker.rs`: the shared state (connections, owners, audit, OAuth state, refresh).
- `assertion.rs`, `identity.rs`: credential-broker.v1 assertions and gateway-identity.v1.
- `config.rs`: the settings and the config.v1 preflight.
- `metadata.rs`, `store.rs`, `lock.rs`: the SQLite schema, the encrypted secret store (local and OpenBao) and the process lock.
- `models.rs`, `setup.rs`, `policy.rs`: request validation, setup specifications and action policy.
- `google.rs`, `calendar.rs`, `service.rs`, `ssrf.rs`: Google calls, calendar writes, custom services and the outbound address checks.
- `sensor_grants.rs`: sensor grants.
- `tz.rs`, `util.rs`, `obs.rs`, `fail.rs`: time zones, Python-compatible JSON text, log lines and error answers.
