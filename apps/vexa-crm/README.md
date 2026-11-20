# vexa-crm

`vexa-crm` is the Vexa CRM (`core/crm`, contract `crm.v1`) as a native process: crm-api with its
outbox loop and the hourly audit purge in one process. It keeps the Python service's contracts: every
route, body model and 422, the answers byte for byte, the rows it writes in the same transactions,
the audit (H9), the event.v2 outbox with its Ed25519 fact seal, and the MCP tool manifest
(`/.well-known/mcp-tools.json`) and OpenAPI that the MCP edge assembles its `crm_*`, `desktop_*`
and `card_*` tools from.

```sh
vexa-crm      # crm-api on 127.0.0.1:VEXA_CRM_PORT (default 8300)
```

The settings are the Python service's variables: the config.v1 preflight (`config.v1.json`, embedded
at build time), `CRM_DATABASE_URL` (the runtime role; a superuser or a schema version that is not
10 refuses to start), `ADMIN_API_URL` and `INTERNAL_API_SECRET` (identity), `CRM_ORG_ID`,
`VEXA_FEATURES`, `CRM_AGENT_API_URL` (the desk limits in `_global/POLICIES.md`), and for the outbox
`VEXA_CRM_OUTBOX_ENABLED`, `FLOWS_API_URL`, `FLOWS_PUBLISH_KEY` and `VEXA_FACT_SEAL_KEY_FILE`.
The schema, its migrations and the seal key stay with the Python jobs (`python -m crm.migrate init`,
`python -m crm.fact_keys keygen`); this process never creates or alters a table. One thread serves
each connection; a pool holds the database connections.

`vexa-daemon` runs it in the `services` group, after the core process group.
`VEXA_NATIVE_PY_CRM=1` runs the Python crm in the core group again, with the same environment.

`PARITY.md` lists what is the same as the Python service, what differs and what is not checked.
The check that runs against both, on a native PostgreSQL (never a container):

```sh
cargo build --release --manifest-path apps/vexa-crm/Cargo.toml
cd core/crm
# the same requests to the Python and the Rust crm: answers, rows, outbox events, log lines
.venv/bin/python ../../apps/vexa-crm/parity.py
```

`gen_openapi.py` writes the OpenAPI, the body models and the 422 cases from the Python app into `src/`.
