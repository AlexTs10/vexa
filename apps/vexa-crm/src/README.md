# vexa-crm source

- `main.rs`: the boot (config.v1 preflight, the database pool and its migrate check, the outbox and retention threads, the listener).
- `api.rs`, `validate.rs`: every route, the middlewares (binding, privacy label, feature switch), the caller and the audit of each route, the body models' 422 answers.
- `store.rs`, `db.rs`, `schema.rs`, `field_classes.rs`: records, policies and the field view, revisions and the outbox row of each write, the transactions and the pending audit row, the tables' columns.
- `card_ops.rs`, `card_templates.rs`, `card_face.rs`, `layouts.rs`: cards (lifecycle, members, decisions, proposals, faces) and the record card layout.
- `desk.rs`, `member_settings.rs`, `blocks.rs`: the desk, the person's workspace settings, the page blocks.
- `persons.rs`, `person_profiles.rs`, `profiles.rs`: one person with many addresses, the claimed profile, the links to published profiles.
- `outbox.rs`, `fact_envelope.rs`, `fact_keys.rs`: event.v2 delivery to flows and the Ed25519 fact seal.
- `caller.rs`, `orgs.rs`, `features.rs`, `privacy.rs`, `policies.rs`, `net.rs`: identity, the org that serves a caller, `VEXA_FEATURES`, the private-data hold, the desk limits, outbound HTTP.
- `migrate.rs`, `bootstrap.rs`, `preflight.rs`, `retention.rs`: the start-up schema check, the personal org, the config.v1 preflight, the audit purge.
- `markdown_links.rs`, `val.rs`, `err.rs`: CRM links in Markdown, Python's view of JSON values, the exception classes.
- `openapi.json`, `models.json`, `pages.json`, `mcp.tools.v1.json`, `validate_cases.json`: what `gen_openapi.py` writes from the Python app.
