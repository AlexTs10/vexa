# Vexa Automation Engine

`vexa-automation` is the first safe step toward one local automation engine.
It is a Rust control surface. It does not process work yet.

The current application keeps all features in the existing services:

| Legacy service | Current ownership | Required parity before replacement |
|---|---|---|
| `flows-api` | Authenticated flow and event HTTP API | Every route, caller scope, and response contract |
| `flows-worker` | Reaction claims, steps, schedules, receipts, retention | Transaction claim rules, retries, schedule catch-up, and all flow packs |
| `flows-mailbox` | IMAP or Graph input and mail fact admission | Provider read rules, rate limits, quarantine, and ticket signing |
| `crm-outbox` | CRM change publication to flows | Signed fact envelope, ordering, retry, and idempotency |

## Commands

```sh
cargo run --manifest-path apps/vexa-automation/Cargo.toml -- status
cargo run --manifest-path apps/vexa-automation/Cargo.toml -- contract
cargo run --manifest-path apps/vexa-automation/Cargo.toml -- check-env
```

`check-env` prints only `set` or `unset`. It never prints a secret.

`start` always refuses. This prevents two workers from claiming the same work.

## Migration order

1. Run this binary in shadow mode beside the current services.
2. Add read-only PostgreSQL checks for reaction, receipt, schedule, and outbox state.
3. Replay production-like facts into both engines and compare results.
4. Move one non-mail flow pack at a time.
5. Move the worker claim loop only after its transaction and retry parity pass.
6. Move mail intake and CRM publication last. They hold external side effects.

The engine must keep the current gateway service-door rules and separate key scopes.
It must not reuse the admin key or expose a secret to a broader process.
