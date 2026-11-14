# vexa-daemon runtime

The Vexa runtime as part of the daemon: the `process` backend of `core/runtime` (`runtime_kernel`)
for one Mac user, on `127.0.0.1:<VEXA_RUNTIME_PORT>`. meeting-api and agent-api call it as they
call the Python runtime.

- `mod.rs`: start, the HTTP listener, the background loops (exit watcher, callback sweep,
  scheduler tick) and the stop of all workloads.
- `api.rs`: the routes, bearer auth, request validation (FastAPI error shapes) and `/health`.
- `kernel.rs`: workload records, the runtime.v1 lifecycle and the process backend.
- `workload_env.rs`: runtime-owned keys, the mount checks and the child environment.
- `callbacks.rs`: RuntimeEvent delivery with the `X-Runtime-Signature` HMAC.
- `scheduler.rs`, `redis.rs`, `clock.rs`: schedule.v1 over Redis, cron and ISO 8601 time.
- `preflight.rs`: the config.v1 boot checks and the `/health` capability rows, read from
  `core/runtime/src/runtime_kernel/config.v1.json`.
