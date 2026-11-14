# vexa-daemon source

- `main.rs`: commands, the local HTTP shell and `/status`.
- `supervisor.rs`: starts, watches, restarts and stops host processes.
- `config.rs`: `config/native.env` (ports, minted secrets, operator settings).
- `stack.rs`: the folders, host tools and the `infra` group (PostgreSQL, Redis, storage, stt).
- `pyapp.rs`: Python services in their image layout (symlink trees from Dockerfile `COPY` lines) and locked environments.
- `services.rs`: the application services, process groups, key and schema jobs, and the terminal.
