"""Desktop Flows process: one HTTP API and one worker in one container.

This is only for the local desktop overlay. The normal Compose service layout
stays available for server deployments. The combined process keeps the legacy
API and worker code unchanged. It only gives them one process owner.

``--shadow`` starts the API only. It is safe for parity checks because it does
not claim reactions, emit events, poll mail, or send notifications.
"""
from __future__ import annotations

import argparse
import os
import threading
import time

import uvicorn

from flows_integrations import flows_api
from flows_worker import __main__ as worker


START_TIMEOUT_S = 10.0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Run the local combined Flows process")
    result.add_argument(
        "--shadow",
        action="store_true",
        help="run the HTTP API only; do not start the worker or any side effect",
    )
    return result


def api_server() -> uvicorn.Server:
    """Build the existing API server with its existing environment contract."""
    host = flows_api.bind_host()
    port = int(os.environ.get("VEXA_FLOWS_API_PORT", "8200"))
    config = uvicorn.Config(flows_api.app, host=host, port=port, log_level="warning")
    return uvicorn.Server(config)


def wait_until_started(server: uvicorn.Server) -> None:
    deadline = time.monotonic() + START_TIMEOUT_S
    while not server.started:
        if server.should_exit:
            raise RuntimeError("combined Flows API stopped before it became ready")
        if time.monotonic() >= deadline:
            raise RuntimeError("combined Flows API did not become ready")
        time.sleep(0.05)


def run(shadow: bool) -> int:
    # Fail before the port is open. The FastAPI lifespan repeats this idempotent
    # validation when uvicorn starts, exactly as the legacy API command does.
    flows_api.boot()
    server = api_server()
    api_thread = threading.Thread(target=server.run, name="flows-api", daemon=True)
    api_thread.start()
    wait_until_started(server)
    mode = "shadow" if shadow else "combined"
    print(f"flows-{mode} API ready on {server.config.host}:{server.config.port}", flush=True)

    if shadow:
        while api_thread.is_alive():
            api_thread.join(timeout=0.5)
        return 1

    # The worker remains the only writer. It runs on the main thread so Docker
    # sends its normal stop signal to the process that owns work claims.
    return worker.main()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(shadow=args.shadow)


if __name__ == "__main__":
    raise SystemExit(main())
