"""Run several Vexa services in one Python process (a native process group).

Each service keeps its own app builder, routes, lifespan and port. The
services share one interpreter and one event loop, so their common libraries
load once. This lowers the memory of the native Mac stack.

    python native_group.py edge    # admin-api, meeting-api, gateway (+ door), mcp
    python native_group.py agent   # agent-api, model-proxy

Ports come from ``VEXA_<SERVICE>_PORT``. All listeners use 127.0.0.1.
mcp asks every domain for its tools when it is built, so the edge group
builds it last, after each URL in ``VEXA_NATIVE_MCP_WAIT_URLS`` answers 200.

The process stops all listeners on SIGINT or SIGTERM, and exits with code 1
when one listener stops by itself, so the daemon restarts the whole group.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
import urllib.request
from typing import Any, Callable, Coroutine

import uvicorn

log = logging.getLogger("vexa.native_group")
HOST = "127.0.0.1"


class Listener(uvicorn.Server):
    """A uvicorn server that leaves signal handling to the group."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield

    def install_signal_handlers(self) -> None:  # uvicorn < 0.29
        return None


def port(name: str) -> int:
    return int(os.environ[f"VEXA_{name}_PORT"])


def listener(app, port_number: int) -> Listener:
    level = os.getenv("LOG_LEVEL", "info").lower()
    return Listener(uvicorn.Config(app, host=HOST, port=port_number, log_level=level))


# ─── edge ──────────────────────────────────────────────────────────────────


def edge_now() -> list[tuple[str, Listener]]:
    from admin_api.__main__ import build_production_app as admin_app
    from gateway.adapters import build_production_app as gateway_app
    from gateway.adapters import load_signing_key
    from gateway.service_door import build_door_app, door_port
    from meeting_api.__main__ import build_production_app as meeting_app

    door = build_door_app(identity_key=load_signing_key(os.getenv("VEXA_GATEWAY_IDENTITY_SIGNING_KEY_FILE", "")))
    return [
        ("admin-api", listener(admin_app(), port("ADMIN_API"))),
        ("meeting-api", listener(meeting_app(), port("MEETING_API"))),
        ("gateway", listener(gateway_app(), port("GATEWAY"))),
        ("gateway-door", listener(door, door_port())),
    ]


def _answers(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status == 200
    except Exception:  # noqa: BLE001 -- any failure means "not yet"
        return False


async def edge_later() -> list[tuple[str, Listener]]:
    urls = [u for u in os.getenv("VEXA_NATIVE_MCP_WAIT_URLS", "").split(",") if u]
    loop = asyncio.get_running_loop()
    while True:
        waiting = [u for u in urls if not await loop.run_in_executor(None, _answers, u)]
        if not waiting:
            break
        log.info("mcp waits for %s", ", ".join(waiting))
        await asyncio.sleep(2)
    from vexa_mcp.app import create_app

    for attempt in range(1, 21):
        try:
            app = await loop.run_in_executor(None, create_app)
            return [("mcp", listener(app, port("MCP")))]
        except Exception as error:  # noqa: BLE001 -- a domain may still be starting
            log.warning("mcp build attempt %d failed: %s", attempt, error)
            await asyncio.sleep(3)
    raise RuntimeError("mcp could not assemble its tools")


# ─── agent ─────────────────────────────────────────────────────────────────


def agent_now() -> list[tuple[str, Listener]]:
    import redis
    from control_plane import api as agent_api
    from control_plane import model_proxy as proxy
    from shared.config import load_settings

    settings = load_settings()
    client = redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=5)
    proxy_app = proxy.create_app(proxy.Grants(client, settings.model_proxy_secret.get_secret_value()))
    return [
        ("agent-api", listener(agent_api.app, port("AGENT_API"))),
        ("model-proxy", listener(proxy_app, port("MODEL_PROXY"))),
    ]


async def nothing_later() -> list[tuple[str, Listener]]:
    return []


GROUPS: dict[str, tuple[Callable[[], list], Callable[[], Coroutine[Any, Any, list]]]] = {
    "edge": (edge_now, edge_later),
    "agent": (agent_now, nothing_later),
}


async def run(group: str) -> int:
    build_now, build_later = GROUPS[group]
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    servers: list[tuple[str, Listener]] = []
    tasks: dict[asyncio.Task, str] = {}

    def start(named: list[tuple[str, Listener]]) -> None:
        for name, server in named:
            servers.append((name, server))
            tasks[asyncio.create_task(server.serve(), name=name)] = name
            log.info("%s listens on %s:%s", name, HOST, server.config.port)

    start(build_now())
    later = asyncio.create_task(build_later(), name="later")
    stopper = asyncio.create_task(stop.wait(), name="stop")
    code = 0
    while True:
        done, _ = await asyncio.wait([*tasks, later, stopper], return_when=asyncio.FIRST_COMPLETED)
        if stopper in done:
            break
        if later in done:
            if later.exception() is not None:
                log.error("%s group: %s", group, later.exception())
                code = 1
                break
            start(later.result())
            later = asyncio.create_task(asyncio.Event().wait(), name="idle")
            continue
        ended = [tasks[t] for t in done if t in tasks]
        log.error("%s stopped by itself; stopping the %s group", ", ".join(ended), group)
        code = 1
        break
    for _, server in servers:
        server.should_exit = True
    later.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    return code


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in GROUPS:
        print(__doc__, file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return asyncio.run(run(argv[1]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
